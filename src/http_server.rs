//! Lightweight std-only HTTP/1.1 REST server for `sonaraim-node`.
//! Exposes `/health`, `/metrics`, `/v1/identity`, `/v1/identity/{did}`, `/v1/relay/envelopes`,
//! `/v1/relay/mailboxes/{mailbox_id}`, `/v1/media/presign`, `/v1/contacts/psi`,
//! `/v1/identity/anchors/latest`, and `/v1/p2p/gossip`.

use crate::config::NodeConfig;
use crate::health::HealthStatus;
use crate::merkle::{IdentityLogEntry, KeyTransparencyLog};
use crate::p2p::P2pMeshNode;
use crate::psi_service::{build_l2_anchor_receipt, handle_presign_json, handle_psi_json};
use crate::redis_store::RedisRespClient;
use crate::relay::{MailboxStore, SealedEnvelope};
use crate::storage::{
    append_wal_entry, extract_json_str, replay_wal_into_log, wal_path_from_signing_key, WalEntry,
};
use crate::udp_gossip::{ingest_gossip_json, verify_did_web_document};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{SystemTime, UNIX_EPOCH};

/// Shared mutable state for a running `sonaraim-node` HTTP server.
#[derive(Debug)]
pub struct NodeState {
    /// Validated node configuration.
    pub config: NodeConfig,
    /// Ephemeral store-and-forward mailbox queues.
    pub relay: MailboxStore,
    /// Append-only Key Transparency Merkle log.
    pub kt_log: KeyTransparencyLog,
    /// Lookup index from DID string to latest [`IdentityLogEntry`].
    pub did_index: HashMap<String, IdentityLogEntry>,
    /// P2P mesh gossip state tracking peer `SignedTreeHead` epochs.
    pub p2p_mesh: P2pMeshNode,
    /// Optional durable Write-Ahead Log file path.
    pub wal_path: Option<PathBuf>,
    /// Optional Redis RESP client for mailbox TTL persistence.
    pub redis: Option<RedisRespClient>,
}

impl NodeState {
    /// Creates a new [`NodeState`], recovering WAL entries if `NODE_SIGNING_KEY_PATH` is set.
    #[must_use]
    pub fn new(config: NodeConfig, relay: MailboxStore, kt_log: KeyTransparencyLog) -> Self {
        let wal = std::env::var("NODE_SIGNING_KEY_PATH")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .map(|p| wal_path_from_signing_key(&p));
        let redis = std::env::var("REDIS_URL")
            .ok()
            .and_then(|u| RedisRespClient::from_url(&u).ok());
        Self::with_wal_and_redis(config, relay, kt_log, wal, redis)
    }

    /// Creates a [`NodeState`] with explicit WAL path and optional [`RedisRespClient`].
    #[must_use]
    pub fn with_wal_and_redis(
        config: NodeConfig,
        relay: MailboxStore,
        mut kt_log: KeyTransparencyLog,
        wal_path: Option<PathBuf>,
        redis: Option<RedisRespClient>,
    ) -> Self {
        let did_index = replay_wal_into_log(wal_path.as_deref(), &mut kt_log);
        let p2p_mesh = P2pMeshNode::new(&config.node_id);
        Self {
            config,
            relay,
            kt_log,
            did_index,
            p2p_mesh,
            wal_path,
            redis,
        }
    }
}

/// Starts a background HTTP test server bound to `127.0.0.1:0` and returns `(addr, handle)`.
pub fn start_test_server(state: NodeState) -> Result<(String, JoinHandle<()>), std::io::Error> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?.to_string();
    let shared = Arc::new(Mutex::new(state));
    let handle = thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let _ = handle_connection(stream, &shared);
        }
    });
    Ok((addr, handle))
}

/// Runs the blocking HTTP server on `config.http_bind_address()`.
pub fn run_server(state: NodeState) -> Result<(), std::io::Error> {
    let listener = TcpListener::bind(state.config.http_bind_address())?;
    let shared = Arc::new(Mutex::new(state));
    for stream in listener.incoming().flatten() {
        let _ = handle_connection(stream, &shared);
    }
    Ok(())
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(1_700_000_000, |d| d.as_secs())
}

fn handle_connection(
    mut stream: TcpStream,
    shared: &Arc<Mutex<NodeState>>,
) -> Result<(), std::io::Error> {
    let mut buf = [0u8; 16_384];
    let n = stream.read(&mut buf)?;
    if n == 0 {
        return Ok(());
    }
    let raw = String::from_utf8_lossy(&buf[..n]);
    let (head, body) = raw.split_once("\r\n\r\n").unwrap_or((&raw, ""));
    let mut first = head.lines().next().unwrap_or("").split_whitespace();
    let (method, path) = (first.next().unwrap_or(""), first.next().unwrap_or(""));
    let ctype = if path == "/metrics" {
        "text/plain; version=0.0.4"
    } else {
        "application/json"
    };
    let (status, reason, resp) = dispatch(method, path, body, shared);
    let reply = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{resp}",
        resp.len()
    );
    stream.write_all(reply.as_bytes())
}

fn dispatch(
    method: &str,
    path: &str,
    body: &str,
    shared: &Arc<Mutex<NodeState>>,
) -> (u16, &'static str, String) {
    let Ok(mut st) = shared.lock() else {
        return (
            500,
            "Internal Server Error",
            err_json("LOCK_ERROR", "lock poisoned"),
        );
    };
    match (method, path) {
        ("GET", "/health") => {
            let h = HealthStatus::from_state(&st.config, &st.relay, &st.kt_log).to_json();
            (200, "OK", h)
        }
        ("GET", "/metrics") => {
            let m =
                HealthStatus::format_prometheus_metrics(st.kt_log.len(), st.relay.total_queued());
            (200, "OK", m)
        }
        ("POST", "/v1/identity") => handle_post_identity(&mut st, body),
        ("POST", "/v1/p2p/gossip") => ingest_gossip_json(&mut st.p2p_mesh, body),
        ("GET", "/v1/identity/anchors/latest") => {
            let r = build_l2_anchor_receipt(st.kt_log.len(), &st.kt_log.tree_head(), now_secs());
            (200, "OK", r.to_json())
        }
        ("GET", p) if p.starts_with("/v1/identity/") => {
            let did = &p["/v1/identity/".len()..];
            match st.did_index.get(did) {
                Some(e) => {
                    let b2b = e.did.starts_with("did:web:");
                    let th = st.kt_log.tree_head();
                    let j = format!(
                        "{{\"did\":\"{}\",\"verified_b2b\":{b2b},\"leaf_hash\":\"{}\",\"tree_head\":\"{th}\"}}",
                        e.did, e.leaf_hash
                    );
                    (200, "OK", j)
                }
                None => (
                    404,
                    "Not Found",
                    err_json("NOT_FOUND", "DID not registered"),
                ),
            }
        }
        ("POST", "/v1/relay/envelopes") => handle_post_envelope(&mut st, body),
        ("GET", p) if p.starts_with("/v1/relay/mailboxes/") => {
            let mbx = &p["/v1/relay/mailboxes/".len()..];
            if let Some(ref redis) = st.redis {
                let _ = redis.del(&format!("sonaraim:mbx:{mbx}"));
            }
            let ids: Vec<String> = st
                .relay
                .drain_active(mbx, now_secs())
                .into_iter()
                .map(|e| format!("\"{}\"", e.envelope_id))
                .collect();
            (200, "OK", format!("{{\"envelopes\":[{}]}}", ids.join(",")))
        }
        ("POST", "/v1/media/presign") => handle_presign_json(body),
        ("POST", "/v1/contacts/psi") => handle_psi_json(body, st.config.node_id.as_bytes()),
        _ => (
            404,
            "Not Found",
            err_json("ROUTE_NOT_FOUND", "unknown route or method"),
        ),
    }
}

fn handle_post_identity(st: &mut NodeState, body: &str) -> (u16, &'static str, String) {
    let (Some(did), Some(commit)) = (
        extract_json_str(body, "did"),
        extract_json_str(body, "key_commitment"),
    ) else {
        return (
            400,
            "Bad Request",
            err_json("INVALID_BODY", "missing did or key_commitment"),
        );
    };
    if did.starts_with("did:web:")
        && body.contains("\"did_document_json\"")
        && !extract_json_str(body, "did_document_json")
            .is_some_and(|doc| verify_did_web_document(&did, &doc))
    {
        return (
            400,
            "Bad Request",
            err_json("INVALID_DID_WEB_DOC", "did:web invalid"),
        );
    }
    let epoch = now_secs();
    match st.kt_log.append(&did, &commit, epoch) {
        Ok((index, _)) => {
            if let Some(ref wal) = st.wal_path {
                let entry = WalEntry {
                    did: did.clone(),
                    key_commitment: commit.clone(),
                    epoch_secs: epoch,
                };
                let _ = append_wal_entry(wal, &entry);
            }
            let leaf_hash = KeyTransparencyLog::hash_leaf(index, &did, &commit, epoch);
            let json = format!(
                "{{\"did\":\"{did}\",\"index\":{index},\"tree_head\":\"{}\"}}",
                st.kt_log.tree_head()
            );
            st.did_index.insert(
                did.clone(),
                IdentityLogEntry {
                    index,
                    did,
                    key_commitment: commit,
                    epoch_secs: epoch,
                    leaf_hash,
                },
            );
            (201, "Created", json)
        }
        Err(e) => (400, "Bad Request", err_json("INVALID_DID", &e.to_string())),
    }
}

fn handle_post_envelope(st: &mut NodeState, body: &str) -> (u16, &'static str, String) {
    let (Some(env_id), Some(mbx)) = (
        extract_json_str(body, "envelope_id"),
        extract_json_str(body, "recipient_mailbox_id"),
    ) else {
        return (
            400,
            "Bad Request",
            err_json(
                "INVALID_BODY",
                "missing envelope_id or recipient_mailbox_id",
            ),
        );
    };
    let payload_hex = extract_json_str(body, "payload_hex").unwrap_or_default();
    if let Some(ref redis) = st.redis {
        let _ = redis.set_ex(
            &format!("sonaraim:mbx:{mbx}"),
            &env_id,
            st.config.envelope_ttl_seconds,
        );
    }
    let token = st.relay.enqueue(SealedEnvelope {
        envelope_id: env_id,
        recipient_mailbox_id: mbx,
        ciphertext: payload_hex.into_bytes(),
        created_at_epoch_secs: now_secs(),
    });
    (
        202,
        "Accepted",
        format!("{{\"wake_up_token\":\"{token}\"}}"),
    )
}

fn err_json(code: &str, message: &str) -> String {
    format!("{{\"error\":{{\"code\":\"{code}\",\"message\":\"{message}\"}}}}")
}
