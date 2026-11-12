//! Lightweight std-only HTTP/1.1 REST server for `sonaraim-node`.
//!
//! Exposes `/health`, `/metrics`, `/v1/identity`, `/v1/identity/{did}`, `/v1/relay/envelopes`,
//! `/v1/relay/mailboxes/{mailbox_id}`, `/v1/media/presign`, `/v1/contacts/psi`,
//! and `/v1/identity/anchors/latest`.

use crate::config::NodeConfig;
use crate::health::HealthStatus;
use crate::merkle::{IdentityLogEntry, KeyTransparencyLog};
use crate::psi_service::{build_l2_anchor_receipt, evaluate_psi_batch};
use crate::redis_store::RedisRespClient;
use crate::relay::{MailboxStore, SealedEnvelope};
use crate::storage::{
    append_wal_entry, extract_json_str, extract_json_str_array, extract_json_u64,
    generate_s3_presigned_url, load_wal_entries, wal_path_from_signing_key, WalEntry,
};
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
    /// Optional durable Write-Ahead Log file path.
    pub wal_path: Option<PathBuf>,
    /// Optional Redis RESP client for mailbox TTL persistence.
    pub redis: Option<RedisRespClient>,
}

impl NodeState {
    /// Creates a new [`NodeState`], recovering WAL entries if `NODE_SIGNING_KEY_PATH` is set
    /// and connecting to `REDIS_URL` if configured.
    #[must_use]
    pub fn new(config: NodeConfig, relay: MailboxStore, kt_log: KeyTransparencyLog) -> Self {
        let wal_path = std::env::var("NODE_SIGNING_KEY_PATH")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .map(|p| wal_path_from_signing_key(&p));
        let redis = std::env::var("REDIS_URL")
            .ok()
            .and_then(|u| RedisRespClient::from_url(&u).ok());
        Self::with_wal_and_redis(config, relay, kt_log, wal_path, redis)
    }

    /// Creates a [`NodeState`] with explicit WAL path and optional [`RedisRespClient`],
    /// replaying any existing WAL entries into `kt_log` and `did_index`.
    #[must_use]
    pub fn with_wal_and_redis(
        config: NodeConfig,
        relay: MailboxStore,
        mut kt_log: KeyTransparencyLog,
        wal_path: Option<PathBuf>,
        redis: Option<RedisRespClient>,
    ) -> Self {
        let mut did_index = HashMap::new();
        if let Some(ref path) = wal_path {
            for item in load_wal_entries(path).unwrap_or_default() {
                if let Ok((index, _)) =
                    kt_log.append(&item.did, &item.key_commitment, item.epoch_secs)
                {
                    let leaf_hash = KeyTransparencyLog::hash_leaf(
                        index,
                        &item.did,
                        &item.key_commitment,
                        item.epoch_secs,
                    );
                    did_index.insert(
                        item.did.clone(),
                        IdentityLogEntry {
                            index,
                            did: item.did,
                            key_commitment: item.key_commitment,
                            epoch_secs: item.epoch_secs,
                            leaf_hash,
                        },
                    );
                }
            }
        }
        Self {
            config,
            relay,
            kt_log,
            did_index,
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
            let st = Arc::clone(&shared);
            let _ = handle_connection(stream, &st);
        }
    });
    Ok((addr, handle))
}

/// Runs the blocking HTTP server on `config.http_bind_address()`.
pub fn run_server(state: NodeState) -> Result<(), std::io::Error> {
    let bind_addr = state.config.http_bind_address();
    let listener = TcpListener::bind(bind_addr)?;
    let shared = Arc::new(Mutex::new(state));
    for stream in listener.incoming().flatten() {
        let st = Arc::clone(&shared);
        let _ = handle_connection(stream, &st);
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
    let mut first_line = head.lines().next().unwrap_or("").split_whitespace();
    let method = first_line.next().unwrap_or("");
    let path = first_line.next().unwrap_or("");

    let content_type = if path == "/metrics" {
        "text/plain; version=0.0.4"
    } else {
        "application/json"
    };
    let (status, reason, resp_body) = dispatch(method, path, body, shared);
    let reply = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{resp_body}",
        resp_body.len()
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
            err_json("LOCK_ERROR", "state lock poisoned"),
        );
    };

    match (method, path) {
        ("GET", "/health") => {
            let health = HealthStatus::from_state(&st.config, &st.relay, &st.kt_log);
            (200, "OK", health.to_json())
        }
        ("GET", "/metrics") => {
            let text = format!(
                "# HELP sonaraim_node_kt_entries_total Total Key Transparency log entries\n\
                 # TYPE sonaraim_node_kt_entries_total counter\n\
                 sonaraim_node_kt_entries_total {}\n\
                 # HELP sonaraim_node_queued_envelopes Currently queued relay envelopes\n\
                 # TYPE sonaraim_node_queued_envelopes gauge\n\
                 sonaraim_node_queued_envelopes {}\n",
                st.kt_log.len(),
                st.relay.total_queued()
            );
            (200, "OK", text)
        }
        ("POST", "/v1/identity") => handle_post_identity(&mut st, body),
        ("GET", "/v1/identity/anchors/latest") => {
            let receipt =
                build_l2_anchor_receipt(st.kt_log.len(), &st.kt_log.tree_head(), now_secs());
            (200, "OK", receipt.to_json())
        }
        ("GET", p) if p.starts_with("/v1/identity/") => {
            let did = &p["/v1/identity/".len()..];
            match st.did_index.get(did) {
                Some(entry) => {
                    let verified_b2b = entry.did.starts_with("did:web:");
                    let json = format!(
                        "{{\"did\":\"{}\",\"verified_b2b\":{},\"leaf_hash\":\"{}\",\"tree_head\":\"{}\"}}",
                        entry.did, verified_b2b, entry.leaf_hash, st.kt_log.tree_head()
                    );
                    (200, "OK", json)
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
            let items = st.relay.drain_active(mbx, now_secs());
            let ids: Vec<String> = items
                .into_iter()
                .map(|e| format!("\"{}\"", e.envelope_id))
                .collect();
            (200, "OK", format!("{{\"envelopes\":[{}]}}", ids.join(",")))
        }
        ("POST", "/v1/media/presign") => {
            let Some(hash) = extract_json_str(body, "sha256_ciphertext") else {
                return (
                    400,
                    "Bad Request",
                    err_json("INVALID_BODY", "missing sha256_ciphertext"),
                );
            };
            let len = extract_json_u64(body, "content_length").unwrap_or(0);
            let endpoint = std::env::var("S3_ENDPOINT_URL").unwrap_or_default();
            let bucket = std::env::var("S3_BUCKET_MEDIA").unwrap_or_default();
            let url = generate_s3_presigned_url(&endpoint, &bucket, &hash, len);
            (200, "OK", format!("{{\"presigned_url\":\"{url}\"}}"))
        }
        ("POST", "/v1/contacts/psi") => {
            let tokens = extract_json_str_array(body, "blinded_tokens");
            let eval = evaluate_psi_batch(&tokens, st.config.node_id.as_bytes());
            let quoted: Vec<String> = eval.into_iter().map(|t| format!("\"{t}\"")).collect();
            (
                200,
                "OK",
                format!("{{\"evaluated_tokens\":[{}]}}", quoted.join(",")),
            )
        }
        _ => (
            404,
            "Not Found",
            err_json("ROUTE_NOT_FOUND", "unknown route or method"),
        ),
    }
}

fn handle_post_identity(st: &mut NodeState, body: &str) -> (u16, &'static str, String) {
    let Some(did) = extract_json_str(body, "did") else {
        return (400, "Bad Request", err_json("INVALID_BODY", "missing did"));
    };
    let Some(commit) = extract_json_str(body, "key_commitment") else {
        return (
            400,
            "Bad Request",
            err_json("INVALID_BODY", "missing key_commitment"),
        );
    };
    let epoch = now_secs();
    match st.kt_log.append(&did, &commit, epoch) {
        Ok((index, _)) => {
            if let Some(ref wal_path) = st.wal_path {
                let _ = append_wal_entry(
                    wal_path,
                    &WalEntry {
                        did: did.clone(),
                        key_commitment: commit.clone(),
                        epoch_secs: epoch,
                    },
                );
            }
            let leaf_hash = KeyTransparencyLog::hash_leaf(index, &did, &commit, epoch);
            let entry = IdentityLogEntry {
                index,
                did: did.clone(),
                key_commitment: commit,
                epoch_secs: epoch,
                leaf_hash,
            };
            let json = format!(
                "{{\"did\":\"{}\",\"index\":{},\"tree_head\":\"{}\"}}",
                entry.did,
                entry.index,
                st.kt_log.tree_head()
            );
            st.did_index.insert(did, entry);
            (201, "Created", json)
        }
        Err(e) => (400, "Bad Request", err_json("INVALID_DID", &e.to_string())),
    }
}

fn handle_post_envelope(st: &mut NodeState, body: &str) -> (u16, &'static str, String) {
    let Some(env_id) = extract_json_str(body, "envelope_id") else {
        return (
            400,
            "Bad Request",
            err_json("INVALID_BODY", "missing envelope_id"),
        );
    };
    let Some(mbx) = extract_json_str(body, "recipient_mailbox_id") else {
        return (
            400,
            "Bad Request",
            err_json("INVALID_BODY", "missing recipient_mailbox_id"),
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
