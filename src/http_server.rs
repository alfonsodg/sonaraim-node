//! Lightweight std-only HTTP/1.1 REST server for `sonaraim-node`.
//!
//! Exposes `/health`, `/v1/identity`, `/v1/identity/{did}`, `/v1/relay/envelopes`,
//! `/v1/relay/mailboxes/{mailbox_id}`, `/v1/media/presign`, `/v1/contacts/psi`,
//! and `/v1/identity/anchors/latest`.

use crate::config::NodeConfig;
use crate::health::HealthStatus;
use crate::merkle::{IdentityLogEntry, KeyTransparencyLog};
use crate::psi_service::{build_l2_anchor_receipt, evaluate_psi_batch};
use crate::relay::{MailboxStore, SealedEnvelope};
use crate::storage::generate_s3_presigned_url;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
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
}

impl NodeState {
    /// Creates a new [`NodeState`].
    #[must_use]
    pub fn new(config: NodeConfig, relay: MailboxStore, kt_log: KeyTransparencyLog) -> Self {
        Self {
            config,
            relay,
            kt_log,
            did_index: HashMap::new(),
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

    let (status, reason, resp_body) = dispatch(method, path, body, shared);
    let reply = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{resp_body}",
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
        ("POST", "/v1/identity") => {
            let Some(did) = extract_str(body, "did") else {
                return (400, "Bad Request", err_json("INVALID_BODY", "missing did"));
            };
            let Some(commit) = extract_str(body, "key_commitment") else {
                return (
                    400,
                    "Bad Request",
                    err_json("INVALID_BODY", "missing key_commitment"),
                );
            };
            match st.kt_log.append(&did, &commit, now_secs()) {
                Ok((index, leaf_hash)) => {
                    let entry = IdentityLogEntry {
                        index,
                        did: did.clone(),
                        key_commitment: commit,
                        epoch_secs: now_secs(),
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
                        entry.did,
                        verified_b2b,
                        entry.leaf_hash,
                        st.kt_log.tree_head()
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
        ("POST", "/v1/relay/envelopes") => {
            let Some(env_id) = extract_str(body, "envelope_id") else {
                return (
                    400,
                    "Bad Request",
                    err_json("INVALID_BODY", "missing envelope_id"),
                );
            };
            let Some(mbx) = extract_str(body, "recipient_mailbox_id") else {
                return (
                    400,
                    "Bad Request",
                    err_json("INVALID_BODY", "missing recipient_mailbox_id"),
                );
            };
            let payload_hex = extract_str(body, "payload_hex").unwrap_or_default();
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
        ("GET", p) if p.starts_with("/v1/relay/mailboxes/") => {
            let mbx = &p["/v1/relay/mailboxes/".len()..];
            let items = st.relay.drain_active(mbx, now_secs());
            let ids: Vec<String> = items
                .into_iter()
                .map(|e| format!("\"{}\"", e.envelope_id))
                .collect();
            (200, "OK", format!("{{\"envelopes\":[{}]}}", ids.join(",")))
        }
        ("POST", "/v1/media/presign") => {
            let Some(hash) = extract_str(body, "sha256_ciphertext") else {
                return (
                    400,
                    "Bad Request",
                    err_json("INVALID_BODY", "missing sha256_ciphertext"),
                );
            };
            let len = extract_u64(body, "content_length").unwrap_or(0);
            let endpoint = std::env::var("S3_ENDPOINT_URL").unwrap_or_default();
            let bucket = std::env::var("S3_BUCKET_MEDIA").unwrap_or_default();
            let url = generate_s3_presigned_url(&endpoint, &bucket, &hash, len);
            (200, "OK", format!("{{\"presigned_url\":\"{url}\"}}"))
        }
        ("POST", "/v1/contacts/psi") => {
            let tokens = extract_str_array(body, "blinded_tokens");
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

fn err_json(code: &str, message: &str) -> String {
    format!("{{\"error\":{{\"code\":\"{code}\",\"message\":\"{message}\"}}}}")
}

fn extract_str(raw: &str, key: &str) -> Option<String> {
    let pat = format!("\"{key}\":\"");
    let start = raw.find(&pat)? + pat.len();
    let rest = &raw[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

fn extract_u64(raw: &str, key: &str) -> Option<u64> {
    let pat = format!("\"{key}\":");
    let start = raw.find(&pat)? + pat.len();
    let digits: String = raw[start..]
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    digits.parse::<u64>().ok()
}

fn extract_str_array(raw: &str, key: &str) -> Vec<String> {
    let pat = format!("\"{key}\":[");
    let Some(start) = raw.find(&pat) else {
        return Vec::new();
    };
    let rest = &raw[start + pat.len()..];
    let Some(end) = rest.find(']') else {
        return Vec::new();
    };
    rest[..end]
        .split(',')
        .map(|s| s.trim().trim_matches('"').to_string())
        .filter(|s| !s.is_empty())
        .collect()
}
