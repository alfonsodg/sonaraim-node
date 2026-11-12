//! Multi-node P2P peer registration, catch-up sync, and loop-free replication.

use crate::http_auth::err_json;
use crate::http_server::{now_secs, NodeState};
use crate::merkle::{IdentityLogEntry, KeyTransparencyLog};
use crate::p2p::{PeerRecord, SignedTreeHead};
use crate::relay::SealedEnvelope;
use crate::storage::extract_json_str;
use crate::udp_gossip::{decode_tree_head_json, encode_tree_head_json};
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

/// Executes a synchronous HTTP request against `url` using std-only [`TcpStream`].
pub fn execute_http_request(
    method: &str,
    url: &str,
    body: &str,
    timeout_ms: u64,
) -> Result<(u16, String), String> {
    let raw = url
        .trim_start_matches("http://")
        .trim_start_matches("https://");
    let (hp, path) = raw
        .split_once('/')
        .map_or((raw, "/".to_string()), |(h, p)| (h, format!("/{p}")));
    let addr_str = if hp.contains(':') {
        hp.to_string()
    } else {
        format!("{hp}:80")
    };
    let dur = Duration::from_millis(timeout_ms.max(50));
    let mut addrs = addr_str.to_socket_addrs().map_err(|e| e.to_string())?;
    let addr = addrs
        .next()
        .ok_or_else(|| "no address resolved".to_string())?;
    let mut stream = TcpStream::connect_timeout(&addr, dur).map_err(|e| e.to_string())?;
    let _ = stream.set_read_timeout(Some(dur));
    let _ = stream.set_write_timeout(Some(dur));

    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: {hp}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream
        .write_all(req.as_bytes())
        .map_err(|e| e.to_string())?;
    stream.flush().map_err(|e| e.to_string())?;

    let mut resp = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => resp.extend_from_slice(&buf[..n]),
            Err(_) => break,
        }
    }
    let text = String::from_utf8_lossy(&resp);
    let (head, resp_body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    let status = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);
    Ok((status, resp_body.to_string()))
}

/// Parses top-level JSON objects from an array named `key` in `raw`.
#[must_use]
pub fn parse_json_objects(raw: &str, key: &str) -> Vec<String> {
    let pat = format!("\"{key}\":[");
    let Some(start) = raw.find(&pat) else {
        return Vec::new();
    };
    let rest = &raw[start + pat.len()..];
    let Some(end) = rest.find(']') else {
        return Vec::new();
    };
    let slice = &rest[..end];
    let mut out = Vec::new();
    let (mut depth, mut obj_start) = (0, None);
    for (i, b) in slice.bytes().enumerate() {
        if b == b'{' {
            if depth == 0 {
                obj_start = Some(i);
            }
            depth += 1;
        } else if b == b'}' {
            depth -= 1;
            if depth == 0 {
                if let Some(s) = obj_start {
                    out.push(slice[s..=i].to_string());
                }
                obj_start = None;
            }
        }
    }
    out
}

/// Handles `POST /v1/p2p/peers`.
pub fn handle_post_peers(st: &mut NodeState, body: &str) -> (u16, &'static str, String) {
    let Some(peer_id) = extract_json_str(body, "peer_id") else {
        return (
            400,
            "Bad Request",
            err_json("INVALID_BODY", "missing peer_id"),
        );
    };
    let rpc_url = extract_json_str(body, "rpc_url").unwrap_or_default();
    let multiaddr = extract_json_str(body, "multiaddr").unwrap_or_default();
    st.p2p_mesh.add_peer_record(PeerRecord {
        peer_id: peer_id.clone(),
        rpc_url: rpc_url.clone(),
        multiaddr,
    });
    if !rpc_url.is_empty() {
        let sync_url = format!("{}/v1/p2p/sync", rpc_url.trim_end_matches('/'));
        if let Ok((200, sync_body)) = execute_http_request("GET", &sync_url, "", 2000) {
            if let Err(err_resp) = ingest_sync_payload(st, &sync_body) {
                return err_resp;
            }
        }
    }
    (
        201,
        "Created",
        "{\"status\":\"ok\",\"peered\":true}".to_string(),
    )
}

fn ingest_sync_payload(
    st: &mut NodeState,
    sync_body: &str,
) -> Result<(), (u16, &'static str, String)> {
    if let Some(th_start) = sync_body.find("\"tree_head\":") {
        let th_chunk = &sync_body[th_start..];
        if let Some(sth) = decode_tree_head_json(th_chunk) {
            if let Err(e) = st.p2p_mesh.accept_tree_head(sth) {
                return Err((
                    409,
                    "Conflict",
                    err_json("EQUIVOCATION_DETECTED", &e.to_string()),
                ));
            }
        }
    }
    for obj in parse_json_objects(sync_body, "identities") {
        if let (Some(did), Some(commit)) = (
            extract_json_str(&obj, "did"),
            extract_json_str(&obj, "key_commitment"),
        ) {
            if !st.did_index.contains_key(&did) {
                let epoch = now_secs();
                if let Ok((index, _)) = st.kt_log.append(&did, &commit, epoch) {
                    let leaf_hash = KeyTransparencyLog::hash_leaf(index, &did, &commit, epoch);
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
                }
            }
        }
    }
    for obj in parse_json_objects(sync_body, "envelopes") {
        if let (Some(env_id), Some(mbx)) = (
            extract_json_str(&obj, "envelope_id"),
            extract_json_str(&obj, "recipient_mailbox_id"),
        ) {
            let payload_hex = extract_json_str(&obj, "payload_hex").unwrap_or_default();
            st.relay.enqueue(SealedEnvelope {
                envelope_id: env_id,
                recipient_mailbox_id: mbx,
                ciphertext: payload_hex.into_bytes(),
                created_at_epoch_secs: now_secs(),
            });
        }
    }
    Ok(())
}

/// Handles `GET /v1/p2p/peers`.
pub fn handle_get_peers(st: &NodeState) -> (u16, &'static str, String) {
    let list: Vec<String> = st
        .p2p_mesh
        .peers()
        .into_iter()
        .map(|p| {
            format!(
                "{{\"peer_id\":\"{}\",\"rpc_url\":\"{}\",\"multiaddr\":\"{}\"}}",
                p.peer_id, p.rpc_url, p.multiaddr
            )
        })
        .collect();
    (200, "OK", format!("{{\"peers\":[{}]}}", list.join(",")))
}

/// Handles `GET /v1/p2p/sync`.
pub fn handle_get_sync(st: &NodeState) -> (u16, &'static str, String) {
    let sth = SignedTreeHead {
        node_id: st.config.node_id.clone(),
        tree_size: st.kt_log.len(),
        root_hash: st.kt_log.tree_head(),
    };
    let th_json = encode_tree_head_json(&sth);
    let ids: Vec<String> = st
        .did_index
        .values()
        .map(|e| {
            format!(
                "{{\"did\":\"{}\",\"key_commitment\":\"{}\"}}",
                e.did, e.key_commitment
            )
        })
        .collect();
    let envs: Vec<String> = st
        .relay
        .all_active_tuples(now_secs())
        .into_iter()
        .map(|(i, m, p)| format!("{{\"envelope_id\":\"{i}\",\"recipient_mailbox_id\":\"{m}\",\"payload_hex\":\"{p}\"}}"))
        .collect();
    (
        200,
        "OK",
        format!(
            "{{\"tree_head\":{th_json},\"identities\":[{}],\"envelopes\":[{}]}}",
            ids.join(","),
            envs.join(",")
        ),
    )
}

/// Replicates an envelope across all registered peer nodes without looping.
pub fn replicate_envelope_to_peers(
    peers: &[PeerRecord],
    env_id: &str,
    mbx: &str,
    payload_hex: &str,
) {
    let body = format!(
        "{{\"envelope_id\":\"{env_id}\",\"recipient_mailbox_id\":\"{mbx}\",\"payload_hex\":\"{payload_hex}\",\"replicated\":true}}"
    );
    for peer in peers {
        if !peer.rpc_url.is_empty() {
            let url = format!("{}/v1/relay/envelopes", peer.rpc_url.trim_end_matches('/'));
            let _ = execute_http_request("POST", &url, &body, 1000);
        }
    }
}

/// Replicates an identity binding and new `SignedTreeHead` to registered peers.
pub fn replicate_identity_to_peers(
    peers: &[PeerRecord],
    did: &str,
    commit: &str,
    phone_token: Option<&str>,
    sth: &SignedTreeHead,
) -> Result<(), String> {
    let gossip_body = encode_tree_head_json(sth);
    let p_field = phone_token.map_or_else(String::new, |t| format!(",\"phone_token\":\"{t}\""));
    let id_body = format!(
        "{{\"did\":\"{did}\",\"key_commitment\":\"{commit}\"{p_field},\"replicated\":true}}"
    );
    for peer in peers {
        if !peer.rpc_url.is_empty() {
            let base = peer.rpc_url.trim_end_matches('/');
            let g_url = format!("{base}/v1/p2p/gossip");
            if let Ok((409, resp)) = execute_http_request("POST", &g_url, &gossip_body, 1000) {
                return Err(format!("equivocation on peer {}: {resp}", peer.peer_id));
            }
            let id_url = format!("{base}/v1/identity");
            let _ = execute_http_request("POST", &id_url, &id_body, 1000);
        }
    }
    Ok(())
}
