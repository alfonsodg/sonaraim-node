//! Multi-node P2P peer registration, catch-up sync, and loop-free replication.

use crate::federation_client::{execute_http_request, extract_peer_auth_token};
use crate::http_auth::err_json;
use crate::http_server::{now_secs, NodeState};
use crate::merkle::{IdentityLogEntry, KeyTransparencyLog};
use crate::p2p::{sign_tree_head, PeerRecord, SignedTreeHead};
use crate::relay::SealedEnvelope;
use crate::storage::extract_json_str;
use crate::udp_gossip::{decode_tree_head_json, encode_tree_head_json};

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
    let auth_token = extract_peer_auth_token(body);
    st.p2p_mesh.add_peer_record(PeerRecord {
        peer_id: peer_id.clone(),
        rpc_url: rpc_url.clone(),
        multiaddr,
        auth_token: auth_token.clone(),
    });
    if !rpc_url.is_empty() {
        let sync_url = format!("{}/v1/p2p/sync", rpc_url.trim_end_matches('/'));
        if let Ok((200, sync_body)) =
            execute_http_request("GET", &sync_url, "", auth_token.as_deref(), 2000)
        {
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
                // Federated sync carries the origin's digest in `GET /v1/p2p/sync`
                // `identities[].phone_digest` (digest-only, raw tokens never cross the
                // wire). Local registrations re-derive the digest from the submitted
                // raw token because clients never send digests.
                let phone_digest = extract_json_str(&obj, "phone_digest")
                    .filter(|s| !s.is_empty())
                    .or_else(|| {
                        extract_json_str(&obj, "phone_token").map(|pt| {
                            crate::psi_service::evaluate_psi_single(
                                &pt,
                                &st.config.psi_secret_bytes(),
                            )
                        })
                    });
                if let Ok((index, _)) = st.kt_log.append(&did, &commit, epoch) {
                    let leaf_hash = KeyTransparencyLog::hash_leaf(index, &did, &commit, epoch);
                    st.did_index.insert(
                        did.clone(),
                        IdentityLogEntry {
                            index,
                            did: did.clone(),
                            key_commitment: commit.clone(),
                            epoch_secs: epoch,
                            leaf_hash,
                            phone_digest: phone_digest.clone(),
                        },
                    );
                    // Persist federated inserts to the identity WAL (same
                    // schema as local registrations, #16 one-file-one-schema);
                    // on restart the entry replays like any other line.
                    if let Some(ref wal) = st.wal_path {
                        let entry = crate::storage::WalEntry {
                            did: did.clone(),
                            key_commitment: commit,
                            epoch_secs: epoch,
                            phone_digest: phone_digest.clone(),
                        };
                        if let Err(e) = crate::storage::append_wal_entry(wal, &entry) {
                            eprintln!("{{\"level\":\"ERROR\",\"msg\":\"federated identity wal append failed\",\"error\":\"{e}\"}}");
                        }
                    }
                    if let Some(digest) = phone_digest {
                        st.phone_index.insert(digest, did);
                    }
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
    let seed = st.config.sth_signing_seed();
    let (signer_pubkey_hex, signature_hex) = sign_tree_head(
        &st.config.node_id,
        st.kt_log.len(),
        &st.kt_log.tree_head(),
        &seed,
    );
    let sth = SignedTreeHead {
        node_id: st.config.node_id.clone(),
        tree_size: st.kt_log.len(),
        root_hash: st.kt_log.tree_head(),
        signer_pubkey_hex,
        signature_hex,
    };
    let th_json = encode_tree_head_json(&sth);
    let ids: Vec<String> = st
        .did_index
        .values()
        .map(|e| {
            let digest_field = e
                .phone_digest
                .as_deref()
                .filter(|s| !s.is_empty())
                .map_or_else(String::new, |d| format!(",\"phone_digest\":\"{d}\""));
            format!(
                "{{\"did\":\"{}\",\"key_commitment\":\"{}\"{digest_field}}}",
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
