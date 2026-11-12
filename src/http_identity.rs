//! HTTP handlers for Key Transparency identity registrations and queries.

use crate::http_auth::err_json;
use crate::http_federation::replicate_identity_to_peers;
use crate::http_server::{now_secs, NodeState};
use crate::merkle::{IdentityLogEntry, KeyTransparencyLog};
use crate::p2p::SignedTreeHead;
use crate::storage::{append_wal_entry, extract_json_str, WalEntry};
use crate::udp_gossip::verify_did_web_document;

/// Handles `GET /v1/identity/:did`.
pub fn handle_get_identity(st: &NodeState, did: &str) -> (u16, &'static str, String) {
    if let Some(e) = st.did_index.get(did) {
        let b2b = e.did.starts_with("did:web:");
        let th = st.kt_log.tree_head();
        let j = format!(
            "{{\"did\":\"{}\",\"verified_b2b\":{b2b},\"leaf_hash\":\"{}\",\"tree_head\":\"{th}\"}}",
            e.did, e.leaf_hash
        );
        (200, "OK", j)
    } else {
        (
            404,
            "Not Found",
            err_json("NOT_FOUND", "DID not registered"),
        )
    }
}

/// Handles `GET /v1/identity/by-phone/:token`.
pub fn handle_get_identity_by_phone(st: &NodeState, token: &str) -> (u16, &'static str, String) {
    let eval = crate::psi_service::evaluate_psi_single(token, st.config.node_id.as_bytes());
    if let Some(did) = st
        .phone_index
        .get(token)
        .or_else(|| st.phone_index.get(&eval))
    {
        (
            200,
            "OK",
            format!("{{\"phone_token\":\"{token}\",\"did\":\"{did}\"}}"),
        )
    } else {
        (
            404,
            "Not Found",
            err_json("NOT_FOUND", "phone token not registered"),
        )
    }
}

/// Handles `POST /v1/identity`.
pub fn handle_post_identity(st: &mut NodeState, body: &str) -> (u16, &'static str, String) {
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
    let replicated = body.contains("\"replicated\":true") || body.contains("\"replicated\": true");
    let phone_token =
        extract_json_str(body, "phone_token").or_else(|| extract_json_str(body, "phone_e164"));
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
            if !replicated {
                let sth = SignedTreeHead {
                    node_id: st.config.node_id.clone(),
                    tree_size: st.kt_log.len(),
                    root_hash: st.kt_log.tree_head(),
                };
                let peers = st.p2p_mesh.peers();
                if let Err(e) =
                    replicate_identity_to_peers(&peers, &did, &commit, phone_token.as_deref(), &sth)
                {
                    return (409, "Conflict", err_json("EQUIVOCATION_DETECTED", &e));
                }
            }
            let json = format!(
                "{{\"did\":\"{did}\",\"index\":{index},\"tree_head\":\"{}\"}}",
                st.kt_log.tree_head()
            );
            st.did_index.insert(
                did.clone(),
                IdentityLogEntry {
                    index,
                    did: did.clone(),
                    key_commitment: commit,
                    epoch_secs: epoch,
                    leaf_hash,
                },
            );
            if let Some(ref pt) = phone_token {
                let eval =
                    crate::psi_service::evaluate_psi_single(pt, st.config.node_id.as_bytes());
                st.phone_index.insert(pt.clone(), did.clone());
                st.phone_index.insert(eval, did);
            }
            (201, "Created", json)
        }
        Err(e) => (400, "Bad Request", err_json("INVALID_DID", &e.to_string())),
    }
}
