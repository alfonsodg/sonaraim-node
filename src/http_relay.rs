//! HTTP handlers for relay envelopes and mailbox queues.

use crate::http_auth::err_json;
use crate::http_server::{now_secs, NodeState};
use crate::relay::SealedEnvelope;
use crate::s3_wal_maintenance::compact_wal_file;
use crate::storage::{extract_json_str, extract_json_str_array};

/// Handles `POST /v1/relay/envelopes`.
pub fn handle_post_envelope(st: &mut NodeState, body: &str) -> (u16, &'static str, String) {
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
    let replicated = body.contains("\"replicated\":true") || body.contains("\"replicated\": true");
    if let Some(ref redis) = st.redis {
        let _ = redis.set_ex(
            &format!("sonaraim:mbx:{mbx}"),
            &env_id,
            st.config.envelope_ttl_seconds,
        );
    }
    let token = st.relay.enqueue(SealedEnvelope {
        envelope_id: env_id.clone(),
        recipient_mailbox_id: mbx.clone(),
        ciphertext: payload_hex.as_bytes().to_vec(),
        created_at_epoch_secs: now_secs(),
    });
    if !replicated {
        let peers = st.p2p_mesh.peers();
        crate::http_federation::replicate_envelope_to_peers(&peers, &env_id, &mbx, &payload_hex);
    }
    (
        202,
        "Accepted",
        format!("{{\"wake_up_token\":\"{token}\"}}"),
    )
}

/// Handles `GET /v1/relay/mailboxes/:id`.
pub fn handle_get_mailbox(st: &NodeState, mailbox_id: &str) -> (u16, &'static str, String) {
    let entries = st.relay.get_active(mailbox_id, now_secs());
    let ids: Vec<String> = entries
        .iter()
        .map(|e| format!("\"{}\"", e.envelope_id))
        .collect();
    let items: Vec<String> = entries
        .into_iter()
        .map(|e| {
            let payload = String::from_utf8_lossy(&e.ciphertext);
            format!(
                "{{\"envelope_id\":\"{}\",\"recipient_mailbox_id\":\"{}\",\"payload_hex\":\"{payload}\"}}",
                e.envelope_id, e.recipient_mailbox_id
            )
        })
        .collect();
    (
        200,
        "OK",
        format!(
            "{{\"envelopes\":[{}],\"items\":[{}]}}",
            ids.join(","),
            items.join(",")
        ),
    )
}

/// Handles `POST /v1/relay/mailboxes/:id/ack`.
pub fn handle_ack_mailbox(
    st: &mut NodeState,
    mailbox_id: &str,
    body: &str,
) -> (u16, &'static str, String) {
    let ids = extract_json_str_array(body, "envelope_ids");
    let acked = st.relay.ack(mailbox_id, &ids);
    if let Some(ref redis) = st.redis {
        let _ = redis.del(&format!("sonaraim:mbx:{mailbox_id}"));
    }
    if let Some(ref wal) = st.wal_path {
        let active = st.relay.all_active_tuples(now_secs());
        let _ = compact_wal_file(wal, &active);
    }
    (
        200,
        "OK",
        format!("{{\"status\":\"ok\",\"acknowledged\":{acked}}}"),
    )
}
