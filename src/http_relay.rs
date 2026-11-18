//! HTTP handlers for relay envelopes and mailbox queues.

use crate::envelope_wal::{append_envelope_wal_entry, EnvelopeWalEntry};
use crate::http_auth::err_json;
use crate::http_server::{now_secs, NodeState};
use crate::push_signals::{EphemeralSignal, PushPlatform, SignalType};
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
    let created_at = now_secs();
    if let Some(ref redis) = st.redis {
        let record = format!(
            "{{\"envelope_id\":\"{env_id}\",\"recipient_mailbox_id\":\"{mbx}\",\"payload_hex\":\"{payload_hex}\",\"created_at_epoch_secs\":{created_at}}}"
        );
        if let Err(e) = redis.rpush(&format!("sonaraim:queue:{mbx}"), &record) {
            st.redis_last_error = Some(e.to_string());
            eprintln!("{{\"level\":\"ERROR\",\"msg\":\"redis RPUSH failed\",\"error\":\"{e}\"}}");
        }
    }
    let token = st.relay.enqueue(SealedEnvelope {
        envelope_id: env_id.clone(),
        recipient_mailbox_id: mbx.clone(),
        ciphertext: payload_hex.as_bytes().to_vec(),
        created_at_epoch_secs: created_at,
    });
    if let Some(ref envelope_wal) = st.envelope_wal_path {
        let entry = EnvelopeWalEntry {
            envelope_id: env_id.clone(),
            recipient_mailbox_id: mbx.clone(),
            payload_hex: payload_hex.clone(),
            created_at_epoch_secs: created_at,
        };
        if let Err(e) = append_envelope_wal_entry(envelope_wal, &entry) {
            eprintln!(
                "{{\"level\":\"ERROR\",\"msg\":\"envelope wal append failed\",\"error\":\"{e}\"}}"
            );
        }
    }
    let wake_up_queued = st.push_signals.record_wake_up(&mbx);
    if !replicated {
        let peers = st.p2p_mesh.peers();
        crate::federation_client::replicate_envelope_to_peers(&peers, &env_id, &mbx, &payload_hex);
    }
    (
        202,
        "Accepted",
        format!("{{\"wake_up_token\":\"{token}\",\"wake_up_queued\":{wake_up_queued}}}"),
    )
}

/// Handles `POST /v1/push/register`.
pub fn handle_post_push_register(st: &mut NodeState, body: &str) -> (u16, &'static str, String) {
    let (Some(mbx), Some(plat_str), Some(tok)) = (
        extract_json_str(body, "mailbox_id"),
        extract_json_str(body, "platform"),
        extract_json_str(body, "device_token"),
    ) else {
        return (
            400,
            "Bad Request",
            err_json(
                "INVALID_BODY",
                "missing mailbox_id, platform, or device_token",
            ),
        );
    };
    let Some(platform) = PushPlatform::parse(&plat_str) else {
        return (
            400,
            "Bad Request",
            err_json(
                "INVALID_PLATFORM",
                "supported platforms: apns, fcm, webpush",
            ),
        );
    };
    let hint = extract_json_str(body, "endpoint_hint");
    let reg =
        st.push_signals
            .register_push_token(&mbx, platform, &tok, hint.as_deref(), now_secs());
    (
        200,
        "OK",
        format!(
            "{{\"status\":\"ok\",\"registered\":true,\"mailbox_id\":\"{}\",\"platform\":\"{}\",\"token_hash\":\"{}\"}}",
            reg.mailbox_id,
            reg.platform.as_str(),
            reg.token_hash
        ),
    )
}

/// Handles `POST /v1/relay/signals`.
pub fn handle_post_signal(st: &mut NodeState, body: &str) -> (u16, &'static str, String) {
    let (Some(mbx), Some(sender), Some(sig_str)) = (
        extract_json_str(body, "mailbox_id"),
        extract_json_str(body, "sender_did"),
        extract_json_str(body, "signal_type"),
    ) else {
        return (
            400,
            "Bad Request",
            err_json(
                "INVALID_BODY",
                "missing mailbox_id, sender_did, or signal_type",
            ),
        );
    };
    let Some(sig_type) = SignalType::parse(&sig_str) else {
        return (
            400,
            "Bad Request",
            err_json(
                "INVALID_SIGNAL_TYPE",
                "supported signals: typing, delivered, read",
            ),
        );
    };
    let env_id = extract_json_str(body, "envelope_id");
    let sig = st
        .push_signals
        .record_signal(&mbx, &sender, sig_type, env_id.as_deref(), now_secs());
    (
        200,
        "OK",
        format!(
            "{{\"status\":\"ok\",\"recorded\":true,\"mailbox_id\":\"{}\",\"signal_type\":\"{}\",\"expires_at_epoch\":{}}}",
            sig.mailbox_id,
            sig.signal_type.as_str(),
            sig.expires_at_epoch
        ),
    )
}

/// Handles `GET /v1/relay/signals/:mailbox_id`.
pub fn handle_get_signals(st: &mut NodeState, mailbox_id: &str) -> (u16, &'static str, String) {
    let signals = st.push_signals.drain_signals(mailbox_id, now_secs());
    let items: Vec<String> = signals.iter().map(EphemeralSignal::to_json).collect();
    (
        200,
        "OK",
        format!(
            "{{\"mailbox_id\":\"{mailbox_id}\",\"signals\":[{}]}}",
            items.join(",")
        ),
    )
}

/// Handles `GET /v1/relay/mailboxes/:id`.
///
/// When Redis is configured, queued envelopes are additionally merged from the
/// Redis list (`LRANGE`) so a node that drained its in-memory queue (e.g. after
/// restart before WAL replay, or a peer-forwarded write) still serves them.
/// Redis failures are recorded in state and logged, never silently dropped.
pub fn handle_get_mailbox(st: &mut NodeState, mailbox_id: &str) -> (u16, &'static str, String) {
    let mut entries = st.relay.get_active(mailbox_id, now_secs());
    let redis_records: Vec<String> = if let Some(ref redis) = st.redis {
        match redis.lrange(&format!("sonaraim:queue:{mailbox_id}")) {
            Ok(records) => records,
            Err(e) => {
                st.redis_last_error = Some(e.to_string());
                eprintln!(
                    "{{\"level\":\"ERROR\",\"msg\":\"redis LRANGE failed\",\"error\":\"{e}\"}}"
                );
                Vec::new()
            }
        }
    } else {
        Vec::new()
    };
    {
        let known: std::collections::HashSet<String> =
            entries.iter().map(|e| e.envelope_id.clone()).collect();
        for record in &redis_records {
            let (Some(env_id), Some(mbx)) = (
                extract_json_str(record, "envelope_id"),
                extract_json_str(record, "recipient_mailbox_id"),
            ) else {
                continue;
            };
            if mbx != mailbox_id || known.contains(env_id.as_str()) {
                continue;
            }
            let payload_hex = extract_json_str(record, "payload_hex").unwrap_or_default();
            let created_at = crate::storage::extract_json_u64(record, "created_at_epoch_secs")
                .unwrap_or_else(now_secs);
            entries.push(SealedEnvelope {
                envelope_id: env_id,
                recipient_mailbox_id: mbx,
                ciphertext: payload_hex.into_bytes(),
                created_at_epoch_secs: created_at,
            });
        }
    }
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
        let queue_key = format!("sonaraim:queue:{mailbox_id}");
        if ids.is_empty() {
            if let Err(e) = redis.del(&queue_key) {
                st.redis_last_error = Some(e.to_string());
                eprintln!("{{\"level\":\"ERROR\",\"msg\":\"redis DEL failed\",\"error\":\"{e}\"}}");
            }
        } else {
            for id in &ids {
                let record_prefix = format!("{{\"envelope_id\":\"{id}\"");
                let victims: Vec<String> = match redis.lrange(&queue_key) {
                    Ok(records) => records
                        .into_iter()
                        .filter(|r| r.contains(&record_prefix))
                        .collect(),
                    Err(e) => {
                        st.redis_last_error = Some(e.to_string());
                        eprintln!("{{\"level\":\"ERROR\",\"msg\":\"redis LRANGE failed\",\"error\":\"{e}\"}}");
                        Vec::new()
                    }
                };
                for record in victims {
                    if let Err(e) = redis.lrem(&queue_key, &record) {
                        st.redis_last_error = Some(e.to_string());
                        eprintln!("{{\"level\":\"ERROR\",\"msg\":\"redis LREM failed\",\"error\":\"{e}\"}}");
                    }
                }
            }
        }
    }
    // Ack compaction rewrites only the envelope WAL; the identity WAL is
    // never touched by mailbox operations (one file, one schema).
    if let Some(ref envelope_wal) = st.envelope_wal_path {
        let mut active: Vec<(String, String, String, u64)> = Vec::new();
        for env in st.relay.all_active_envelopes(now_secs()) {
            active.push((
                env.envelope_id,
                env.recipient_mailbox_id,
                String::from_utf8_lossy(&env.ciphertext).to_string(),
                env.created_at_epoch_secs,
            ));
        }
        if let Err(e) = compact_wal_file(envelope_wal, &active) {
            eprintln!("{{\"level\":\"ERROR\",\"msg\":\"envelope wal compaction failed\",\"error\":\"{e}\"}}");
        }
    }
    (
        200,
        "OK",
        format!("{{\"status\":\"ok\",\"acknowledged\":{acked}}}"),
    )
}
