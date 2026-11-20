//! TDD regression tests for `sonaraim-node` #25: naive JSON string scanners
//! silently mangle routing keys.
//!
//! - An earlier string field embedding `"recipient_mailbox_id":"..."` text
//!   (forwarded/nested payload) hijacks the naive first-match scan: the node
//!   answers 202 yet stores under the truncated key, so drain under the FULL
//!   DID key is empty — exactly the #25 E2E symptom.
//! - Whitespace around `:` or reordered keys breaks extraction entirely.
//! - Escaped quotes (`\"`) truncate values at the escape.
//!
//! RED phase: these tests MUST fail on the naive scanners before the fix.

use sonaraim_node::config::NodeConfig;
use sonaraim_node::http_server::{start_test_server, NodeState};
use sonaraim_node::merkle::KeyTransparencyLog;
use sonaraim_node::relay::MailboxStore;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;

fn dev_config() -> NodeConfig {
    let mut vars = HashMap::new();
    vars.insert("NODE_ID".to_string(), "node-json-25".to_string());
    vars.insert("NODE_HTTP_HOST".to_string(), "127.0.0.1".to_string());
    vars.insert("NODE_HTTP_PORT".to_string(), "8040".to_string());
    vars.insert(
        "NODE_P2P_LISTEN_ADDR".to_string(),
        "/ip4/127.0.0.1/udp/0/quic-v1".to_string(),
    );
    vars.insert("NODE_ENVELOPE_TTL_SECONDS".to_string(), "3600".to_string());
    vars.insert("NODE_ALLOW_DEV_NOAUTH".to_string(), "true".to_string());
    NodeConfig::from_map(&vars).expect("valid dev config")
}

fn send_http(addr: &str, method: &str, path: &str, body: &str) -> (u16, String) {
    let mut stream = TcpStream::connect(addr).expect("connect to test http server");
    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(req.as_bytes()).expect("write request");
    let mut raw = String::new();
    stream.read_to_string(&mut raw).expect("read response");
    let (head, resp_body) = raw.split_once("\r\n\r\n").unwrap_or((&raw, ""));
    let status = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);
    (status, resp_body.to_string())
}

#[test]
fn issue25_nested_key_text_must_not_hijack_routing_key() {
    use sonaraim_node::envelope_wal::envelope_wal_path_from_identity_wal;
    use sonaraim_node::storage::wal_path_from_signing_key;

    let dir = std::env::temp_dir().join(format!("sonaraim-json25-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let signing_key = dir.join("node-signing.key");
    let identity_wal = wal_path_from_signing_key(&signing_key.to_string_lossy());
    let envelope_wal = envelope_wal_path_from_identity_wal(&identity_wal);

    let state = NodeState::with_wal_and_redis(
        dev_config(),
        MailboxStore::new(3600),
        KeyTransparencyLog::default(),
        Some(identity_wal.clone()),
        None,
    );
    let (addr, handle) = start_test_server(state).expect("start server");

    // Earlier string field embeds `"recipient_mailbox_id":"did:sonaraim:e2e-"`
    // text (nested/forwarded payload). The real recipient is the FULL DID key.
    let full_key = "did:sonaraim:relay-ts-25";
    let body = format!(
        "{{\"note\":\"ref \\\"recipient_mailbox_id\\\":\\\"did:sonaraim:e2e-\\\" ok\",\"envelope_id\":\"env-25-nested\",\"recipient_mailbox_id\":\"{full_key}\",\"payload_hex\":\"beef\"}}"
    );
    let (st, _) = send_http(&addr, "POST", "/v1/relay/envelopes", &body);
    assert_eq!(st, 202);

    // Drain under the FULL key must return the envelope (empty pre-fix).
    let (st, drained) = send_http(&addr, "GET", &format!("/v1/relay/mailboxes/{full_key}"), "");
    assert_eq!(st, 200);
    assert!(
        drained.contains("env-25-nested"),
        "drain under full DID key lost the envelope: {drained}"
    );

    // WAL must persist the FULL key, never the truncated decoy.
    let wal_raw = std::fs::read_to_string(&envelope_wal).expect("read envelope wal");
    assert!(
        wal_raw.contains(full_key),
        "envelope WAL lost the full DID key: {wal_raw}"
    );

    // Restart: WAL replay must restore under the FULL key.
    drop(handle);
    let restarted = NodeState::with_wal_and_redis(
        dev_config(),
        MailboxStore::new(3600),
        KeyTransparencyLog::default(),
        Some(identity_wal.clone()),
        None,
    );
    let (r_addr, _r_handle) = start_test_server(restarted).expect("restart server");
    let (st, replayed) = send_http(
        &r_addr,
        "GET",
        &format!("/v1/relay/mailboxes/{full_key}"),
        "",
    );
    assert_eq!(st, 200);
    assert!(
        replayed.contains("env-25-nested"),
        "WAL replay lost the envelope under the full DID key: {replayed}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn issue25_whitespace_and_key_order_post_round_trips() {
    let state = NodeState::new(
        dev_config(),
        MailboxStore::new(3600),
        KeyTransparencyLog::default(),
    );
    let (addr, _handle) = start_test_server(state).expect("start server");

    // Same JSON semantics, different spacing and field order.
    let body = r#"{"payload_hex" : "beef01", "recipient_mailbox_id" : "did:sonaraim:spaced-25", "envelope_id" : "env-25-sp"}"#;
    let (st, _) = send_http(&addr, "POST", "/v1/relay/envelopes", body);
    assert_eq!(st, 202, "spaced/reordered envelope body rejected");

    let (st, drained) = send_http(
        &addr,
        "GET",
        "/v1/relay/mailboxes/did:sonaraim:spaced-25",
        "",
    );
    assert_eq!(st, 200);
    assert!(
        drained.contains("env-25-sp"),
        "spaced envelope lost: {drained}"
    );
}

#[test]
fn issue25_escaped_quotes_and_arrays_parse_fully() {
    use sonaraim_node::storage::{extract_json_str, extract_json_str_array};

    let got = extract_json_str(r#"{"v":"a\"b"}"#, "v");
    assert_eq!(
        got.as_deref(),
        Some("a\"b"),
        "escaped quote truncated: {got:?}"
    );

    let got = extract_json_str(r#"{"b":"x","v":"did:sonaraim:q\"q"}"#, "v");
    assert_eq!(
        got.as_deref(),
        Some("did:sonaraim:q\"q"),
        "DID value with escaped quote mangled: {got:?}"
    );

    let arr = extract_json_str_array(r#"{"ids":["a,b","c\"d"]}"#, "ids");
    assert_eq!(arr, vec!["a,b".to_string(), "c\"d".to_string()]);

    let arr = extract_json_str_array(r#"{ "ids" : [ "x" , "y" ] }"#, "ids");
    assert_eq!(arr, vec!["x".to_string(), "y".to_string()]);
}

#[test]
fn issue25_envelope_wal_tolerates_spacing_and_order() {
    use sonaraim_node::envelope_wal::EnvelopeWalEntry;

    let line = r#"{"created_at_epoch_secs": 100, "payload_hex" : "aabb", "recipient_mailbox_id" : "did:sonaraim:replay-25", "envelope_id" : "env-25-re"}"#;
    let entry = EnvelopeWalEntry::from_json_line(line).expect("spaced WAL line parses");
    assert_eq!(entry.envelope_id, "env-25-re");
    assert_eq!(entry.recipient_mailbox_id, "did:sonaraim:replay-25");
    assert_eq!(entry.payload_hex, "aabb");
    assert_eq!(entry.created_at_epoch_secs, 100);
}

#[test]
fn issue25_did_web_document_tolerates_spacing() {
    use sonaraim_node::did_web::document_matches_did;

    let doc = r#"{"id" : "did:web:example.com", "verificationMethod" : ["key-1"]}"#;
    assert!(document_matches_did("did:web:example.com", doc));
}
