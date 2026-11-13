use sonaraim_node::config::NodeConfig;
use sonaraim_node::http_server::{start_test_server, NodeState};
use sonaraim_node::merkle::KeyTransparencyLog;
use sonaraim_node::push_signals::{
    sha256_hex, EphemeralSignal, PushPlatform, PushRegistration, PushSignalRegistry, SignalType,
};
use sonaraim_node::relay::MailboxStore;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;

fn sample_config() -> NodeConfig {
    let mut vars = HashMap::new();
    vars.insert("NODE_ID".to_string(), "node-push-test".to_string());
    vars.insert("NODE_HTTP_HOST".to_string(), "127.0.0.1".to_string());
    vars.insert("NODE_HTTP_PORT".to_string(), "8040".to_string());
    vars.insert(
        "NODE_P2P_LISTEN_ADDR".to_string(),
        "/ip4/127.0.0.1/udp/0/quic-v1".to_string(),
    );
    vars.insert("NODE_ENVELOPE_TTL_SECONDS".to_string(), "3600".to_string());
    NodeConfig::from_map(&vars).expect("sample config must be valid")
}

fn send_raw_http(addr: &str, req: &str) -> String {
    let mut stream = TcpStream::connect(addr).expect("connect to test server");
    stream.write_all(req.as_bytes()).expect("write request");
    let mut resp = String::new();
    stream.read_to_string(&mut resp).expect("read response");
    resp
}

fn make_test_state() -> NodeState {
    let cfg = sample_config();
    let relay = MailboxStore::new(cfg.envelope_ttl_seconds);
    let kt_log = KeyTransparencyLog::default();
    NodeState::new(cfg, relay, kt_log)
}

#[test]
fn test_push_registration_sha256_blind_token() {
    let mut registry = PushSignalRegistry::new();
    let raw_token = "device-token-secret-xyz-987";
    let expected_hash = sha256_hex(raw_token.as_bytes());

    let reg: PushRegistration = registry.register_push_token(
        "mbx-user-alpha",
        PushPlatform::Apns,
        raw_token,
        Some("https://api.push.apple.com"),
        1_700_000_000,
    );

    assert_eq!(reg.mailbox_id, "mbx-user-alpha");
    assert_eq!(reg.platform, PushPlatform::Apns);
    assert_eq!(reg.token_hash, expected_hash);
    assert_eq!(reg.token_hash.len(), 64);
    assert_eq!(
        reg.endpoint_hint.as_deref(),
        Some("https://api.push.apple.com")
    );
    assert!(!format!("{reg:?}").contains(raw_token));
    assert!(registry.has_registration("mbx-user-alpha"));
    assert!(!registry.has_registration("mbx-unregistered"));
}

#[test]
fn test_blind_silent_wakeup_payload_content_free() {
    let mut registry = PushSignalRegistry::new();
    registry.register_push_token(
        "mbx-target-beta",
        PushPlatform::Fcm,
        "fcm-raw-device-token-secret",
        None,
        1_700_000_000,
    );

    let payload = registry
        .build_silent_wakeup_payload("mbx-target-beta")
        .expect("payload should exist for registered mailbox");

    assert!(payload.contains("\"mailbox_id\":\"mbx-target-beta\""));
    assert!(payload.contains("\"wake\":true"));
    assert!(payload.contains("\"has_pending\":true"));

    // Verify zero message plaintext or sender metadata
    assert!(!payload.contains("sender"));
    assert!(!payload.contains("did:"));
    assert!(!payload.contains("ciphertext"));
    assert!(!payload.contains("payload"));
    assert!(!payload.contains("content"));
    assert!(!payload.contains("fcm-raw-device-token-secret"));

    assert!(registry
        .build_silent_wakeup_payload("unknown-mbx")
        .is_none());
}

#[test]
fn test_ephemeral_typing_and_receipt_signals_ttl_and_drain() {
    let mut registry = PushSignalRegistry::new();
    let t0 = 1_700_000_000;

    // Typing signal has 30s TTL
    let s1: EphemeralSignal = registry.record_signal(
        "mbx-alice",
        "did:sonaraim:bob",
        SignalType::Typing,
        None,
        t0,
    );
    assert_eq!(s1.expires_at_epoch, t0 + 30);

    // Delivered receipt has 300s TTL
    let s2 = registry.record_signal(
        "mbx-alice",
        "did:sonaraim:bob",
        SignalType::Delivered,
        Some("env-1001"),
        t0,
    );
    assert_eq!(s2.expires_at_epoch, t0 + 300);

    // Read receipt has 300s TTL
    let s3 = registry.record_signal(
        "mbx-alice",
        "did:sonaraim:bob",
        SignalType::Read,
        Some("env-1001"),
        t0,
    );
    assert_eq!(s3.expires_at_epoch, t0 + 300);

    // Drain at t0 + 10s: all 3 should be returned
    let drained = registry.drain_signals("mbx-alice", t0 + 10);
    assert_eq!(drained.len(), 3);

    // Subsequent drain should be empty
    let empty = registry.drain_signals("mbx-alice", t0 + 10);
    assert!(empty.is_empty());

    // Record new typing at t0, drain at t0 + 35s (expired)
    registry.record_signal(
        "mbx-alice",
        "did:sonaraim:bob",
        SignalType::Typing,
        None,
        t0,
    );
    let expired = registry.drain_signals("mbx-alice", t0 + 35);
    assert!(expired.is_empty());
}

#[test]
fn test_http_push_register_and_silent_wakeup_on_relay() {
    let state = make_test_state();
    let (addr, _handle) = start_test_server(state).expect("start server");

    let reg_body = r#"{"mailbox_id":"mbx-push-1","platform":"fcm","device_token":"secret-fcm-tok-456","endpoint_hint":"https://fcm.googleapis.com"}"#;
    let req = format!(
        "POST /v1/push/register HTTP/1.1\r\nContent-Length: {}\r\n\r\n{}",
        reg_body.len(),
        reg_body
    );
    let resp = send_raw_http(&addr, &req);
    assert!(resp.contains("200 OK"), "expected 200 OK, got: {resp}");
    assert!(resp.contains("\"registered\":true"));
    assert!(resp.contains("\"mailbox_id\":\"mbx-push-1\""));
    assert!(resp.contains("\"token_hash\""));
    assert!(!resp.contains("secret-fcm-tok-456"));

    // Enqueue envelope for registered mailbox -> wake_up_queued should be true
    let env_body = r#"{"envelope_id":"env-push-test","recipient_mailbox_id":"mbx-push-1","payload_hex":"deadbeef"}"#;
    let env_req = format!(
        "POST /v1/relay/envelopes HTTP/1.1\r\nContent-Length: {}\r\n\r\n{}",
        env_body.len(),
        env_body
    );
    let env_resp = send_raw_http(&addr, &env_req);
    assert!(env_resp.contains("202 Accepted"), "got: {env_resp}");
    assert!(env_resp.contains("\"wake_up_queued\":true"));

    // Enqueue envelope for unregistered mailbox -> wake_up_queued should be false
    let unreg_body = r#"{"envelope_id":"env-push-unreg","recipient_mailbox_id":"mbx-not-registered","payload_hex":"cafebabe"}"#;
    let unreg_req = format!(
        "POST /v1/relay/envelopes HTTP/1.1\r\nContent-Length: {}\r\n\r\n{}",
        unreg_body.len(),
        unreg_body
    );
    let unreg_resp = send_raw_http(&addr, &unreg_req);
    assert!(unreg_resp.contains("202 Accepted"));
    assert!(unreg_resp.contains("\"wake_up_queued\":false"));
}

#[test]
fn test_http_ephemeral_signal_relay_and_drain() {
    let state = make_test_state();
    let (addr, _handle) = start_test_server(state).expect("start server");

    // Post typing signal
    let typing_body = r#"{"mailbox_id":"mbx-signals-1","sender_did":"did:sonaraim:alice","signal_type":"typing"}"#;
    let post_req1 = format!(
        "POST /v1/relay/signals HTTP/1.1\r\nContent-Length: {}\r\n\r\n{}",
        typing_body.len(),
        typing_body
    );
    let resp1 = send_raw_http(&addr, &post_req1);
    assert!(resp1.contains("200 OK"), "got: {resp1}");
    assert!(resp1.contains("\"recorded\":true"));

    // Post read receipt signal
    let read_body = r#"{"mailbox_id":"mbx-signals-1","sender_did":"did:sonaraim:alice","signal_type":"read","envelope_id":"env-sig-123"}"#;
    let post_req2 = format!(
        "POST /v1/relay/signals HTTP/1.1\r\nContent-Length: {}\r\n\r\n{}",
        read_body.len(),
        read_body
    );
    let resp2 = send_raw_http(&addr, &post_req2);
    assert!(resp2.contains("200 OK"), "got: {resp2}");

    // Drain signals via GET
    let get_req = "GET /v1/relay/signals/mbx-signals-1 HTTP/1.1\r\n\r\n";
    let get_resp = send_raw_http(&addr, get_req);
    assert!(get_resp.contains("200 OK"), "got: {get_resp}");
    assert!(get_resp.contains("\"signal_type\":\"typing\""));
    assert!(get_resp.contains("\"signal_type\":\"read\""));
    assert!(get_resp.contains("\"envelope_id\":\"env-sig-123\""));

    // Second GET should drain and return empty list
    let get_resp2 = send_raw_http(&addr, get_req);
    assert!(get_resp2.contains("200 OK"));
    assert!(get_resp2.contains("\"signals\":[]"));
}

#[test]
fn test_http_push_and_signals_validation_errors() {
    let state = make_test_state();
    let (addr, _handle) = start_test_server(state).expect("start server");

    // Invalid platform
    let bad_platform =
        r#"{"mailbox_id":"mbx-bad","platform":"invalid_service","device_token":"tok123"}"#;
    let req1 = format!(
        "POST /v1/push/register HTTP/1.1\r\nContent-Length: {}\r\n\r\n{}",
        bad_platform.len(),
        bad_platform
    );
    let resp1 = send_raw_http(&addr, &req1);
    assert!(resp1.contains("400 Bad Request"));
    assert!(resp1.contains("INVALID_PLATFORM"));

    // Invalid signal type
    let bad_signal = r#"{"mailbox_id":"mbx-bad","sender_did":"did:sonaraim:alice","signal_type":"unknown_signal"}"#;
    let req2 = format!(
        "POST /v1/relay/signals HTTP/1.1\r\nContent-Length: {}\r\n\r\n{}",
        bad_signal.len(),
        bad_signal
    );
    let resp2 = send_raw_http(&addr, &req2);
    assert!(resp2.contains("400 Bad Request"));
    assert!(resp2.contains("INVALID_SIGNAL_TYPE"));
}
