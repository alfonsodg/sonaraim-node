//! TDD integration tests for Milestone 10 (`sonaraim-node` #8, #9, #10, #11, #12):
//! - #8: Percent-decoded DID path routing (`%3A` -> `:`) and `NODE_API_AUTH_TOKEN` Bearer gate on write routes

use sonaraim_node::config::NodeConfig;
use sonaraim_node::http_auth::{percent_decode_path, verify_bearer_token};
use sonaraim_node::http_server::{start_test_server, NodeState};
use sonaraim_node::merkle::KeyTransparencyLog;
use sonaraim_node::relay::MailboxStore;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;

fn config_with_token(token: Option<&str>) -> NodeConfig {
    let mut vars = HashMap::new();
    vars.insert("NODE_ID".to_string(), "node-m10-01".to_string());
    vars.insert("NODE_HTTP_HOST".to_string(), "127.0.0.1".to_string());
    vars.insert("NODE_HTTP_PORT".to_string(), "8040".to_string());
    vars.insert(
        "NODE_P2P_LISTEN_ADDR".to_string(),
        "/ip4/127.0.0.1/udp/0/quic-v1".to_string(),
    );
    vars.insert("NODE_ENVELOPE_TTL_SECONDS".to_string(), "3600".to_string());
    if let Some(t) = token {
        vars.insert("NODE_API_AUTH_TOKEN".to_string(), t.to_string());
    }
    NodeConfig::from_map(&vars).expect("valid config")
}

fn send_http_with_auth(
    addr: &str,
    method: &str,
    path: &str,
    bearer: Option<&str>,
    body: &str,
) -> (u16, String) {
    let mut stream = TcpStream::connect(addr).expect("connect to test http server");
    let auth_header = bearer
        .map(|t| format!("Authorization: Bearer {t}\r\n"))
        .unwrap_or_default();
    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: {addr}\r\n{auth_header}Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
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
fn issue8_percent_decoded_did_paths_and_bearer_auth_gate_on_writes() {
    assert_eq!(
        percent_decode_path("/v1/identity/did%3Asonaraim%3Aalice"),
        "/v1/identity/did:sonaraim:alice"
    );
    assert!(verify_bearer_token(
        "POST /v1/identity HTTP/1.1\r\nAuthorization: Bearer topsecret\r\n",
        Some("topsecret")
    ));
    assert!(!verify_bearer_token(
        "POST /v1/identity HTTP/1.1\r\nAuthorization: Bearer wrong\r\n",
        Some("topsecret")
    ));

    let state = NodeState::new(
        config_with_token(Some("sec-token-8")),
        MailboxStore::new(3600),
        KeyTransparencyLog::default(),
    );
    let (addr, _handle) = start_test_server(state).expect("start server");

    // Write without token -> 401 Unauthorized
    let (st_unauth, _) = send_http_with_auth(
        &addr,
        "POST",
        "/v1/identity",
        None,
        r#"{"did":"did:sonaraim:e2e-phase2-user","key_commitment":"pk-e2e"}"#,
    );
    assert_eq!(st_unauth, 401);

    // Write with valid Bearer token -> 201 Created
    let (st_ok, _) = send_http_with_auth(
        &addr,
        "POST",
        "/v1/identity",
        Some("sec-token-8"),
        r#"{"did":"did:sonaraim:e2e-phase2-user","key_commitment":"pk-e2e"}"#,
    );
    assert_eq!(st_ok, 201);

    // Percent-encoded GET /v1/identity/did%3Asonaraim%3Ae2e-phase2-user -> 200 OK
    let (st_get_id, body_id) = send_http_with_auth(
        &addr,
        "GET",
        "/v1/identity/did%3Asonaraim%3Ae2e-phase2-user",
        None,
        "",
    );
    assert_eq!(st_get_id, 200);
    assert!(body_id.contains("did:sonaraim:e2e-phase2-user"));

    // Enqueue envelope with Bearer token
    let (st_env, _) = send_http_with_auth(
        &addr,
        "POST",
        "/v1/relay/envelopes",
        Some("sec-token-8"),
        r#"{"envelope_id":"env-url-1","recipient_mailbox_id":"did:sonaraim:e2e-phase2-user","payload_hex":"deadbeef"}"#,
    );
    assert_eq!(st_env, 202);

    // Percent-encoded GET /v1/relay/mailboxes/did%3Asonaraim%3Ae2e-phase2-user -> 200 OK with env-url-1
    let (st_mbx, body_mbx) = send_http_with_auth(
        &addr,
        "GET",
        "/v1/relay/mailboxes/did%3Asonaraim%3Ae2e-phase2-user",
        None,
        "",
    );
    assert_eq!(st_mbx, 200);
    assert!(body_mbx.contains("env-url-1"));
}

#[test]
fn issue9_s3_object_upload_and_wal_compaction() {
    use sonaraim_node::s3_wal_maintenance::{compact_wal_file, put_s3_object_http};
    use std::net::TcpListener;
    use std::thread;

    // 1. WAL Compaction
    let temp_dir = std::env::temp_dir().join(format!("sonaraim-wal-test-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&temp_dir);
    let wal_path = temp_dir.join("test_mailboxes.wal");
    std::fs::write(
        &wal_path,
        "{\"envelope_id\":\"old-stale\",\"recipient_mailbox_id\":\"stale-mbx\",\"payload_hex\":\"00\"}\n",
    )
    .expect("write initial wal");

    let active_entries = vec![
        (
            "env-active-1".to_string(),
            "mbx-active".to_string(),
            "01020304".to_string(),
        ),
        (
            "env-active-2".to_string(),
            "mbx-active".to_string(),
            "05060708".to_string(),
        ),
    ];
    let written = compact_wal_file(&wal_path, &active_entries).expect("compact wal");
    assert_eq!(written, 2);

    let compacted = std::fs::read_to_string(&wal_path).expect("read compacted wal");
    assert!(!compacted.contains("old-stale"));
    assert!(compacted.contains("env-active-1"));
    assert!(compacted.contains("env-active-2"));

    // 2. Mock S3 HTTP PUT
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock s3");
    let mock_addr = listener.local_addr().expect("local addr").to_string();

    let server_handle = thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut buf = [0u8; 1024];
            let n = stream.read(&mut buf).unwrap_or(0);
            let req = String::from_utf8_lossy(&buf[..n]);
            assert!(req.starts_with("PUT /media-bucket/avatar.bin HTTP/1.1"));
            assert!(req.contains("Content-Length: 13"));
            let resp = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            let _ = stream.write_all(resp.as_bytes());
        }
    });

    let status = put_s3_object_http(
        &format!("http://{mock_addr}"),
        "media-bucket",
        "avatar.bin",
        b"encrypted-pic",
        2000,
    )
    .expect("s3 put success");
    assert_eq!(status, 200);

    let _ = server_handle.join();
    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn issue10_relay_full_envelope_items_and_ack() {
    let state = NodeState::new(
        config_with_token(None),
        MailboxStore::new(3600),
        KeyTransparencyLog::default(),
    );
    let (addr, _handle) = start_test_server(state).expect("start server");

    // 1. Post envelope with payload_hex
    let (st_post, _) = send_http_with_auth(
        &addr,
        "POST",
        "/v1/relay/envelopes",
        None,
        r#"{"envelope_id":"env-payload-10","recipient_mailbox_id":"did:sonaraim:bob","payload_hex":"cafebabe1234"}"#,
    );
    assert_eq!(st_post, 202);

    // 2. GET mailbox returns both envelopes array AND items array with payload_hex
    let (st_get, body_get) = send_http_with_auth(
        &addr,
        "GET",
        "/v1/relay/mailboxes/did%3Asonaraim%3Abob",
        None,
        "",
    );
    assert_eq!(st_get, 200);
    assert!(body_get.contains(r#""envelopes":["env-payload-10"]"#));
    assert!(body_get.contains(r#""payload_hex":"cafebabe1234""#));
    assert!(body_get.contains(r#""recipient_mailbox_id":"did:sonaraim:bob""#));

    // 3. POST ack pops the envelope
    let (st_ack, body_ack) = send_http_with_auth(
        &addr,
        "POST",
        "/v1/relay/mailboxes/did:sonaraim:bob/ack",
        None,
        r#"{"envelope_ids":["env-payload-10"]}"#,
    );
    assert_eq!(st_ack, 200);
    assert!(body_ack.contains(r#""acknowledged":1"#));

    // 4. Subsequent GET returns empty arrays
    let (st_empty, body_empty) = send_http_with_auth(
        &addr,
        "GET",
        "/v1/relay/mailboxes/did:sonaraim:bob",
        None,
        "",
    );
    assert_eq!(st_empty, 200);
    assert!(body_empty.contains(r#""envelopes":[]"#));
    assert!(body_empty.contains(r#""items":[]"#));
}
