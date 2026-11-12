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

fn config_with_id(node_id: &str) -> NodeConfig {
    let mut vars = HashMap::new();
    vars.insert("NODE_ID".to_string(), node_id.to_string());
    vars.insert("NODE_HTTP_HOST".to_string(), "127.0.0.1".to_string());
    vars.insert("NODE_HTTP_PORT".to_string(), "8049".to_string());
    vars.insert(
        "NODE_P2P_LISTEN_ADDR".to_string(),
        "/ip4/127.0.0.1/udp/0/quic-v1".to_string(),
    );
    vars.insert("NODE_ENVELOPE_TTL_SECONDS".to_string(), "3600".to_string());
    NodeConfig::from_map(&vars).expect("valid config")
}

#[test]
fn issue11_multi_node_federation_replication_and_equivocation_detection() {
    let node_a = NodeState::new(
        config_with_id("node-ent-a"),
        MailboxStore::new(3600),
        KeyTransparencyLog::default(),
    );
    let (addr_a, _h_a) = start_test_server(node_a).expect("start server a");

    let node_b = NodeState::new(
        config_with_id("node-user-b"),
        MailboxStore::new(3600),
        KeyTransparencyLog::default(),
    );
    let (addr_b, _h_b) = start_test_server(node_b).expect("start server b");

    // 1. Peer Node A with Node B
    let peer_req = format!(
        r#"{{"peer_id":"node-user-b","rpc_url":"http://{addr_b}","multiaddr":"/ip4/127.0.0.1/tcp/0"}}"#
    );
    let (st_peer, body_peer) =
        send_http_with_auth(&addr_a, "POST", "/v1/p2p/peers", None, &peer_req);
    assert_eq!(st_peer, 201);
    assert!(body_peer.contains("peered"));

    let (st_peers_list, body_peers) =
        send_http_with_auth(&addr_a, "GET", "/v1/p2p/peers", None, "");
    assert_eq!(st_peers_list, 200);
    assert!(body_peers.contains("node-user-b"));

    // 2. Register identity on Node A -> replicates to Node B
    let id_req = r#"{"did":"did:sonaraim:alice-fed","key_commitment":"pk-alice-fed"}"#;
    let (st_id, _) = send_http_with_auth(&addr_a, "POST", "/v1/identity", None, id_req);
    assert_eq!(st_id, 201);

    // Verify identity on Node B
    let (st_id_b, body_id_b) = send_http_with_auth(
        &addr_b,
        "GET",
        "/v1/identity/did:sonaraim:alice-fed",
        None,
        "",
    );
    assert_eq!(st_id_b, 200);
    assert!(body_id_b.contains("did:sonaraim:alice-fed"));

    // 3. Post envelope on Node A -> replicates to Node B
    let env_req = r#"{"envelope_id":"env-fed-001","recipient_mailbox_id":"did:sonaraim:alice-fed","payload_hex":"deadbeef42"}"#;
    let (st_env, _) = send_http_with_auth(&addr_a, "POST", "/v1/relay/envelopes", None, env_req);
    assert_eq!(st_env, 202);

    // Recipient fetches from Node B
    let (st_mbx_b, body_mbx_b) = send_http_with_auth(
        &addr_b,
        "GET",
        "/v1/relay/mailboxes/did:sonaraim:alice-fed",
        None,
        "",
    );
    assert_eq!(st_mbx_b, 200);
    assert!(body_mbx_b.contains("env-fed-001"));
    assert!(body_mbx_b.contains("deadbeef42"));

    // 4. Merkle equivocation detection on Node B -> 409 Conflict
    let equivocation_gossip =
        r#"{"node_id":"node-ent-a","tree_size":1,"root_hash":"conflicting-hash-999"}"#;
    let (st_equiv, body_equiv) =
        send_http_with_auth(&addr_b, "POST", "/v1/p2p/gossip", None, equivocation_gossip);
    assert_eq!(st_equiv, 409);
    assert!(body_equiv.contains("EQUIVOCATION_DETECTED"));
}

#[test]
fn issue12_phone_token_psi_and_routing() {
    let state = NodeState::new(
        config_with_token(None),
        MailboxStore::new(3600),
        KeyTransparencyLog::default(),
    );
    let (addr, _handle) = start_test_server(state).expect("start server");

    // 1. Register identity with phone_token
    let reg_req = r#"{"did":"did:sonaraim:alice-phone","key_commitment":"pk-alice-phone","phone_token":"+51999888777"}"#;
    let (st_reg, body_reg) = send_http_with_auth(&addr, "POST", "/v1/identity", None, reg_req);
    assert_eq!(st_reg, 201);
    assert!(body_reg.contains("did:sonaraim:alice-phone"));

    // 2. Query by phone token (percent-encoded + -> %2B or literal)
    let (st_phone, body_phone) = send_http_with_auth(
        &addr,
        "GET",
        "/v1/identity/by-phone/%2B51999888777",
        None,
        "",
    );
    assert_eq!(st_phone, 200);
    assert!(body_phone.contains("did:sonaraim:alice-phone"));

    // 3. Contact book PSI evaluation with match
    let psi_req = r#"{"blinded_tokens":["+51999888777","+51000111222"]}"#;
    let (st_psi, body_psi) = send_http_with_auth(&addr, "POST", "/v1/contacts/psi", None, psi_req);
    assert_eq!(st_psi, 200);
    assert!(body_psi.contains("evaluated_tokens"));
    assert!(body_psi.contains("matches"));
    assert!(body_psi.contains("did:sonaraim:alice-phone"));
    assert!(body_psi.contains("+51999888777"));

    // 4. Query unregistered phone token -> 404
    let (st_404, _) = send_http_with_auth(
        &addr,
        "GET",
        "/v1/identity/by-phone/%2B51000111222",
        None,
        "",
    );
    assert_eq!(st_404, 404);
}
