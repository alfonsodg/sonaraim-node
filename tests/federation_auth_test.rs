//! TDD regression tests for `sonaraim-node` #18: authenticated, TLS-capable federation.
//!
//! - Replication carries each peer's Bearer token; a peer with auth enabled
//!   and no dev bypass accepts replicated envelopes and identities.
//! - `execute_http_request` sends `Authorization: Bearer <token>` when given.
//! - `https://` peer URLs are parsed as TLS endpoints (not downgraded to
//!   plaintext); plain-`http://` behavior is unchanged.

use sonaraim_node::config::NodeConfig;
use sonaraim_node::federation_client::{execute_http_request, split_url};
use sonaraim_node::http_server::{start_test_server, NodeState};
use sonaraim_node::merkle::KeyTransparencyLog;
use sonaraim_node::relay::MailboxStore;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;

fn config_with_token(node_id: &str, token: Option<&str>) -> NodeConfig {
    let mut vars = HashMap::new();
    vars.insert("NODE_ID".to_string(), node_id.to_string());
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

fn send_http(
    addr: &str,
    method: &str,
    path: &str,
    bearer: Option<&str>,
    body: &str,
) -> (u16, String) {
    let mut stream = TcpStream::connect(addr).expect("connect to test http server");
    let auth = bearer
        .map(|t| format!("Authorization: Bearer {t}\r\n"))
        .unwrap_or_default();
    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: {addr}\r\n{auth}Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
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
fn issue18_url_splitting_supports_tls_endpoints() {
    let plain = split_url("http://127.0.0.1:8040/v1/identity").expect("parse http url");
    assert!(!plain.use_tls);
    assert_eq!(plain.host_port, "127.0.0.1:8040");
    assert_eq!(plain.path, "/v1/identity");

    let tls =
        split_url("https://node2.sonaraim.internal/v1/relay/envelopes").expect("parse https url");
    assert!(tls.use_tls);
    assert_eq!(tls.host_port, "node2.sonaraim.internal:443");
    assert_eq!(tls.path, "/v1/relay/envelopes");
}

#[test]
fn issue18_replication_sends_peer_bearer_token() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind probe");
    let addr = listener.local_addr().expect("addr").to_string();
    let seen = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
    let seen_clone = std::sync::Arc::clone(&seen);
    let handle = std::thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut buf = [0u8; 4096];
            let n = stream.read(&mut buf).unwrap_or(0);
            *seen_clone.lock().expect("lock") = String::from_utf8_lossy(&buf[..n]).to_string();
            let _ = stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}");
        }
    });
    let url = format!("http://{addr}/v1/relay/envelopes");
    let (status, _) = execute_http_request("POST", &url, "{}", Some("peer-secret-token"), 2000)
        .expect("request succeeds");
    assert_eq!(status, 200);
    handle.join().expect("probe join");
    let captured = seen.lock().expect("lock").clone();
    assert!(
        captured.contains("Authorization: Bearer peer-secret-token"),
        "replication must carry the peer Bearer token, got: {captured}"
    );
}

#[test]
fn issue18_two_nodes_replicate_with_auth_and_no_dev_bypass() {
    let node_a = NodeState::new(
        config_with_token("node-fed-a", Some("secret-a")),
        MailboxStore::new(3600),
        KeyTransparencyLog::default(),
    );
    let (addr_a, _h_a) = start_test_server(node_a).expect("start server a");

    let node_b = NodeState::new(
        config_with_token("node-fed-b", Some("secret-b")),
        MailboxStore::new(3600),
        KeyTransparencyLog::default(),
    );
    let (addr_b, _h_b) = start_test_server(node_b).expect("start server b");

    // Peer A -> B carrying B's token (per-peer credentials, no dev bypass).
    let peer_req = format!(
        r#"{{"peer_id":"node-fed-b","rpc_url":"http://{addr_b}","multiaddr":"/ip4/127.0.0.1/tcp/0","auth_token":"secret-b"}}"#
    );
    let (st, _) = send_http(
        &addr_a,
        "POST",
        "/v1/p2p/peers",
        Some("secret-a"),
        &peer_req,
    );
    assert_eq!(st, 201);

    // Identity registration on A replicates to auth-enabled B.
    let (st, _) = send_http(
        &addr_a,
        "POST",
        "/v1/identity",
        Some("secret-a"),
        r#"{"did":"did:sonaraim:fed-auth-user","key_commitment":"pk-fed-auth"}"#,
    );
    assert_eq!(st, 201);
    let (st, body) = send_http(
        &addr_b,
        "GET",
        "/v1/identity/did:sonaraim:fed-auth-user",
        None,
        "",
    );
    assert_eq!(st, 200);
    assert!(body.contains("did:sonaraim:fed-auth-user"));

    // Envelope replication to auth-enabled B.
    let (st, _) = send_http(
        &addr_a,
        "POST",
        "/v1/relay/envelopes",
        Some("secret-a"),
        r#"{"envelope_id":"env-fed-auth-1","recipient_mailbox_id":"did:sonaraim:fed-auth-user","payload_hex":"aabb"}"#,
    );
    assert_eq!(st, 202);
    let (st, body) = send_http(
        &addr_b,
        "GET",
        "/v1/relay/mailboxes/did:sonaraim:fed-auth-user",
        None,
        "",
    );
    assert_eq!(st, 200);
    assert!(body.contains("env-fed-auth-1"));
}
