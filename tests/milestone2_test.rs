//! TDD integration tests for Milestone 2 & 5 (`sonaraim-node` #2, #3, #4, #5):
//! - #2: P2P mesh gossip, SignedTreeHead equivocation detection, envelope forwarding
//! - #3: Live HTTP REST server (`GET /health`, `POST /v1/identity`, `GET /v1/identity/{did}`,
//!       `POST /v1/relay/envelopes`, `GET /v1/relay/mailboxes/{id}`)
//! - #4: Durable snapshot persistence & S3 presigned media URL generation (`POST /v1/media/presign`)
//! - #5: PSI blind contact discovery (`POST /v1/contacts/psi`) & L2 anchor receipts (`GET /v1/identity/anchors/latest`)

use sonaraim_node::config::NodeConfig;
use sonaraim_node::http_server::{start_test_server, NodeState};
use sonaraim_node::merkle::KeyTransparencyLog;
use sonaraim_node::p2p::{P2pMeshNode, SignedTreeHead};
use sonaraim_node::psi_service::{build_l2_anchor_receipt, evaluate_psi_batch};
use sonaraim_node::relay::MailboxStore;
use sonaraim_node::storage::{generate_s3_presigned_url, NodeSnapshot};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;

fn sample_config() -> NodeConfig {
    let mut vars = HashMap::new();
    vars.insert("NODE_ID".to_string(), "node-test-01".to_string());
    vars.insert("NODE_HTTP_HOST".to_string(), "127.0.0.1".to_string());
    vars.insert("NODE_HTTP_PORT".to_string(), "8040".to_string());
    vars.insert(
        "NODE_P2P_LISTEN_ADDR".to_string(),
        "/ip4/127.0.0.1/udp/0/quic-v1".to_string(),
    );
    vars.insert("NODE_ENVELOPE_TTL_SECONDS".to_string(), "3600".to_string());
    NodeConfig::from_map(&vars).expect("sample config must be valid")
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
fn p2p_mesh_syncs_merkle_heads_and_rejects_equivocation() {
    let mut node_a = P2pMeshNode::new("node-a");
    let mut node_b = P2pMeshNode::new("node-b");
    node_a.add_peer("node-b", "/ip4/10.0.0.2/udp/8041/quic-v1");

    let sth1 = SignedTreeHead {
        node_id: "node-a".to_string(),
        tree_size: 10,
        root_hash: "aaaa1111".to_string(),
    };
    assert!(node_b.accept_tree_head(sth1).is_ok());

    let equivocating = SignedTreeHead {
        node_id: "node-a".to_string(),
        tree_size: 10,
        root_hash: "bbbb2222".to_string(),
    };
    assert!(node_b.accept_tree_head(equivocating).is_err());
}

#[test]
fn http_server_handles_all_documented_endpoints_and_methods() {
    let state = NodeState::new(
        sample_config(),
        MailboxStore::new(3600),
        KeyTransparencyLog::default(),
    );
    let (addr, handle) = start_test_server(state).expect("start http server");

    let (st, health_body) = send_http(&addr, "GET", "/health", "");
    assert_eq!(st, 200);
    assert!(health_body.contains("\"status\":\"ok\""));

    let (st, id_resp) = send_http(
        &addr,
        "POST",
        "/v1/identity",
        r#"{"did":"did:web:clinic.example.com","key_commitment":"ed25519_pub_01"}"#,
    );
    assert_eq!(st, 201);
    assert!(id_resp.contains("clinic.example.com"));

    let (st, resolved) = send_http(&addr, "GET", "/v1/identity/did:web:clinic.example.com", "");
    assert_eq!(st, 200);
    assert!(resolved.contains("\"verified_b2b\":true"));

    let (st, missing) = send_http(&addr, "GET", "/v1/identity/did:web:unknown.example.com", "");
    assert_eq!(st, 404);
    assert!(missing.contains("NOT_FOUND"));

    let (st, relay_resp) = send_http(
        &addr,
        "POST",
        "/v1/relay/envelopes",
        r#"{"envelope_id":"env-1","recipient_mailbox_id":"mbx-100","payload_hex":"aabbccdd"}"#,
    );
    assert_eq!(st, 202);
    assert!(relay_resp.contains("wake_up_token"));

    let (st, drained) = send_http(&addr, "GET", "/v1/relay/mailboxes/mbx-100", "");
    assert_eq!(st, 200);
    assert!(drained.contains("env-1"));

    let (st, presign) = send_http(
        &addr,
        "POST",
        "/v1/media/presign",
        r#"{"content_length":1024,"sha256_ciphertext":"deadbeef"}"#,
    );
    assert_eq!(st, 200);
    assert!(presign.contains("presigned_url"));

    let (st, psi_resp) = send_http(
        &addr,
        "POST",
        "/v1/contacts/psi",
        r#"{"blinded_tokens":["tok1","tok2"]}"#,
    );
    assert_eq!(st, 200);
    assert!(psi_resp.contains("evaluated_tokens"));

    let (st, anchor_resp) = send_http(&addr, "GET", "/v1/identity/anchors/latest", "");
    assert_eq!(st, 200);
    assert!(anchor_resp.contains("root_hash"));

    drop(handle);
}

#[test]
fn durable_snapshot_and_s3_presign_and_psi_work_deterministically() {
    let mut log = KeyTransparencyLog::default();
    log.append("did:sonaraim:alice", "pk-alice", 1_700_000_000)
        .expect("append");
    let snap = NodeSnapshot::capture(&log);
    let encoded = snap.to_json_lines();
    let restored = NodeSnapshot::from_json_lines(&encoded).expect("restore");
    assert_eq!(restored.tree_head, log.tree_head());

    let url =
        generate_s3_presigned_url("https://s3.example.com", "sonaraim-media", "deadbeef", 1024);
    assert!(url.starts_with("https://s3.example.com/sonaraim-media/deadbeef?sig="));

    let eval = evaluate_psi_batch(&["blind-1".to_string()], b"secret-key");
    assert_eq!(eval.len(), 1);
    let receipt = build_l2_anchor_receipt(log.len(), &log.tree_head(), 1_700_000_100);
    assert_eq!(receipt.tree_size, 1);
}
