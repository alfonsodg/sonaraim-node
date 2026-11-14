//! TDD integration tests for Milestone 6 & 7 (`sonaraim-node` #6, #7):
//! - #6: File-backed WAL append and recovery (`append_wal_entry`, `load_wal_entries`, `wal_path_from_signing_key`)
//! - #6: Zero-dependency TCP RESP client (`RedisRespClient`) against a mock Redis TCP server (`AUTH`, `SET EX`, `GET`, `DEL`)
//! - #6: Prometheus `GET /metrics` endpoint returning `text/plain; version=0.0.4` counters
//! - #7: Live UDP gossip (`UdpGossipNode`) exchanging `SignedTreeHead` packets and detecting equivocation
//! - #7: `verify_did_web_document` and `POST /v1/p2p/gossip` endpoint (`409 Conflict` on equivocation)

use sonaraim_node::config::NodeConfig;
use sonaraim_node::http_server::{start_test_server, NodeState};
use sonaraim_node::merkle::KeyTransparencyLog;
use sonaraim_node::p2p::{P2pMeshNode, SignedTreeHead};
use sonaraim_node::redis_store::RedisRespClient;
use sonaraim_node::relay::MailboxStore;
use sonaraim_node::storage::{
    append_wal_entry, load_wal_entries, wal_path_from_signing_key, WalEntry,
};
use sonaraim_node::udp_gossip::{verify_did_web_document, UdpGossipNode};
use std::collections::HashMap;
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn temp_wal_file(tag: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let dir = std::env::temp_dir().join(format!("sonaraim_wal_{tag}_{nanos}"));
    fs::create_dir_all(&dir).expect("create temp wal dir");
    let signing_key = dir.join("node.key");
    wal_path_from_signing_key(&signing_key.to_string_lossy())
}

fn sample_config() -> NodeConfig {
    let mut vars = HashMap::new();
    vars.insert("NODE_ID".to_string(), "node-m6-01".to_string());
    vars.insert("NODE_HTTP_HOST".to_string(), "127.0.0.1".to_string());
    vars.insert("NODE_HTTP_PORT".to_string(), "8040".to_string());
    vars.insert(
        "NODE_P2P_LISTEN_ADDR".to_string(),
        "/ip4/127.0.0.1/udp/0/quic-v1".to_string(),
    );
    vars.insert("NODE_ENVELOPE_TTL_SECONDS".to_string(), "3600".to_string());
    vars.insert("NODE_ALLOW_DEV_NOAUTH".to_string(), "true".to_string());
    NodeConfig::from_map(&vars).expect("valid config")
}

fn send_http(addr: &str, method: &str, path: &str, body: &str) -> (u16, String, String) {
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
    (status, head.to_string(), resp_body.to_string())
}

#[test]
fn wal_append_and_recovery_restores_kt_log_across_node_state_reinit() {
    let wal_path = temp_wal_file("recovery");
    let entry_1 = WalEntry {
        did: "did:sonaraim:alice".to_string(),
        key_commitment: "ed25519_alice_01".to_string(),
        epoch_secs: 1_700_000_010,
    };
    let entry_2 = WalEntry {
        did: "did:web:enterprise.example.com".to_string(),
        key_commitment: "ed25519_ent_02".to_string(),
        epoch_secs: 1_700_000_020,
    };

    append_wal_entry(&wal_path, &entry_1).expect("append wal 1");
    append_wal_entry(&wal_path, &entry_2).expect("append wal 2");

    let loaded = load_wal_entries(&wal_path).expect("load wal entries");
    assert_eq!(loaded, vec![entry_1, entry_2]);

    let state = NodeState::with_wal_and_redis(
        sample_config(),
        MailboxStore::new(3600),
        KeyTransparencyLog::default(),
        Some(wal_path.clone()),
        None,
    );
    assert_eq!(state.kt_log.len(), 2);
    assert!(state.did_index.contains_key("did:sonaraim:alice"));
    assert!(state
        .did_index
        .contains_key("did:web:enterprise.example.com"));

    let _ = fs::remove_file(&wal_path);
}

#[test]
fn redis_resp_client_executes_auth_set_ex_get_and_del() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock redis");
    let addr = listener.local_addr().expect("local addr");

    let server = thread::spawn(move || {
        for step in 0..3 {
            let (mut conn, _) = listener.accept().expect("accept redis client");
            let mut buf = [0u8; 1024];
            let n = conn.read(&mut buf).expect("read auth");
            let req1 = String::from_utf8_lossy(&buf[..n]);
            assert!(req1.contains("AUTH"));
            conn.write_all(b"+OK\r\n").expect("write auth ok");

            let n2 = conn.read(&mut buf).expect("read cmd");
            let req2 = String::from_utf8_lossy(&buf[..n2]);
            match step {
                0 => {
                    assert!(req2.contains("SET"));
                    assert!(req2.contains("EX"));
                    conn.write_all(b"+OK\r\n").expect("write set ok");
                }
                1 => {
                    assert!(req2.contains("GET"));
                    conn.write_all(b"$7\r\nenv-777\r\n").expect("write bulk");
                }
                _ => {
                    assert!(req2.contains("DEL"));
                    conn.write_all(b":1\r\n").expect("write del int");
                }
            }
        }
    });

    let url = format!("redis://:secretpass@{addr}/0");
    let client = RedisRespClient::from_url(&url).expect("parse redis url");
    client
        .set_ex("sonaraim:mbx:1", "env-777", 300)
        .expect("set_ex");
    let got = client.get("sonaraim:mbx:1").expect("get");
    assert_eq!(got.as_deref(), Some("env-777"));
    let deleted = client.del("sonaraim:mbx:1").expect("del");
    assert_eq!(deleted, 1);

    server.join().expect("mock redis server join");
}

#[test]
fn http_metrics_endpoint_returns_prometheus_counters_and_persists_wal() {
    let wal_path = temp_wal_file("http_metrics");
    let state = NodeState::with_wal_and_redis(
        sample_config(),
        MailboxStore::new(3600),
        KeyTransparencyLog::default(),
        Some(wal_path.clone()),
        None,
    );
    let (addr, _handle) = start_test_server(state).expect("start server");

    let (st, _, _) = send_http(
        &addr,
        "POST",
        "/v1/identity",
        r#"{"did":"did:sonaraim:bob","key_commitment":"ed25519_bob_pk"}"#,
    );
    assert_eq!(st, 201);

    let (st, _, _) = send_http(
        &addr,
        "POST",
        "/v1/relay/envelopes",
        r#"{"envelope_id":"env-99","recipient_mailbox_id":"mbx-bob","payload_hex":"cafebabe"}"#,
    );
    assert_eq!(st, 202);

    let (st, headers, metrics_body) = send_http(&addr, "GET", "/metrics", "");
    assert_eq!(st, 200);
    assert!(headers.contains("text/plain; version=0.0.4"));
    assert!(metrics_body.contains("sonaraim_node_kt_entries_total 1"));
    assert!(metrics_body.contains("sonaraim_node_queued_envelopes 1"));

    let recovered = NodeState::with_wal_and_redis(
        sample_config(),
        MailboxStore::new(3600),
        KeyTransparencyLog::default(),
        Some(wal_path.clone()),
        None,
    );
    assert_eq!(recovered.kt_log.len(), 1);
    assert!(recovered.did_index.contains_key("did:sonaraim:bob"));

    let _ = fs::remove_file(&wal_path);
}

#[test]
fn udp_gossip_nodes_exchange_signed_tree_heads_and_detect_equivocation() {
    let node_a = UdpGossipNode::bind("127.0.0.1:0").expect("bind udp a");
    let node_b = UdpGossipNode::bind("127.0.0.1:0").expect("bind udp b");
    let addr_b = node_b.local_addr().expect("addr b").to_string();

    let sth_valid = SignedTreeHead {
        node_id: "node-a".to_string(),
        tree_size: 42,
        root_hash: "aabbccdd11223344".to_string(),
    };
    node_a
        .send_tree_head(&addr_b, &sth_valid)
        .expect("send valid sth");

    let mut received = None;
    for _ in 0..20 {
        if let Ok(Some(pkt)) = node_b.recv_tree_head_nonblocking() {
            received = Some(pkt);
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    let received_sth = received.expect("node_b should receive UDP SignedTreeHead");
    assert_eq!(received_sth, sth_valid);

    let mut mesh_b = P2pMeshNode::new("node-b");
    assert!(mesh_b.accept_tree_head(received_sth).is_ok());

    let sth_conflict = SignedTreeHead {
        node_id: "node-a".to_string(),
        tree_size: 42,
        root_hash: "ff00ff00ff00ff00".to_string(),
    };
    node_a
        .send_tree_head(&addr_b, &sth_conflict)
        .expect("send conflicting sth");

    let mut received_conflict = None;
    for _ in 0..20 {
        if let Ok(Some(pkt)) = node_b.recv_tree_head_nonblocking() {
            received_conflict = Some(pkt);
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    assert!(mesh_b
        .accept_tree_head(received_conflict.expect("receive conflict"))
        .is_err());
}

#[test]
fn verify_did_web_and_http_p2p_gossip_endpoint_enforces_conflict_check() {
    assert!(verify_did_web_document(
        "did:web:clinic.example.com",
        r#"{"id":"did:web:clinic.example.com","verificationMethod":[{"id":"did:web:clinic.example.com#key-1"}]}"#
    ));
    assert!(!verify_did_web_document(
        "did:web:clinic.example.com",
        r#"{"id":"did:web:wrong.example.com","verificationMethod":[]}"#
    ));

    let state = NodeState::new(
        sample_config(),
        MailboxStore::new(3600),
        KeyTransparencyLog::default(),
    );
    let (addr, _handle) = start_test_server(state).expect("start server");

    // Invalid did_document on POST /v1/identity returns 400
    let (st_bad_doc, _, _) = send_http(
        &addr,
        "POST",
        "/v1/identity",
        r#"{"did":"did:web:acme.example.com","key_commitment":"pk1","did_document_json":"{\"id\":\"did:web:other\"}"}"#,
    );
    assert_eq!(st_bad_doc, 400);

    // First SignedTreeHead for tree_size 5 -> 200 OK
    let (st1, _, body1) = send_http(
        &addr,
        "POST",
        "/v1/p2p/gossip",
        r#"{"node_id":"peer-01","tree_size":5,"root_hash":"1111aaaa"}"#,
    );
    assert_eq!(st1, 200);
    assert!(body1.contains("\"accepted\":true"));

    // Conflicting SignedTreeHead for tree_size 5 -> 409 Conflict
    let (st2, _, body2) = send_http(
        &addr,
        "POST",
        "/v1/p2p/gossip",
        r#"{"node_id":"peer-01","tree_size":5,"root_hash":"2222bbbb"}"#,
    );
    assert_eq!(st2, 409);
    assert!(body2.contains("EQUIVOCATION_DETECTED"));
}
