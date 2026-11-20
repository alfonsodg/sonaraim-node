//! TDD tests for `sonaraim-node` #22: durable phone-token matching across restarts.
//!
//! Gap verified against `develop` (10dbad1):
//! - `NodeState::with_wal_and_redis` replays the identity WAL into
//!   `kt_log`/`did_index` but leaves `phone_index` empty, so
//!   `POST /v1/contacts/psi` misses phone tokens after restart.
//! - `http_federation::ingest_sync_payload` inserts identities into
//!   `kt_log`/`did_index`/`phone_index` without appending to `kt_log.wal`,
//!   so they are lost on restart (#16 one-file-one-schema preserved).
//!
//! Expected (privacy invariant preserved): the identity WAL persists the
//! phone HMAC digest (never the raw token), keyed by the secret id active at
//! registration; replay re-derives nothing and rebuilds `phone_index`
//! directly from the persisted digest.

use sonaraim_node::config::NodeConfig;
use sonaraim_node::http_server::{start_test_server, NodeState};
use sonaraim_node::merkle::KeyTransparencyLog;
use sonaraim_node::relay::MailboxStore;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;

fn dev_config() -> NodeConfig {
    let mut vars = HashMap::new();
    vars.insert("NODE_ID".to_string(), "node-wal-22".to_string());
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
fn issue22_phone_matching_survives_restart_and_wal_holds_no_raw_token() {
    use sonaraim_node::storage::wal_path_from_signing_key;

    let dir = std::env::temp_dir().join(format!("sonaraim-wal22-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let signing_key = dir.join("node-signing.key");
    let identity_wal = wal_path_from_signing_key(&signing_key.to_string_lossy());

    let state = NodeState::with_wal_and_redis(
        dev_config(),
        MailboxStore::new(3600),
        KeyTransparencyLog::default(),
        Some(identity_wal.clone()),
        None,
    );
    let (addr, _handle) = start_test_server(state).expect("start server");

    let (st, _) = send_http(
        &addr,
        "POST",
        "/v1/identity",
        r#"{"did":"did:sonaraim:psi-restart","key_commitment":"ed25519_psi_restart_01","phone_token":"+51999111222"}"#,
    );
    assert_eq!(st, 201);

    // The identity WAL must persist the digest solely, never the raw token.
    let raw = std::fs::read_to_string(&identity_wal).expect("read identity wal");
    assert!(raw.contains("did:sonaraim:psi-restart"));
    assert!(!raw.contains("+51999111222"));

    // Restart: replay must rebuild phone_index from the persisted digest.
    drop(_handle);
    let restarted = NodeState::with_wal_and_redis(
        dev_config(),
        MailboxStore::new(3600),
        KeyTransparencyLog::default(),
        Some(identity_wal.clone()),
        None,
    );
    assert!(restarted.did_index.contains_key("did:sonaraim:psi-restart"));
    let psi_secret = restarted.config.psi_secret_bytes();
    let expected = sonaraim_node::psi_service::evaluate_psi_single("+51999111222", &psi_secret);
    assert_eq!(
        restarted.phone_index.get(&expected).map(String::as_str),
        Some("did:sonaraim:psi-restart"),
        "phone_index must rebuild from the persisted digest on restart"
    );

    let (r_addr, _r_handle) = start_test_server(restarted).expect("restart server");
    let (st, body) = send_http(&r_addr, "GET", "/v1/identity/by-phone/%2B51999111222", "");
    assert_eq!(st, 200);
    assert!(body.contains("did:sonaraim:psi-restart"));

    let (st, psi_body) = send_http(
        &r_addr,
        "POST",
        "/v1/contacts/psi",
        r#"{"blinded_tokens":["+51999111222","+51000111222"]}"#,
    );
    assert_eq!(st, 200);
    assert!(psi_body.contains("did:sonaraim:psi-restart"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn issue22_federated_identity_inserts_persist_to_identity_wal() {
    use sonaraim_node::storage::wal_path_from_signing_key;

    let dir_a = std::env::temp_dir().join(format!("sonaraim-walfed22a-{}", std::process::id()));
    let dir_b = std::env::temp_dir().join(format!("sonaraim-walfed22b-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir_a);
    let _ = std::fs::create_dir_all(&dir_b);
    let wal_a = wal_path_from_signing_key(&dir_a.join("node-signing.key").to_string_lossy());
    let wal_b = wal_path_from_signing_key(&dir_b.join("node-signing.key").to_string_lossy());

    // Node A registers an identity with a phone token (persists to A's WAL).
    let node_a = NodeState::with_wal_and_redis(
        dev_config(),
        MailboxStore::new(3600),
        KeyTransparencyLog::default(),
        Some(wal_a.clone()),
        None,
    );
    let (addr_a, _h_a) = start_test_server(node_a).expect("start server a");
    let (st, _) = send_http(
        &addr_a,
        "POST",
        "/v1/identity",
        r#"{"did":"did:sonaraim:fed-phone","key_commitment":"ed25519_fed_phone_01","phone_token":"+51888777666"}"#,
    );
    assert_eq!(st, 201);

    // Node B (separate WAL) peers to A and must persist the synced identity
    // (and its digest, never the raw token) to its OWN identity WAL.
    let node_b = NodeState::with_wal_and_redis(
        dev_config(),
        MailboxStore::new(3600),
        KeyTransparencyLog::default(),
        Some(wal_b.clone()),
        None,
    );
    let (addr_b, _h_b) = start_test_server(node_b).expect("start server b");
    let peer_req = format!(
        "{{\"peer_id\":\"node-fed-a\",\"rpc_url\":\"http://{addr_a}\",\"multiaddr\":\"/ip4/127.0.0.1/tcp/0\"}}"
    );
    let (st, _) = send_http(&addr_b, "POST", "/v1/p2p/peers", &peer_req);
    assert_eq!(st, 201);

    let raw_b = std::fs::read_to_string(&wal_b).expect("read B identity wal");
    assert!(
        raw_b.contains("did:sonaraim:fed-phone"),
        "federated identities must append to the identity WAL (same schema), got: {raw_b}"
    );
    assert!(!raw_b.contains("+51888777666"));

    // Restart of B replays its own WAL: identity and phone matching survive.
    drop(_h_b);
    let restarted_b = NodeState::with_wal_and_redis(
        dev_config(),
        MailboxStore::new(3600),
        KeyTransparencyLog::default(),
        Some(wal_b.clone()),
        None,
    );
    assert!(restarted_b.did_index.contains_key("did:sonaraim:fed-phone"));
    let psi_secret = restarted_b.config.psi_secret_bytes();
    let expected = sonaraim_node::psi_service::evaluate_psi_single("+51888777666", &psi_secret);
    assert_eq!(
        restarted_b.phone_index.get(&expected).map(String::as_str),
        Some("did:sonaraim:fed-phone"),
        "federated phone binding must survive B restart"
    );

    let _ = std::fs::remove_dir_all(&dir_a);
    let _ = std::fs::remove_dir_all(&dir_b);
}
