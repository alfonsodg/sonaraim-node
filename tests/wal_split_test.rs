//! TDD regression tests for `sonaraim-node` #16: per-domain WAL files.
//!
//! - Identity bindings append to `kt_log.wal`; relay envelopes append to
//!   `relay_mailboxes.wal` (one file, one schema).
//! - Ack compaction rewrites only the envelope WAL, never the identity WAL.
//! - Restart replays both WALs: identity log intact, queued envelopes restored.

use sonaraim_node::config::NodeConfig;
use sonaraim_node::http_server::{start_test_server, NodeState};
use sonaraim_node::merkle::KeyTransparencyLog;
use sonaraim_node::relay::MailboxStore;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;

fn dev_config() -> NodeConfig {
    let mut vars = HashMap::new();
    vars.insert("NODE_ID".to_string(), "node-wal-16".to_string());
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
fn issue20_identity_post_appends_binding_to_identity_wal() {
    use sonaraim_node::storage::{load_wal_entries, wal_path_from_signing_key};

    let dir = std::env::temp_dir().join(format!("sonaraim-idwal20-{}", std::process::id()));
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
        r#"{"did":"did:sonaraim:walguard","key_commitment":"ed25519_walguard_01"}"#,
    );
    assert_eq!(st, 201);

    let entries = load_wal_entries(&identity_wal).expect("load identity wal");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].did, "did:sonaraim:walguard");
    assert_eq!(entries[0].key_commitment, "ed25519_walguard_01");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn issue16_ack_compaction_restart_keeps_identities_and_envelopes() {
    use sonaraim_node::envelope_wal::envelope_wal_path_from_identity_wal;
    use sonaraim_node::storage::wal_path_from_signing_key;

    let dir = std::env::temp_dir().join(format!("sonaraim-wal16-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let signing_key = dir.join("node-signing.key");
    let identity_wal = wal_path_from_signing_key(&signing_key.to_string_lossy());
    let envelope_wal = envelope_wal_path_from_identity_wal(&identity_wal);

    // Boot the node with the identity WAL path configured.
    let state = NodeState::with_wal_and_redis(
        dev_config(),
        MailboxStore::new(3600),
        KeyTransparencyLog::default(),
        Some(identity_wal.clone()),
        None,
    );
    assert!(state.envelope_wal_path.is_some());
    let (addr, _handle) = start_test_server(state).expect("start server");

    // 1. Register an identity.
    let (st, _) = send_http(
        &addr,
        "POST",
        "/v1/identity",
        r#"{"did":"did:sonaraim:walice","key_commitment":"ed25519_walice_01"}"#,
    );
    assert_eq!(st, 201);

    // 2. Enqueue two envelopes, then ack exactly one of them.
    for env in ["env-keep-16", "env-acked-16"] {
        let body = format!(
            "{{\"envelope_id\":\"{env}\",\"recipient_mailbox_id\":\"did:sonaraim:walice\",\"payload_hex\":\"cafebabe\"}}"
        );
        let (st, _) = send_http(&addr, "POST", "/v1/relay/envelopes", &body);
        assert_eq!(st, 202);
    }
    let (st, body) = send_http(
        &addr,
        "POST",
        "/v1/relay/mailboxes/did:sonaraim:walice/ack",
        r#"{"envelope_ids":["env-acked-16"]}"#,
    );
    assert_eq!(st, 200);
    assert!(body.contains("\"acknowledged\":1"));

    // 3. WAL files must be separated by domain: identity WAL holds the DID
    // binding and no envelope records; envelope WAL holds the survivor only.
    let identity_raw = std::fs::read_to_string(&identity_wal).expect("read identity wal");
    assert!(identity_raw.contains("did:sonaraim:walice"));
    assert!(!identity_raw.contains("envelope-keep-16"));
    assert!(!identity_raw.contains("envelope-acked-16"));
    let envelope_raw = std::fs::read_to_string(&envelope_wal).expect("read envelope wal");
    assert!(envelope_raw.contains("env-keep-16"));
    assert!(!envelope_raw.contains("env-acked-16"));

    // 4. Restart: fresh in-memory state replays both WAL files from disk.
    drop(_handle);
    let restarted = NodeState::with_wal_and_redis(
        dev_config(),
        MailboxStore::new(3600),
        KeyTransparencyLog::default(),
        Some(identity_wal.clone()),
        None,
    );
    assert_eq!(restarted.kt_log.len(), 1);
    assert!(restarted.did_index.contains_key("did:sonaraim:walice"));
    let (r_addr, _r_handle) = start_test_server(restarted).expect("restart server");
    let (st, body) = send_http(
        &r_addr,
        "GET",
        "/v1/relay/mailboxes/did:sonaraim:walice",
        "",
    );
    assert_eq!(st, 200);
    assert!(body.contains("env-keep-16"));
    assert!(!body.contains("env-acked-16"));

    let _ = std::fs::remove_dir_all(&dir);
}
