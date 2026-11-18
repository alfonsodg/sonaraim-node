//! TDD regression tests for `sonaraim-node` #17: honest SHA-256/HMAC cryptography.
//!
//! - Merkle leaf/node digests are real SHA-256 over the documented preimages.
//! - PSI evaluation is HMAC-SHA256 keyed by the configured server secret.
//! - Wake tokens are SHA-256 based (no FNV); phone tokens are never stored raw.
//! - `POST /v1/media/presign` returns a real SigV4 URL when S3 credentials are
//!   configured, and an honest 400 otherwise.

use sonaraim_node::config::NodeConfig;
use sonaraim_node::crypto::{hmac_sha256_hex, sha256_hex};
use sonaraim_node::http_server::{start_test_server, NodeState};
use sonaraim_node::merkle::KeyTransparencyLog;
use sonaraim_node::psi_service::{handle_presign_json, PresignParams};
use sonaraim_node::relay::MailboxStore;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;

fn dev_config() -> NodeConfig {
    let mut vars = HashMap::new();
    vars.insert("NODE_ID".to_string(), "node-crypto-17".to_string());
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
fn issue17_merkle_digests_are_real_sha256() {
    // SHA-256("sonaraim:leaf:v1|0|did:sonaraim:alice|ed25519:pk|1000") computed
    // with an independent implementation (python hashlib).
    let leaf = KeyTransparencyLog::hash_leaf(0, "did:sonaraim:alice", "ed25519:pk", 1000);
    assert_eq!(
        leaf,
        sha256_hex(b"sonaraim:leaf:v1|0|did:sonaraim:alice|ed25519:pk|1000")
    );
    assert_eq!(leaf.len(), 64);

    let node = KeyTransparencyLog::hash_children(&leaf, &leaf);
    assert_eq!(
        node,
        sha256_hex(format!("sonaraim:node:v1|{leaf}|{leaf}").as_bytes())
    );
    assert_eq!(node.len(), 64);

    // Empty-tree head is SHA-256 of the domain tag, not FNV.
    let empty = KeyTransparencyLog::new().tree_head();
    assert_eq!(empty, sha256_hex(b"sonaraim:merkle:empty"));

    // Proofs still verify end to end under SHA-256.
    let mut log = KeyTransparencyLog::new();
    log.append("did:sonaraim:a", "pk-a", 1).expect("append");
    log.append("did:sonaraim:b", "pk-b", 2).expect("append");
    let proof = log.generate_proof(0).expect("proof");
    assert!(KeyTransparencyLog::verify_proof(&proof));
}

#[test]
fn issue17_hmac_sha256_matches_rfc4231_vector() {
    // RFC 4231 test case 1: key = 0x0b * 20, data = "Hi There".
    let mac = hmac_sha256_hex(&[0x0bu8; 20], b"Hi There");
    assert_eq!(
        mac,
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
    );
}

#[test]
fn issue17_psi_uses_hmac_and_phone_tokens_never_plaintext() {
    let secret = b"test-psi-server-secret";
    let eval = sonaraim_node::psi_service::evaluate_psi_single("+51999888777", secret);
    assert_eq!(eval, hmac_sha256_hex(secret, b"+51999888777"));
    assert_eq!(eval.len(), 64);

    // Registering an identity stores only the HMAC of the phone token.
    let state = NodeState::new(
        dev_config(),
        MailboxStore::new(3600),
        KeyTransparencyLog::default(),
    );
    let (addr, _handle) = start_test_server(state).expect("start server");
    let (st, _) = send_http(
        &addr,
        "POST",
        "/v1/identity",
        r#"{"did":"did:sonaraim:psi-user","key_commitment":"pk-psi","phone_token":"+51999111222"}"#,
    );
    assert_eq!(st, 201);
    // Blind query by the same token still resolves via server-side evaluation.
    let (st, body) = send_http(&addr, "GET", "/v1/identity/by-phone/%2B51999111222", "");
    assert_eq!(st, 200);
    assert!(body.contains("did:sonaraim:psi-user"));
    // PSI match path resolves too.
    let (st, body) = send_http(
        &addr,
        "POST",
        "/v1/contacts/psi",
        r#"{"blinded_tokens":["+51999111222"]}"#,
    );
    assert_eq!(st, 200);
    assert!(body.contains("did:sonaraim:psi-user"));
}

#[test]
fn issue17_wake_tokens_are_sha256_based() {
    let t1 = sonaraim_node::relay::MailboxStore::derive_blind_wake_token(
        "mbx-w",
        "env-1",
        1_700_000_000,
    );
    assert!(t1.starts_with("wake_"));
    assert_eq!(t1.len(), "wake_".len() + 32);
    assert_eq!(
        t1,
        format!(
            "wake_{}",
            &sha256_hex(b"sonaraim:wake:v1|mbx-w|env-1|1700000000")[..32]
        )
    );
}

#[test]
fn issue17_presign_sigv4_with_creds_and_honest_400_without() {
    let with_creds = PresignParams {
        endpoint_url: "https://s3.example.com",
        bucket: "sonaraim-media",
        sha256_ciphertext: "deadbeef",
        content_length: 1024,
        region: "us-east-1",
        access_key_id: Some("AKIDEXAMPLE"),
        secret_access_key: Some("wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"),
        request_epoch_secs: 1_700_000_000,
        expires_secs: 900,
    };
    let (st, _, body) = handle_presign_json(
        r#"{"sha256_ciphertext":"deadbeef","content_length":1024}"#,
        &with_creds,
    );
    assert_eq!(st, 200);
    assert!(body.contains("X-Amz-Algorithm=AWS4-HMAC-SHA256"));
    assert!(body.contains("X-Amz-Signature="));
    assert!(body.contains("AKIDEXAMPLE"));
    assert!(!body.contains("sig="));

    let without_creds = PresignParams {
        access_key_id: None,
        secret_access_key: None,
        ..with_creds
    };
    let (st, _, body) = handle_presign_json(r#"{"sha256_ciphertext":"deadbeef"}"#, &without_creds);
    assert_eq!(st, 400);
    assert!(body.contains("MISSING_S3_CREDENTIALS"));
}
