//! Unit and integration tests for `sonaraim-node`.

use std::collections::HashMap;

use sonaraim_node::config::{ConfigError, NodeConfig};
use sonaraim_node::health::HealthStatus;
use sonaraim_node::merkle::{KeyTransparencyLog, MerkleError};
use sonaraim_node::relay::{MailboxStore, SealedEnvelope};

/// Helper that returns a valid baseline environment variable map.
fn sample_env_map() -> HashMap<String, String> {
    let mut map = HashMap::new();
    map.insert("NODE_ID".to_string(), "node-eu-west-01".to_string());
    map.insert("NODE_HTTP_HOST".to_string(), "127.0.0.1".to_string());
    map.insert("NODE_HTTP_PORT".to_string(), "8040".to_string());
    map.insert(
        "NODE_P2P_LISTEN_ADDR".to_string(),
        "/ip4/0.0.0.0/tcp/4001".to_string(),
    );
    map.insert(
        "NODE_ENVELOPE_TTL_SECONDS".to_string(),
        "604800".to_string(),
    );
    map
}

#[test]
fn test_node_config_valid_and_missing_vars() {
    let map = sample_env_map();
    let cfg = NodeConfig::from_map(&map).expect("valid config map should parse");
    assert_eq!(cfg.node_id, "node-eu-west-01");
    assert_eq!(cfg.http_bind_address(), "127.0.0.1:8040");
    assert_eq!(cfg.envelope_ttl_seconds, 604_800);

    let mut missing = map.clone();
    missing.remove("NODE_HTTP_PORT");
    assert_eq!(
        NodeConfig::from_map(&missing),
        Err(ConfigError::MissingVariable("NODE_HTTP_PORT".to_string()))
    );

    let mut bad_multiaddr = map;
    bad_multiaddr.insert(
        "NODE_P2P_LISTEN_ADDR".to_string(),
        "invalid-multiaddr".to_string(),
    );
    assert!(matches!(
        NodeConfig::from_map(&bad_multiaddr),
        Err(ConfigError::InvalidValue { .. })
    ));
}

#[test]
fn test_mailbox_store_and_forward_with_ttl_eviction() {
    let mut store = MailboxStore::new(300);
    assert_eq!(store.ttl_seconds(), 300);

    let env1 = SealedEnvelope {
        envelope_id: "env-001".to_string(),
        recipient_mailbox_id: "mbox-alice".to_string(),
        ciphertext: vec![0xde, 0xad, 0xbe, 0xef],
        created_at_epoch_secs: 1_000,
    };
    let env2 = SealedEnvelope {
        envelope_id: "env-002".to_string(),
        recipient_mailbox_id: "mbox-alice".to_string(),
        ciphertext: vec![0xca, 0xfe, 0xba, 0xbe],
        created_at_epoch_secs: 1_250,
    };

    let token1 = store.enqueue(env1);
    let token2 = store.enqueue(env2.clone());
    assert!(token1.starts_with("wake_"));
    assert_ne!(token1, token2);
    assert_eq!(store.total_queued(), 2);

    // At t = 1_350, env1 (age 350 >= 300) is expired, while env2 (age 100 < 300) is active
    let active = store.drain_active("mbox-alice", 1_350);
    assert_eq!(active, vec![env2]);
    assert_eq!(store.total_queued(), 0);
}

#[test]
fn test_mailbox_purge_expired_across_queues() {
    let mut store = MailboxStore::new(60);
    store.enqueue(SealedEnvelope {
        envelope_id: "env-old".to_string(),
        recipient_mailbox_id: "mbox-bob".to_string(),
        ciphertext: vec![1, 2, 3],
        created_at_epoch_secs: 100,
    });
    store.enqueue(SealedEnvelope {
        envelope_id: "env-fresh".to_string(),
        recipient_mailbox_id: "mbox-carol".to_string(),
        ciphertext: vec![4, 5, 6],
        created_at_epoch_secs: 150,
    });

    let purged = store.purge_expired(170);
    assert_eq!(purged, 1);
    assert_eq!(store.total_queued(), 1);
}

#[test]
fn test_key_transparency_log_and_inclusion_proofs() {
    let mut log = KeyTransparencyLog::new();
    assert!(log.is_empty());

    assert_eq!(
        log.append("did:invalid:123", "pk_commit_0", 1_700_000_000),
        Err(MerkleError::UnsupportedDidScheme(
            "did:invalid:123".to_string()
        ))
    );

    let (idx0, head0) = log
        .append("did:sonaraim:alice", "ed25519:pk_alice", 1_700_000_001)
        .expect("did:sonaraim should append");
    let (idx1, head1) = log
        .append("did:web:acme.corp:bob", "ed25519:pk_bob", 1_700_000_002)
        .expect("did:web should append");
    let (idx2, head2) = log
        .append("did:sonaraim:carol", "ed25519:pk_carol", 1_700_000_003)
        .expect("third entry should append");

    assert_eq!((idx0, idx1, idx2), (0, 1, 2));
    assert_ne!(head0, head1);
    assert_ne!(head1, head2);
    assert_eq!(log.len(), 3);

    for leaf_idx in 0..3 {
        let proof = log
            .generate_proof(leaf_idx)
            .expect("proof should be generated for valid index");
        assert_eq!(proof.tree_head, head2);
        assert!(KeyTransparencyLog::verify_proof(&proof));

        let mut tampered = proof.clone();
        tampered.leaf_hash = "00000000000000000000000000000000".to_string();
        assert!(!KeyTransparencyLog::verify_proof(&tampered));
    }
}

#[test]
fn test_health_status_serialization() {
    let cfg = NodeConfig::from_map(&sample_env_map()).expect("valid config");
    let mut store = MailboxStore::new(cfg.envelope_ttl_seconds);
    let mut kt_log = KeyTransparencyLog::new();

    store.enqueue(SealedEnvelope {
        envelope_id: "env-health-1".to_string(),
        recipient_mailbox_id: "mbox-1".to_string(),
        ciphertext: vec![0x01],
        created_at_epoch_secs: 500,
    });
    kt_log
        .append("did:sonaraim:node1", "commit_xyz", 500)
        .expect("append identity");

    let status = HealthStatus::from_state(&cfg, &store, &kt_log);
    let json = status.to_json();
    assert!(json.contains("\"status\":\"ok\""));
    assert!(json.contains("\"node_id\":\"node-eu-west-01\""));
    assert!(json.contains("\"http_bind\":\"127.0.0.1:8040\""));
    assert!(json.contains("\"queued_envelopes\":1"));
    assert!(json.contains("\"kt_log_entries\":1"));
}
