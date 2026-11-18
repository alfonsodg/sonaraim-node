//! TDD tests for issue #19: gossip daemon thread + E2E UDP head exchange.
//!
//! - Daemon binds `NODE_P2P_LISTEN_ADDR`, joins `NODE_BOOTSTRAP_PEERS` at
//!   startup, ingests inbound signed heads into the shared mesh.
//! - E2E: two live daemon-backed nodes exchange tree heads over UDP with no
//!   HTTP involvement (node A appends to its KT log -> signed broadcast ->
//!   node B's mesh observes it; forgery is dropped).

use sonaraim_node::config::NodeConfig;
use sonaraim_node::gossip_daemon::{
    parse_udp_bootstrap_peers, spawn_gossip_daemon, spawn_gossip_daemon_with_peers,
    udp_bind_addr_from_listen_addr,
};
use sonaraim_node::http_server::NodeState;
use sonaraim_node::merkle::KeyTransparencyLog;
use sonaraim_node::relay::MailboxStore;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

fn config_with_addrs(node_id: &str, p2p: &str) -> NodeConfig {
    let mut vars = HashMap::new();
    vars.insert("NODE_ID".to_string(), node_id.to_string());
    vars.insert("NODE_HTTP_HOST".to_string(), "127.0.0.1".to_string());
    vars.insert("NODE_HTTP_PORT".to_string(), "8040".to_string());
    vars.insert("NODE_P2P_LISTEN_ADDR".to_string(), p2p.to_string());
    vars.insert("NODE_ENVELOPE_TTL_SECONDS".to_string(), "3600".to_string());
    vars.insert("NODE_ALLOW_DEV_NOAUTH".to_string(), "true".to_string());
    vars.insert(
        "NODE_STH_SIGNING_SEED".to_string(),
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
    );
    NodeConfig::from_map(&vars).expect("valid config")
}

fn shared_state_on_port(node_id: &str, udp_port: u16) -> Arc<Mutex<NodeState>> {
    let cfg = config_with_addrs(node_id, &format!("/ip4/127.0.0.1/udp/{udp_port}/quic-v1"));
    Arc::new(Mutex::new(NodeState::new(
        cfg,
        MailboxStore::new(3600),
        KeyTransparencyLog::default(),
    )))
}

fn free_udp_port() -> u16 {
    let sock = std::net::UdpSocket::bind("127.0.0.1:0").expect("ephemeral udp");
    sock.local_addr().expect("addr").port()
}

#[test]
fn udp_bootstrap_and_bind_addr_parsing() {
    assert_eq!(
        udp_bind_addr_from_listen_addr("/ip4/0.0.0.0/udp/9031/quic-v1"),
        Some("0.0.0.0:9031".to_string())
    );
    assert_eq!(
        udp_bind_addr_from_listen_addr("/ip4/127.0.0.1/udp/0/quic-v1"),
        Some("127.0.0.1:0".to_string())
    );
    assert_eq!(
        udp_bind_addr_from_listen_addr("127.0.0.1:9999"),
        Some("127.0.0.1:9999".to_string())
    );
    assert_eq!(udp_bind_addr_from_listen_addr("not-a-multiaddr"), None);
    assert_eq!(udp_bind_addr_from_listen_addr("/ip4/1.2.3.4/tcp/80"), None);

    assert_eq!(
        parse_udp_bootstrap_peers("/ip4/10.0.0.2/udp/9031/quic-v1,/ip4/10.0.0.3/udp/9032/quic-v1"),
        vec!["10.0.0.2:9031".to_string(), "10.0.0.3:9032".to_string()]
    );
    assert_eq!(
        parse_udp_bootstrap_peers("127.0.0.1:9001, garbage!!, /ip4/1.2.3.4/tcp/80"),
        vec!["127.0.0.1:9001".to_string()]
    );
    assert!(parse_udp_bootstrap_peers("").is_empty());
}

#[test]
fn gossip_daemon_e2e_two_nodes_exchange_heads_over_udp() {
    let port_a = free_udp_port();
    let port_b = free_udp_port();
    std::env::remove_var("NODE_BOOTSTRAP_PEERS");

    let shared_a = shared_state_on_port("node-gossip-a", port_a);
    let shared_b = shared_state_on_port("node-gossip-b", port_b);
    let addr_a = format!("127.0.0.1:{port_a}");
    let addr_b = format!("127.0.0.1:{port_b}");

    // Each daemon knows the other's concrete UDP dial address (as
    // NODE_BOOTSTRAP_PEERS would provide in production); no HTTP involved.
    let (_local_a, _h_a) =
        spawn_gossip_daemon_with_peers(Arc::clone(&shared_a), std::slice::from_ref(&addr_b))
            .expect("daemon a binds");
    let (_local_b, _h_b) =
        spawn_gossip_daemon_with_peers(Arc::clone(&shared_b), std::slice::from_ref(&addr_a))
            .expect("daemon b binds");

    // Node A appends an identity -> its tree head changes -> daemon announces.
    {
        let mut st = shared_a.lock().expect("lock a");
        st.kt_log
            .append("did:sonaraim:e2e-alice", "pk-e2e", 1_700_000_001)
            .expect("append");
    }

    // B's mesh must observe A's signed head over UDP. Detect via probe: once
    // B holds a size-1 head from A, a conflicting size-1 probe equivocate-fails.
    let mut observed = false;
    let mut probe_root = 0u32;
    for _ in 0..200 {
        thread::sleep(Duration::from_millis(50));
        probe_root = probe_root.wrapping_add(1);
        let probe = {
            let (pub_hex, sig_hex) = sonaraim_node::p2p::sign_tree_head(
                "node-gossip-a",
                1,
                &format!("probe-conflict-{probe_root}"),
                &[0x55u8; 32],
            );
            sonaraim_node::p2p::SignedTreeHead {
                node_id: "node-gossip-a".to_string(),
                tree_size: 1,
                root_hash: format!("probe-conflict-{probe_root}"),
                signer_pubkey_hex: pub_hex,
                signature_hex: sig_hex,
            }
        };
        let mut st = shared_b.lock().expect("lock b");
        if let Err(sonaraim_node::p2p::P2pError::EquivocationDetected { .. }) =
            st.p2p_mesh.accept_tree_head(probe)
        {
            observed = true;
            break;
        }
    }
    assert!(observed, "node B never observed node A's UDP head");
}

#[test]
fn gossip_daemon_drops_forged_inbound_datagram() {
    let port_a = free_udp_port();
    let port_b = free_udp_port();
    let shared_a = shared_state_on_port("node-forge-a", port_a);
    let shared_b = shared_state_on_port("node-forge-b", port_b);
    let (_l_a, _h_a) = spawn_gossip_daemon(Arc::clone(&shared_a)).expect("daemon a");
    {
        let mut st = shared_b.lock().expect("lock b");
        st.p2p_mesh.add_peer(
            "node-forge-a",
            &format!("/ip4/127.0.0.1/udp/{port_a}/quic-v1"),
        );
    }
    let (_l_b, _h_b) = spawn_gossip_daemon(Arc::clone(&shared_b)).expect("daemon b");

    // Send a forged unsigned datagram straight at B from a raw socket.
    let raw = std::net::UdpSocket::bind("127.0.0.1:0").expect("raw socket");
    raw.send_to(
        br#"{"node_id":"node-forge-a","tree_size":77,"root_hash":"forged"}"#,
        format!("127.0.0.1:{port_b}"),
    )
    .expect("send forged");
    thread::sleep(Duration::from_millis(500));

    // Size 77 must NOT be recorded: a conflicting signed head is accepted Ok
    // (no equivocation possible against a dropped forgery).
    let good = {
        let (pub_hex, sig_hex) =
            sonaraim_node::p2p::sign_tree_head("node-forge-a", 77, "legit-root", &[0x77u8; 32]);
        sonaraim_node::p2p::SignedTreeHead {
            node_id: "node-forge-a".to_string(),
            tree_size: 77,
            root_hash: "legit-root".to_string(),
            signer_pubkey_hex: pub_hex,
            signature_hex: sig_hex,
        }
    };
    let mut st = shared_b.lock().expect("lock b");
    assert!(st.p2p_mesh.accept_tree_head(good).is_ok());
}
