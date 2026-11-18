//! UDP gossip daemon: binds `NODE_P2P_LISTEN_ADDR`, broadcasts signed STHs
//! periodically, joins `NODE_BOOTSTRAP_PEERS` on startup, and ingests inbound
//! datagrams into the shared mesh.
//!
//! The daemon owns a [`UdpGossipNode`] on a background thread. Every tick it
//! (a) drains inbound datagrams through [`P2pMeshNode::accept_tree_head`]
//! (signature verified, equivocations logged, forgeries dropped), and
//! (b) broadcasts the current signed tree head to all UDP peers plus an
//! on-change announcement whenever the head differs from the last broadcast.
//! `NODE_BOOTSTRAP_PEERS` entries receive an immediate hello head at startup.

use crate::http_server::NodeState;
use crate::p2p::{sign_tree_head, SignedTreeHead};
use crate::udp_gossip::UdpGossipNode;
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

/// Interval between periodic STH broadcasts (5 seconds).
pub const GOSSIP_BROADCAST_INTERVAL: Duration = Duration::from_secs(5);

/// Parses a comma-separated `NODE_BOOTSTRAP_PEERS` value into UDP `host:port`
/// targets, accepting `/ip4/<host>/udp/<port>/...` multiaddrs and bare
/// `host:port` strings. Unparseable entries are skipped with an error log.
#[must_use]
pub fn parse_udp_bootstrap_peers(raw: &str) -> Vec<String> {
    raw.split(',')
        .filter_map(|entry| parse_udp_peer_addr(entry.trim()))
        .collect()
}

/// Parses one bootstrap entry into a UDP `host:port` target.
fn parse_udp_peer_addr(entry: &str) -> Option<String> {
    if entry.is_empty() {
        return None;
    }
    if let Some(rest) = entry.strip_prefix("/ip4/") {
        let mut parts = rest.split('/');
        let host = parts.next().filter(|h| !h.is_empty())?;
        for part in parts.by_ref() {
            if part == "udp" {
                let port = parts.next().filter(|p| !p.is_empty())?;
                if port.parse::<u16>().is_err() {
                    log_error(&format!("ignoring bootstrap peer with bad port: {entry}"));
                    return None;
                }
                return Some(format!("{host}:{port}"));
            }
        }
        log_error(&format!(
            "ignoring bootstrap peer without udp part: {entry}"
        ));
        return None;
    }
    if entry.contains(':') && !entry.contains('/') {
        return Some(entry.to_string());
    }
    log_error(&format!("ignoring unparseable bootstrap peer: {entry}"));
    None
}

/// Resolves the UDP bind address from `NODE_P2P_LISTEN_ADDR`.
///
/// Accepts `/ip4/<host>/udp/<port>/...` multiaddrs (port `0` allowed for
/// ephemeral binds) and bare `host:port` strings.
pub fn udp_bind_addr_from_listen_addr(listen_addr: &str) -> Option<String> {
    parse_udp_peer_addr(listen_addr.trim())
}

/// Builds the currently-signed tree head for `state`.
fn current_signed_head(state: &NodeState) -> SignedTreeHead {
    let seed = state.config.sth_signing_seed();
    let (signer_pubkey_hex, signature_hex) = sign_tree_head(
        &state.config.node_id,
        state.kt_log.len(),
        &state.kt_log.tree_head(),
        &seed,
    );
    SignedTreeHead {
        node_id: state.config.node_id.clone(),
        tree_size: state.kt_log.len(),
        root_hash: state.kt_log.tree_head(),
        signer_pubkey_hex,
        signature_hex,
    }
}

fn log_error(msg: &str) {
    eprintln!("{{\"level\":\"ERROR\",\"msg\":\"{msg}\"}}");
}

/// Starts the gossip daemon thread bound to the node's `NODE_P2P_LISTEN_ADDR`.
///
/// `extra_udp_peers` are additional `host:port` targets seeded alongside
/// `NODE_BOOTSTRAP_PEERS` (used by tests that know concrete ephemeral ports).
///
/// Returns `(local_udp_addr, join_handle)`. The thread loops forever:
/// drain inbound datagrams into the mesh, broadcast the signed head every
/// [`GOSSIP_BROADCAST_INTERVAL`], announce immediately when the head changes,
/// and send a hello head to every `NODE_BOOTSTRAP_PEERS` target at startup.
/// Bind failure is returned as [`std::io::Error`]; per-datagram failures are
/// logged and never crash the loop.
pub fn spawn_gossip_daemon(
    shared: Arc<Mutex<NodeState>>,
) -> Result<(String, JoinHandle<()>), std::io::Error> {
    spawn_gossip_daemon_with_peers(shared, &[])
}

/// Starts the gossip daemon thread with additional explicit UDP peer targets.
///
/// See [`spawn_gossip_daemon`].
pub fn spawn_gossip_daemon_with_peers(
    shared: Arc<Mutex<NodeState>>,
    extra_udp_peers: &[String],
) -> Result<(String, JoinHandle<()>), std::io::Error> {
    let bind_addr = {
        let st = shared
            .lock()
            .map_err(|_| std::io::Error::other("gossip daemon: lock poisoned"))?;
        udp_bind_addr_from_listen_addr(&st.config.p2p_listen_addr).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "gossip daemon: unparseable NODE_P2P_LISTEN_ADDR",
            )
        })?
    };
    let node = UdpGossipNode::bind(&bind_addr)?;
    node.socket_set_broadcast()?;
    let local = node.local_addr()?.to_string();
    let mut bootstrap: Vec<String> = std::env::var("NODE_BOOTSTRAP_PEERS")
        .ok()
        .map(|raw| parse_udp_bootstrap_peers(&raw))
        .unwrap_or_default();
    for peer in extra_udp_peers {
        if !bootstrap.contains(peer) {
            bootstrap.push(peer.clone());
        }
    }
    let handle = thread::spawn(move || {
        run_gossip_loop(node, shared, bootstrap);
    });
    Ok((local, handle))
}

fn run_gossip_loop(node: UdpGossipNode, shared: Arc<Mutex<NodeState>>, bootstrap: Vec<String>) {
    let mut last_broadcast: Option<SignedTreeHead> = None;
    let mut last_tick_ms: u64 = 0;
    // Join: immediate hello head to every bootstrap peer at startup.
    if !bootstrap.is_empty() {
        if let Ok(st) = shared.lock() {
            let hello = current_signed_head(&st);
            for peer in &bootstrap {
                if let Err(e) = node.send_tree_head(peer, &hello) {
                    log_error(&format!("gossip bootstrap hello failed to {peer}: {e}"));
                }
            }
            last_broadcast = Some(hello);
            last_tick_ms = now_ms();
        }
    }
    loop {
        thread::sleep(Duration::from_millis(50));
        // Drain inbound datagrams.
        loop {
            match node.recv_tree_head_nonblocking() {
                Ok(Some(sth)) => {
                    if let Ok(mut st) = shared.lock() {
                        if let Err(e) = st.p2p_mesh.accept_tree_head(sth) {
                            log_error(&format!("gossip ingest rejected: {e}"));
                        }
                    }
                }
                Ok(None) => break,
                Err(e) => {
                    log_error(&format!("gossip recv failed: {e}"));
                    break;
                }
            }
        }
        // Broadcast: periodic tick or on-change announcement.
        let (head, changed) = match shared.lock() {
            Ok(st) => {
                let head = current_signed_head(&st);
                let changed = last_broadcast.as_ref() != Some(&head);
                (head, changed)
            }
            Err(_) => continue,
        };
        let now = now_ms();
        let tick_due =
            now.saturating_sub(last_tick_ms) >= GOSSIP_BROADCAST_INTERVAL.as_millis() as u64;
        if last_broadcast.is_none() || changed || tick_due {
            let targets = collect_udp_targets(&shared, &bootstrap);
            for peer in &targets {
                if let Err(e) = node.send_tree_head(peer, &head) {
                    log_error(&format!("gossip broadcast failed to {peer}: {e}"));
                }
            }
            last_broadcast = Some(head);
            last_tick_ms = now;
        }
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

/// Collects UDP targets: explicit bootstrap peers plus mesh peers whose
/// multiaddr parses as `/ip4/<host>/udp/<port>`.
///
/// Mesh records carry the peer's *listen* multiaddr, which may contain port
/// `0` (ephemeral test binds) or be otherwise undialable. Callers that know a
/// concrete dial address should pass it via `bootstrap` instead.
fn collect_udp_targets(shared: &Arc<Mutex<NodeState>>, bootstrap: &[String]) -> Vec<String> {
    let mut targets: Vec<String> = bootstrap.to_vec();
    if let Ok(st) = shared.lock() {
        for peer in st.p2p_mesh.peers() {
            if let Some(addr) = parse_udp_peer_addr(&peer.multiaddr) {
                if !targets.contains(&addr) {
                    targets.push(addr);
                }
            }
        }
    }
    targets
}
