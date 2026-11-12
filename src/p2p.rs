//! P2P relay mesh state, peer registry, and Gossipsub `SignedTreeHead` synchronization.
//!
//! Detects split-view / equivocation attacks where a peer signs two different Merkle
//! roots for the exact same `tree_size` epoch.

use std::collections::HashMap;
use std::fmt;

/// Signed Merkle tree head gossiped across `sonaraim-node` peers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedTreeHead {
    /// Originating peer node identifier.
    pub node_id: String,
    /// Total number of leaves in the Key Transparency log.
    pub tree_size: usize,
    /// Hexadecimal Merkle root hash at `tree_size`.
    pub root_hash: String,
}

/// Errors returned during P2P mesh synchronization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum P2pError {
    /// Two conflicting Merkle root hashes were observed for the same `tree_size`.
    EquivocationDetected {
        /// Tree size at which equivocation occurred.
        tree_size: usize,
        /// Previously accepted root hash.
        existing_root: String,
        /// Conflicting newly received root hash.
        conflicting_root: String,
    },
}

impl fmt::Display for P2pError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EquivocationDetected {
                tree_size,
                existing_root,
                conflicting_root,
            } => write!(
                f,
                "Merkle equivocation at size {tree_size}: {existing_root} != {conflicting_root}"
            ),
        }
    }
}

impl std::error::Error for P2pError {}

/// Detailed record of a registered peer node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerRecord {
    /// Remote node identifier.
    pub peer_id: String,
    /// HTTP RPC URL for inter-node federation calls.
    pub rpc_url: String,
    /// QUIC or TCP multiaddress.
    pub multiaddr: String,
}

/// Decentralized P2P mesh routing and gossip state for a `sonaraim-node`.
#[derive(Debug, Clone)]
pub struct P2pMeshNode {
    /// Local node identifier.
    pub node_id: String,
    peers: HashMap<String, String>,
    peer_records: HashMap<String, PeerRecord>,
    observed_heads: HashMap<usize, String>,
}

impl P2pMeshNode {
    /// Creates a new [`P2pMeshNode`] instance.
    #[must_use]
    pub fn new(node_id: &str) -> Self {
        Self {
            node_id: node_id.to_string(),
            peers: HashMap::new(),
            peer_records: HashMap::new(),
            observed_heads: HashMap::new(),
        }
    }

    /// Registers or updates a peer's QUIC multiaddr.
    pub fn add_peer(&mut self, peer_id: &str, multiaddr: &str) {
        self.peers
            .insert(peer_id.to_string(), multiaddr.to_string());
        self.peer_records.insert(
            peer_id.to_string(),
            PeerRecord {
                peer_id: peer_id.to_string(),
                rpc_url: String::new(),
                multiaddr: multiaddr.to_string(),
            },
        );
    }

    /// Registers a peer with full [`PeerRecord`].
    pub fn add_peer_record(&mut self, record: PeerRecord) {
        self.peers
            .insert(record.peer_id.clone(), record.multiaddr.clone());
        self.peer_records.insert(record.peer_id.clone(), record);
    }

    /// Returns all registered peer records.
    #[must_use]
    pub fn peers(&self) -> Vec<PeerRecord> {
        self.peer_records.values().cloned().collect()
    }

    /// Returns the number of connected peers.
    #[must_use]
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    /// Validates and records a gossiped [`SignedTreeHead`], rejecting equivocation.
    pub fn accept_tree_head(&mut self, sth: SignedTreeHead) -> Result<(), P2pError> {
        if let Some(existing) = self.observed_heads.get(&sth.tree_size) {
            if existing != &sth.root_hash {
                return Err(P2pError::EquivocationDetected {
                    tree_size: sth.tree_size,
                    existing_root: existing.clone(),
                    conflicting_root: sth.root_hash,
                });
            }
        } else {
            self.observed_heads.insert(sth.tree_size, sth.root_hash);
        }
        Ok(())
    }
}
