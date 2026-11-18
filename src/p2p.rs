//! P2P relay mesh state, peer registry, and Gossipsub `SignedTreeHead` synchronization.
//!
//! Detects split-view / equivocation attacks where a peer signs two different Merkle
//! roots for the exact same `tree_size` epoch.

use std::collections::HashMap;
use std::fmt;

/// Signed Merkle tree head gossiped across `sonaraim-node` peers.
///
/// Carries an Ed25519 signature over the canonical payload
/// `sonaraim:sth:v1|<node_id>|<tree_size>|<root_hash>`, produced with the
/// origin node's 32-byte signing seed. Receivers verify before recording.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedTreeHead {
    /// Originating peer node identifier.
    pub node_id: String,
    /// Total number of leaves in the Key Transparency log.
    pub tree_size: usize,
    /// Hexadecimal Merkle root hash at `tree_size`.
    pub root_hash: String,
    /// Hex-encoded Ed25519 public key of the signer (64 chars, 32 bytes).
    pub signer_pubkey_hex: String,
    /// Hex-encoded Ed25519 signature over the canonical payload (128 chars, 64 bytes).
    pub signature_hex: String,
}

impl SignedTreeHead {
    /// Returns the canonical byte payload covered by [`Self::signature_hex`].
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        format!(
            "sonaraim:sth:v1|{}|{}|{}",
            self.node_id, self.tree_size, self.root_hash
        )
        .into_bytes()
    }
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
    /// The STH signature failed verification or was malformed.
    InvalidSignature(String),
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
            Self::InvalidSignature(msg) => write!(f, "invalid STH signature: {msg}"),
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
    /// Optional per-peer Bearer token used for replication calls.
    pub auth_token: Option<String>,
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
                auth_token: None,
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
    ///
    /// The Ed25519 signature is verified first: heads with a missing, malformed,
    /// or non-matching signature are rejected with
    /// [`P2pError::InvalidSignature`] and never recorded.
    pub fn accept_tree_head(&mut self, sth: SignedTreeHead) -> Result<(), P2pError> {
        verify_tree_head_signature(&sth)?;
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

/// Decodes an even-length lowercase/uppercase hex string into bytes.
fn hex_decode(hex: &str) -> Option<Vec<u8>> {
    if !hex.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(hex.len() / 2);
    for i in (0..hex.len()).step_by(2) {
        let byte = u8::from_str_radix(&hex[i..i + 2], 16).ok()?;
        out.push(byte);
    }
    Some(out)
}

/// Signs the STH canonical payload with a 32-byte Ed25519 seed, returning
/// `(signer_pubkey_hex, signature_hex)`.
pub fn sign_tree_head(
    node_id: &str,
    tree_size: usize,
    root_hash: &str,
    signing_seed: &[u8; 32],
) -> (String, String) {
    use ed25519_dalek::Signer;
    let signing = ed25519_dalek::SigningKey::from_bytes(signing_seed);
    let payload = format!("sonaraim:sth:v1|{node_id}|{tree_size}|{root_hash}");
    let signature = signing.sign(payload.as_bytes());
    (
        hex_encode(&signing.verifying_key().to_bytes()),
        hex_encode(&signature.to_bytes()),
    )
}

/// Verifies a [`SignedTreeHead`]'s Ed25519 signature over its canonical payload.
pub fn verify_tree_head_signature(sth: &SignedTreeHead) -> Result<(), P2pError> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    if sth.signer_pubkey_hex.len() != 64 || sth.signature_hex.len() != 128 {
        return Err(P2pError::InvalidSignature(
            "missing or malformed signer key/signature".to_string(),
        ));
    }
    let pub_bytes = hex_decode(&sth.signer_pubkey_hex)
        .ok_or_else(|| P2pError::InvalidSignature("malformed signer key hex".to_string()))?;
    let sig_bytes = hex_decode(&sth.signature_hex)
        .ok_or_else(|| P2pError::InvalidSignature("malformed signature hex".to_string()))?;
    let verifying = VerifyingKey::from_bytes(
        pub_bytes
            .as_slice()
            .try_into()
            .map_err(|_| P2pError::InvalidSignature("signer key wrong length".to_string()))?,
    )
    .map_err(|_| P2pError::InvalidSignature("invalid signer public key".to_string()))?;
    let signature = Signature::from_bytes(
        sig_bytes
            .as_slice()
            .try_into()
            .map_err(|_| P2pError::InvalidSignature("signature wrong length".to_string()))?,
    );
    verifying
        .verify(sth.canonical_bytes().as_slice(), &signature)
        .map_err(|_| P2pError::InvalidSignature("signature mismatch".to_string()))
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}
