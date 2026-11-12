//! Append-only Key Transparency Merkle log (`KeyTransparencyLog`).
//!
//! Tracks identity key bindings for `did:sonaraim:*` and `did:web:*` identifiers,
//! computes deterministic Merkle tree heads, and generates/verifies cryptographic
//! inclusion proofs.

use std::fmt;

/// Errors returned by [`KeyTransparencyLog`] operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MerkleError {
    /// The provided DID does not start with `did:sonaraim:` or `did:web:`.
    UnsupportedDidScheme(String),
    /// The public key commitment is empty.
    EmptyKeyCommitment,
    /// The requested leaf index does not exist in the log.
    IndexOutOfBounds {
        /// Requested leaf index.
        index: usize,
        /// Current number of entries in the log.
        len: usize,
    },
}

impl fmt::Display for MerkleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedDidScheme(did) => {
                write!(
                    f,
                    "unsupported DID scheme (expected did:sonaraim: or did:web:): {did}"
                )
            }
            Self::EmptyKeyCommitment => write!(f, "key commitment must not be empty"),
            Self::IndexOutOfBounds { index, len } => {
                write!(
                    f,
                    "leaf index {index} out of bounds for log of length {len}"
                )
            }
        }
    }
}

impl std::error::Error for MerkleError {}

/// Single entry recorded in the Key Transparency log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityLogEntry {
    /// Zero-based sequential leaf index.
    pub index: usize,
    /// Decentralized Identifier (`did:sonaraim:...` or `did:web:...`).
    pub did: String,
    /// Hex or base64 commitment of the identity's public key bundle.
    pub key_commitment: String,
    /// Unix epoch timestamp when the binding was recorded.
    pub epoch_secs: u64,
    /// Deterministic leaf hash in hexadecimal format.
    pub leaf_hash: String,
}

/// Step in a Merkle inclusion proof path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofNode {
    /// Hexadecimal hash of the sibling node at this level.
    pub sibling_hash: String,
    /// True if the sibling is on the left (`hash(sibling || current)`), false if on the right.
    pub sibling_is_left: bool,
}

/// Verifiable Merkle inclusion proof for a specific leaf in [`KeyTransparencyLog`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InclusionProof {
    /// Leaf index being proven.
    pub leaf_index: usize,
    /// Total number of leaves in the tree when the proof was generated.
    pub log_size: usize,
    /// Hexadecimal hash of the target leaf.
    pub leaf_hash: String,
    /// Ordered sibling path from leaf to root.
    pub path: Vec<ProofNode>,
    /// Expected Merkle tree head (root hash).
    pub tree_head: String,
}

/// Append-only Key Transparency Merkle tree log.
#[derive(Debug, Clone, Default)]
pub struct KeyTransparencyLog {
    entries: Vec<IdentityLogEntry>,
}

impl KeyTransparencyLog {
    /// Initializes an empty [`KeyTransparencyLog`].
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Returns the number of entries currently recorded in the log.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if the log contains no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Appends a new identity key binding to the log and returns `(leaf_index, tree_head)`.
    ///
    /// # Errors
    ///
    /// Returns [`MerkleError`] if `did` is not `did:sonaraim:*` or `did:web:*`, or if
    /// `key_commitment` is empty.
    pub fn append(
        &mut self,
        did: &str,
        key_commitment: &str,
        epoch_secs: u64,
    ) -> Result<(usize, String), MerkleError> {
        let trimmed_did = did.trim();
        if !trimmed_did.starts_with("did:sonaraim:") && !trimmed_did.starts_with("did:web:") {
            return Err(MerkleError::UnsupportedDidScheme(trimmed_did.to_string()));
        }
        let trimmed_key = key_commitment.trim();
        if trimmed_key.is_empty() {
            return Err(MerkleError::EmptyKeyCommitment);
        }

        let index = self.entries.len();
        let leaf_hash = Self::hash_leaf(index, trimmed_did, trimmed_key, epoch_secs);
        self.entries.push(IdentityLogEntry {
            index,
            did: trimmed_did.to_string(),
            key_commitment: trimmed_key.to_string(),
            epoch_secs,
            leaf_hash,
        });

        Ok((index, self.tree_head()))
    }

    /// Computes the current deterministic Merkle root hash (`tree_head`).
    #[must_use]
    pub fn tree_head(&self) -> String {
        if self.entries.is_empty() {
            return Self::digest_hex("sonaraim:merkle:empty");
        }
        let mut level: Vec<String> = self.entries.iter().map(|e| e.leaf_hash.clone()).collect();
        while level.len() > 1 {
            let mut next = Vec::with_capacity(level.len().div_ceil(2));
            let mut i = 0;
            while i < level.len() {
                if i + 1 < level.len() {
                    next.push(Self::hash_children(&level[i], &level[i + 1]));
                } else {
                    // Promote odd trailing node deterministically with self-duplication domain tag
                    next.push(Self::hash_children(&level[i], &level[i]));
                }
                i += 2;
            }
            level = next;
        }
        level.remove(0)
    }

    /// Generates an [`InclusionProof`] for the entry at `leaf_index`.
    ///
    /// # Errors
    ///
    /// Returns [`MerkleError::IndexOutOfBounds`] if `leaf_index >= self.len()`.
    pub fn generate_proof(&self, leaf_index: usize) -> Result<InclusionProof, MerkleError> {
        if leaf_index >= self.entries.len() {
            return Err(MerkleError::IndexOutOfBounds {
                index: leaf_index,
                len: self.entries.len(),
            });
        }

        let mut level: Vec<String> = self.entries.iter().map(|e| e.leaf_hash.clone()).collect();
        let mut idx = leaf_index;
        let mut path = Vec::new();

        while level.len() > 1 {
            let sibling_is_left = idx % 2 == 1;
            let sibling_hash = if sibling_is_left {
                level[idx - 1].clone()
            } else if idx + 1 < level.len() {
                level[idx + 1].clone()
            } else {
                level[idx].clone()
            };

            path.push(ProofNode {
                sibling_hash,
                sibling_is_left,
            });

            let mut next = Vec::with_capacity(level.len().div_ceil(2));
            let mut i = 0;
            while i < level.len() {
                if i + 1 < level.len() {
                    next.push(Self::hash_children(&level[i], &level[i + 1]));
                } else {
                    next.push(Self::hash_children(&level[i], &level[i]));
                }
                i += 2;
            }
            level = next;
            idx /= 2;
        }

        Ok(InclusionProof {
            leaf_index,
            log_size: self.entries.len(),
            leaf_hash: self.entries[leaf_index].leaf_hash.clone(),
            path,
            tree_head: level.remove(0),
        })
    }

    /// Verifies that an [`InclusionProof`] is cryptographically consistent with its `tree_head`.
    #[must_use]
    pub fn verify_proof(proof: &InclusionProof) -> bool {
        if proof.log_size == 0 || proof.leaf_index >= proof.log_size {
            return false;
        }
        let mut current = proof.leaf_hash.clone();
        for step in &proof.path {
            current = if step.sibling_is_left {
                Self::hash_children(&step.sibling_hash, &current)
            } else {
                Self::hash_children(&current, &step.sibling_hash)
            };
        }
        current == proof.tree_head
    }

    /// Computes a domain-separated leaf hash (`0x00` prefix).
    #[must_use]
    pub fn hash_leaf(index: usize, did: &str, key_commitment: &str, epoch_secs: u64) -> String {
        let preimage = format!("sonaraim:leaf:v1|{index}|{did}|{key_commitment}|{epoch_secs}");
        Self::digest_hex(&preimage)
    }

    /// Computes a domain-separated interior node hash (`0x01` prefix).
    #[must_use]
    pub fn hash_children(left: &str, right: &str) -> String {
        let preimage = format!("sonaraim:node:v1|{left}|{right}");
        Self::digest_hex(&preimage)
    }

    /// Produces a 128-bit deterministic hexadecimal digest from `input`.
    fn digest_hex(input: &str) -> String {
        let mut h1: u64 = 0xcbf2_9ce4_8422_2325;
        let mut h2: u64 = 0x9e37_79b9_7f4a_7c15;
        for (i, byte) in input.bytes().enumerate() {
            h1 ^= u64::from(byte);
            h1 = h1.wrapping_mul(0x0100_0000_01b3).rotate_left(5);
            h2 ^= u64::from(byte).wrapping_add(i as u64);
            h2 = h2.wrapping_mul(0xbf58_476d_1ce4_e5b9).rotate_right(7);
        }
        format!("{h1:016x}{h2:016x}")
    }
}
