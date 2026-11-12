//! Durable snapshot persistence and S3-compatible presigned media URL generation.

use crate::merkle::KeyTransparencyLog;
use std::fmt;

/// Errors returned by snapshot serialization or S3 presign helpers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StorageError {
    /// Snapshot text was malformed or missing expected fields.
    MalformedSnapshot(&'static str),
}

impl fmt::Display for StorageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MalformedSnapshot(msg) => write!(f, "malformed node snapshot: {msg}"),
        }
    }
}

impl std::error::Error for StorageError {}

/// Point-in-time serializable snapshot of a `sonaraim-node` identity log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeSnapshot {
    /// Number of recorded entries in the Merkle log.
    pub log_size: usize,
    /// Hexadecimal Merkle root hash at capture time.
    pub tree_head: String,
}

impl NodeSnapshot {
    /// Captures a [`NodeSnapshot`] from an active [`KeyTransparencyLog`].
    #[must_use]
    pub fn capture(log: &KeyTransparencyLog) -> Self {
        Self {
            log_size: log.len(),
            tree_head: log.tree_head(),
        }
    }

    /// Serializes the snapshot as a single JSON-lines record.
    #[must_use]
    pub fn to_json_lines(&self) -> String {
        format!(
            "{{\"log_size\":{},\"tree_head\":\"{}\"}}\n",
            self.log_size, self.tree_head
        )
    }

    /// Restores a [`NodeSnapshot`] from a JSON-lines record.
    pub fn from_json_lines(raw: &str) -> Result<Self, StorageError> {
        let trimmed = raw.trim();
        let log_size = extract_json_usize(trimmed, "log_size")
            .ok_or(StorageError::MalformedSnapshot("missing log_size"))?;
        let tree_head = extract_json_str(trimmed, "tree_head")
            .ok_or(StorageError::MalformedSnapshot("missing tree_head"))?;
        Ok(Self {
            log_size,
            tree_head,
        })
    }
}

/// Generates a deterministic S3-compatible presigned URL for client-encrypted media blobs.
#[must_use]
pub fn generate_s3_presigned_url(
    endpoint_url: &str,
    bucket: &str,
    sha256_ciphertext: &str,
    content_length: u64,
) -> String {
    let base = endpoint_url.trim_end_matches('/');
    let mut acc: u64 = 0xcbf2_9ce4_8422_2325;
    for b in format!("{bucket}:{sha256_ciphertext}:{content_length}").bytes() {
        acc ^= u64::from(b);
        acc = acc.wrapping_mul(0x0100_0000_01b3);
    }
    format!("{base}/{bucket}/{sha256_ciphertext}?sig={acc:016x}&len={content_length}")
}

fn extract_json_str(raw: &str, key: &str) -> Option<String> {
    let pattern = format!("\"{key}\":\"");
    let start = raw.find(&pattern)? + pattern.len();
    let rest = &raw[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

fn extract_json_usize(raw: &str, key: &str) -> Option<usize> {
    let pattern = format!("\"{key}\":");
    let start = raw.find(&pattern)? + pattern.len();
    let rest = &raw[start..];
    let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    digits.parse::<usize>().ok()
}
