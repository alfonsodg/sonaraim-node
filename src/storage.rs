//! Durable snapshot persistence, file-backed Write-Ahead Log (WAL) recovery,
//! S3-compatible presigned media URL generation, and lightweight JSON field parsers.

use crate::merkle::{IdentityLogEntry, KeyTransparencyLog};
use std::collections::HashMap;
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

/// Errors returned by snapshot serialization, WAL recovery, or S3 presign helpers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StorageError {
    /// Snapshot or WAL text was malformed or missing expected fields.
    MalformedSnapshot(&'static str),
    /// Filesystem I/O error while reading or appending the WAL.
    Io(String),
}

impl fmt::Display for StorageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MalformedSnapshot(msg) => write!(f, "malformed node snapshot: {msg}"),
            Self::Io(msg) => write!(f, "storage I/O error: {msg}"),
        }
    }
}

impl std::error::Error for StorageError {}

/// Single durable Write-Ahead Log (WAL) record for a Key Transparency identity binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalEntry {
    /// Decentralized Identifier (`did:sonaraim:*` or `did:web:*`).
    pub did: String,
    /// Public key commitment string.
    pub key_commitment: String,
    /// Unix epoch timestamp (in seconds) when the binding was appended.
    pub epoch_secs: u64,
}

impl WalEntry {
    /// Serializes this [`WalEntry`] as a JSON-lines record.
    #[must_use]
    pub fn to_json_line(&self) -> String {
        format!(
            "{{\"did\":\"{}\",\"key_commitment\":\"{}\",\"epoch_secs\":{}}}\n",
            self.did, self.key_commitment, self.epoch_secs
        )
    }

    /// Parses a single JSON-lines record into a [`WalEntry`].
    pub fn from_json_line(line: &str) -> Result<Self, StorageError> {
        let trimmed = line.trim();
        let did = extract_json_str(trimmed, "did")
            .ok_or(StorageError::MalformedSnapshot("missing wal did"))?;
        let key_commitment = extract_json_str(trimmed, "key_commitment").ok_or(
            StorageError::MalformedSnapshot("missing wal key_commitment"),
        )?;
        let epoch_secs = extract_json_u64(trimmed, "epoch_secs")
            .ok_or(StorageError::MalformedSnapshot("missing wal epoch_secs"))?;
        Ok(Self {
            did,
            key_commitment,
            epoch_secs,
        })
    }
}

/// Derives the WAL file path (`kt_log.wal`) in the parent directory of `signing_key_path`.
#[must_use]
pub fn wal_path_from_signing_key(signing_key_path: &str) -> PathBuf {
    let p = Path::new(signing_key_path);
    match p.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.join("kt_log.wal"),
        _ => PathBuf::from("kt_log.wal"),
    }
}

/// Appends a [`WalEntry`] to the specified WAL file on disk, creating parent directories if needed.
pub fn append_wal_entry(wal_path: &Path, entry: &WalEntry) -> Result<(), StorageError> {
    if let Some(parent) = wal_path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).map_err(|e| StorageError::Io(e.to_string()))?;
        }
    }
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(wal_path)
        .map_err(|e| StorageError::Io(e.to_string()))?;
    file.write_all(entry.to_json_line().as_bytes())
        .map_err(|e| StorageError::Io(e.to_string()))?;
    file.flush().map_err(|e| StorageError::Io(e.to_string()))
}

/// Loads all [`WalEntry`] records from `wal_path`. Returns an empty vector if the file does not exist.
pub fn load_wal_entries(wal_path: &Path) -> Result<Vec<WalEntry>, StorageError> {
    if !wal_path.exists() {
        return Ok(Vec::new());
    }
    let raw = fs::read_to_string(wal_path).map_err(|e| StorageError::Io(e.to_string()))?;
    let mut entries = Vec::new();
    for line in raw.lines() {
        if !line.trim().is_empty() {
            entries.push(WalEntry::from_json_line(line)?);
        }
    }
    Ok(entries)
}

/// Replays WAL entries from `wal_path` into `kt_log` and returns the populated `did_index`.
#[must_use]
pub fn replay_wal_into_log(
    wal_path: Option<&Path>,
    kt_log: &mut KeyTransparencyLog,
) -> HashMap<String, IdentityLogEntry> {
    let mut did_index = HashMap::new();
    let Some(path) = wal_path else {
        return did_index;
    };
    for item in load_wal_entries(path).unwrap_or_default() {
        if let Ok((idx, _)) = kt_log.append(&item.did, &item.key_commitment, item.epoch_secs) {
            let leaf_hash = KeyTransparencyLog::hash_leaf(
                idx,
                &item.did,
                &item.key_commitment,
                item.epoch_secs,
            );
            did_index.insert(
                item.did.clone(),
                IdentityLogEntry {
                    index: idx,
                    did: item.did,
                    key_commitment: item.key_commitment,
                    epoch_secs: item.epoch_secs,
                    leaf_hash,
                },
            );
        }
    }
    did_index
}

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

/// Extracts a string value for `"key":"value"` from a flat JSON payload.
#[must_use]
pub fn extract_json_str(raw: &str, key: &str) -> Option<String> {
    let pattern = format!("\"{key}\":\"");
    let start = raw.find(&pattern)? + pattern.len();
    let rest = &raw[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

/// Extracts a `usize` integer value for `"key":123` from a flat JSON payload.
#[must_use]
pub fn extract_json_usize(raw: &str, key: &str) -> Option<usize> {
    let pattern = format!("\"{key}\":");
    let start = raw.find(&pattern)? + pattern.len();
    let digits: String = raw[start..]
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    digits.parse::<usize>().ok()
}

/// Extracts a `u64` integer value for `"key":123` from a flat JSON payload.
#[must_use]
pub fn extract_json_u64(raw: &str, key: &str) -> Option<u64> {
    let pattern = format!("\"{key}\":");
    let start = raw.find(&pattern)? + pattern.len();
    let digits: String = raw[start..]
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    digits.parse::<u64>().ok()
}

/// Extracts a string array for `"key":["a","b"]` from a flat JSON payload.
#[must_use]
pub fn extract_json_str_array(raw: &str, key: &str) -> Vec<String> {
    let pat = format!("\"{key}\":[");
    let Some(start) = raw.find(&pat) else {
        return Vec::new();
    };
    let rest = &raw[start + pat.len()..];
    let Some(end) = rest.find(']') else {
        return Vec::new();
    };
    rest[..end]
        .split(',')
        .map(|s| s.trim().trim_matches('"').to_string())
        .filter(|s| !s.is_empty())
        .collect()
}
