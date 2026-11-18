//! Durable per-domain Write-Ahead Log (WAL) for relay envelopes (`relay_mailboxes.wal`).
//!
//! Identity bindings live in `kt_log.wal` (`crate::storage`); relay envelopes
//! live here. One file, one schema: envelope records never touch the identity
//! WAL, so mailbox ack compaction cannot destroy the identity log.

use crate::relay::{MailboxStore, SealedEnvelope};
use crate::storage::StorageError;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

/// Single durable WAL record for a queued relay envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvelopeWalEntry {
    /// Unique identifier of the envelope.
    pub envelope_id: String,
    /// Opaque hash identifying the recipient's mailbox.
    pub recipient_mailbox_id: String,
    /// Envelope ciphertext serialized as hex.
    pub payload_hex: String,
    /// Unix epoch timestamp (in seconds) when the envelope was queued.
    pub created_at_epoch_secs: u64,
}

impl EnvelopeWalEntry {
    /// Serializes this [`EnvelopeWalEntry`] as a JSON-lines record.
    #[must_use]
    pub fn to_json_line(&self) -> String {
        format!(
            "{{\"envelope_id\":\"{}\",\"recipient_mailbox_id\":\"{}\",\"payload_hex\":\"{}\",\"created_at_epoch_secs\":{}}}\n",
            self.envelope_id,
            self.recipient_mailbox_id,
            self.payload_hex,
            self.created_at_epoch_secs
        )
    }

    /// Parses a single JSON-lines record into an [`EnvelopeWalEntry`].
    pub fn from_json_line(line: &str) -> Result<Self, StorageError> {
        let trimmed = line.trim();
        let envelope_id = crate::storage::extract_json_str(trimmed, "envelope_id")
            .ok_or(StorageError::MalformedSnapshot("missing wal envelope_id"))?;
        let recipient_mailbox_id =
            crate::storage::extract_json_str(trimmed, "recipient_mailbox_id").ok_or(
                StorageError::MalformedSnapshot("missing wal recipient_mailbox_id"),
            )?;
        let payload_hex = crate::storage::extract_json_str(trimmed, "payload_hex")
            .ok_or(StorageError::MalformedSnapshot("missing wal payload_hex"))?;
        let created_at_epoch_secs =
            crate::storage::extract_json_u64(trimmed, "created_at_epoch_secs").ok_or(
                StorageError::MalformedSnapshot("missing wal created_at_epoch_secs"),
            )?;
        Ok(Self {
            envelope_id,
            recipient_mailbox_id,
            payload_hex,
            created_at_epoch_secs,
        })
    }
}

/// Derives the envelope WAL path (`relay_mailboxes.wal`) colocated with `identity_wal`.
#[must_use]
pub fn envelope_wal_path_from_identity_wal(identity_wal: &Path) -> PathBuf {
    match identity_wal.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.join("relay_mailboxes.wal"),
        _ => PathBuf::from("relay_mailboxes.wal"),
    }
}

/// Appends an [`EnvelopeWalEntry`] to the envelope WAL, fsyncing before returning.
pub fn append_envelope_wal_entry(
    wal_path: &Path,
    entry: &EnvelopeWalEntry,
) -> Result<(), StorageError> {
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
    file.flush().map_err(|e| StorageError::Io(e.to_string()))?;
    file.sync_all().map_err(|e| StorageError::Io(e.to_string()))
}

/// Loads all [`EnvelopeWalEntry`] records; returns empty when the file is missing.
pub fn load_envelope_wal_entries(wal_path: &Path) -> Result<Vec<EnvelopeWalEntry>, StorageError> {
    if !wal_path.exists() {
        return Ok(Vec::new());
    }
    let raw = fs::read_to_string(wal_path).map_err(|e| StorageError::Io(e.to_string()))?;
    let mut entries = Vec::new();
    for line in raw.lines() {
        if !line.trim().is_empty() {
            entries.push(EnvelopeWalEntry::from_json_line(line)?);
        }
    }
    Ok(entries)
}

/// Replays non-expired envelope WAL records into `relay`; returns replayed count.
pub fn replay_envelope_wal_into_relay(
    relay: &mut MailboxStore,
    wal_path: Option<&Path>,
    now_epoch_secs: u64,
) -> usize {
    let Some(path) = wal_path else {
        return 0;
    };
    let entries = match load_envelope_wal_entries(path) {
        Ok(items) => items,
        Err(e) => {
            eprintln!(
                "{{\"level\":\"ERROR\",\"msg\":\"envelope wal replay failed\",\"error\":\"{e}\"}}"
            );
            return 0;
        }
    };
    let mut replayed = 0usize;
    for item in entries {
        relay.enqueue(SealedEnvelope {
            envelope_id: item.envelope_id,
            recipient_mailbox_id: item.recipient_mailbox_id,
            ciphertext: item.payload_hex.into_bytes(),
            created_at_epoch_secs: item.created_at_epoch_secs,
        });
        replayed += 1;
    }
    relay.purge_expired(now_epoch_secs);
    replayed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_wal_round_trips_and_replays() {
        let dir = std::env::temp_dir().join(format!("env-wal-unit-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let identity =
            crate::storage::wal_path_from_signing_key(&dir.join("node.key").to_string_lossy());
        let envelope = envelope_wal_path_from_identity_wal(&identity);
        assert!(envelope.to_string_lossy().ends_with("relay_mailboxes.wal"));

        let entry = EnvelopeWalEntry {
            envelope_id: "env-1".to_string(),
            recipient_mailbox_id: "mbx-1".to_string(),
            payload_hex: "aabb".to_string(),
            created_at_epoch_secs: 100,
        };
        append_envelope_wal_entry(&envelope, &entry).expect("append");
        let loaded = load_envelope_wal_entries(&envelope).expect("load");
        assert_eq!(loaded, vec![entry]);

        let mut relay = MailboxStore::new(3600);
        let n = replay_envelope_wal_into_relay(&mut relay, Some(&envelope), 200);
        assert_eq!(n, 1);
        assert_eq!(relay.total_queued(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
