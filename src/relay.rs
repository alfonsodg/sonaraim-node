//! Ephemeral metadata-blind store-and-forward relay queue (`MailboxStore`).
//!
//! Stores opaque [`SealedEnvelope`] items keyed by recipient mailbox identifier,
//! enforces time-to-live (TTL) eviction, and derives deterministic blind push
//! wake-up tokens without exposing sender identity.

use std::collections::HashMap;

/// An opaque end-to-end encrypted envelope queued for an offline recipient.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedEnvelope {
    /// Unique identifier of the envelope.
    pub envelope_id: String,
    /// Opaque hash identifying the recipient's mailbox.
    pub recipient_mailbox_id: String,
    /// End-to-end encrypted ciphertext bytes.
    pub ciphertext: Vec<u8>,
    /// Unix epoch timestamp (in seconds) when the envelope was queued.
    pub created_at_epoch_secs: u64,
}

impl SealedEnvelope {
    /// Checks whether this envelope has expired given a `ttl_seconds` policy and `now_epoch_secs`.
    #[must_use]
    pub fn is_expired(&self, ttl_seconds: u64, now_epoch_secs: u64) -> bool {
        now_epoch_secs.saturating_sub(self.created_at_epoch_secs) >= ttl_seconds
    }
}

/// Ephemeral in-memory store-and-forward queue for offline peers.
#[derive(Debug, Clone)]
pub struct MailboxStore {
    ttl_seconds: u64,
    queues: HashMap<String, Vec<SealedEnvelope>>,
}

impl MailboxStore {
    /// Creates a new [`MailboxStore`] enforcing the specified `ttl_seconds`.
    #[must_use]
    pub fn new(ttl_seconds: u64) -> Self {
        Self {
            ttl_seconds,
            queues: HashMap::new(),
        }
    }

    /// Returns the configured envelope TTL in seconds.
    #[must_use]
    pub fn ttl_seconds(&self) -> u64 {
        self.ttl_seconds
    }

    /// Enqueues a [`SealedEnvelope`] for its recipient mailbox and returns a
    /// deterministic blind push wake-up token.
    pub fn enqueue(&mut self, envelope: SealedEnvelope) -> String {
        let token = Self::derive_blind_wake_token(
            &envelope.recipient_mailbox_id,
            &envelope.envelope_id,
            envelope.created_at_epoch_secs,
        );
        self.queues
            .entry(envelope.recipient_mailbox_id.clone())
            .or_default()
            .push(envelope);
        token
    }

    /// Drains and returns all non-expired envelopes for `mailbox_id` at `now_epoch_secs`.
    /// Expired envelopes in that mailbox are discarded.
    pub fn drain_active(&mut self, mailbox_id: &str, now_epoch_secs: u64) -> Vec<SealedEnvelope> {
        let ttl = self.ttl_seconds;
        let Some(entries) = self.queues.remove(mailbox_id) else {
            return Vec::new();
        };
        entries
            .into_iter()
            .filter(|env| !env.is_expired(ttl, now_epoch_secs))
            .collect()
    }

    /// Returns active envelopes for `mailbox_id` without removing them.
    #[must_use]
    pub fn get_active(&self, mailbox_id: &str, now_epoch_secs: u64) -> Vec<SealedEnvelope> {
        let ttl = self.ttl_seconds;
        let Some(entries) = self.queues.get(mailbox_id) else {
            return Vec::new();
        };
        entries
            .iter()
            .filter(|env| !env.is_expired(ttl, now_epoch_secs))
            .cloned()
            .collect()
    }

    /// Acknowledges and removes envelopes matching `envelope_ids` (or all if empty) for `mailbox_id`.
    /// Returns the number of removed envelopes.
    pub fn ack(&mut self, mailbox_id: &str, envelope_ids: &[String]) -> usize {
        let Some(list) = self.queues.get_mut(mailbox_id) else {
            return 0;
        };
        let before = list.len();
        if envelope_ids.is_empty() {
            list.clear();
        } else {
            list.retain(|env| !envelope_ids.iter().any(|id| id == &env.envelope_id));
        }
        let removed = before.saturating_sub(list.len());
        if list.is_empty() {
            self.queues.remove(mailbox_id);
        }
        removed
    }

    /// Returns active `(envelope_id, recipient_mailbox_id, payload_hex)` tuples across all queues.
    #[must_use]
    pub fn all_active_tuples(&self, now_epoch_secs: u64) -> Vec<(String, String, String)> {
        let ttl = self.ttl_seconds;
        let mut out = Vec::new();
        for list in self.queues.values() {
            for env in list {
                if !env.is_expired(ttl, now_epoch_secs) {
                    out.push((
                        env.envelope_id.clone(),
                        env.recipient_mailbox_id.clone(),
                        String::from_utf8_lossy(&env.ciphertext).to_string(),
                    ));
                }
            }
        }
        out
    }

    /// Purges expired envelopes across all mailboxes at `now_epoch_secs` and returns
    /// the number of evicted envelopes.
    pub fn purge_expired(&mut self, now_epoch_secs: u64) -> usize {
        let ttl = self.ttl_seconds;
        let mut purged = 0usize;
        self.queues.retain(|_, list| {
            let before = list.len();
            list.retain(|env| !env.is_expired(ttl, now_epoch_secs));
            purged += before.saturating_sub(list.len());
            !list.is_empty()
        });
        purged
    }

    /// Returns the total number of envelopes currently stored across all mailboxes.
    #[must_use]
    pub fn total_queued(&self) -> usize {
        self.queues.values().map(Vec::len).sum()
    }

    /// Derives a deterministic 128-bit blind push wake-up token formatted as hex.
    ///
    /// Uses two independent FNV-1a 64-bit passes with domain separation so push
    /// notification relays can wake a recipient device without learning sender metadata.
    #[must_use]
    pub fn derive_blind_wake_token(
        mailbox_id: &str,
        envelope_id: &str,
        created_at_epoch_secs: u64,
    ) -> String {
        let payload =
            format!("sonaraim:wake:v1|{mailbox_id}|{envelope_id}|{created_at_epoch_secs}");
        let hi = fnv1a_64(payload.as_bytes(), 0xcbf2_9ce4_8422_2325);
        let lo = fnv1a_64(payload.as_bytes(), 0x8422_2325_cbf2_9ce4);
        format!("wake_{hi:016x}{lo:016x}")
    }
}

/// Computes a 64-bit FNV-1a digest with a custom initial basis.
fn fnv1a_64(data: &[u8], basis: u64) -> u64 {
    let mut hash = basis;
    for &byte in data {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    hash
}
