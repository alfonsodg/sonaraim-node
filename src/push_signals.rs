//! Blind device push token registration and ephemeral signal relay.
//!
//! Provides content-free wake-up descriptors for APNs, FCM, and WebPush without
//! exposing plaintext messages or sender metadata, alongside ephemeral typing
//! and receipt signals with automatic time-to-live eviction.

use std::collections::HashMap;

/// Supported mobile and web push delivery platforms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PushPlatform {
    /// Apple Push Notification service.
    Apns,
    /// Firebase Cloud Messaging.
    Fcm,
    /// W3C WebPush.
    WebPush,
}

impl PushPlatform {
    /// Parses a string into a [`PushPlatform`].
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "apns" => Some(Self::Apns),
            "fcm" => Some(Self::Fcm),
            "webpush" | "web_push" => Some(Self::WebPush),
            _ => None,
        }
    }

    /// Returns the canonical platform identifier string.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Apns => "apns",
            Self::Fcm => "fcm",
            Self::WebPush => "webpush",
        }
    }
}

/// Blind device push registration record.
///
/// Device tokens are stored as SHA-256 hashes so raw tokens are never exposed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushRegistration {
    /// Target recipient mailbox ID.
    pub mailbox_id: String,
    /// Push platform.
    pub platform: PushPlatform,
    /// SHA-256 hexadecimal hash of the device token.
    pub token_hash: String,
    /// Optional push gateway endpoint hint.
    pub endpoint_hint: Option<String>,
}

/// Ephemeral signal category.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignalType {
    /// User is currently composing a message.
    Typing,
    /// Envelope was delivered to recipient's client.
    Delivered,
    /// Envelope was read by the recipient.
    Read,
}

impl SignalType {
    /// Parses a string into a [`SignalType`].
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "typing" => Some(Self::Typing),
            "delivered" => Some(Self::Delivered),
            "read" => Some(Self::Read),
            _ => None,
        }
    }

    /// Returns the canonical signal string identifier.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Typing => "typing",
            Self::Delivered => "delivered",
            Self::Read => "read",
        }
    }

    /// Returns the default time-to-live in seconds (30s for typing, 300s for receipts).
    #[must_use]
    pub const fn default_ttl_secs(&self) -> u64 {
        match self {
            Self::Typing => 30,
            Self::Delivered | Self::Read => 300,
        }
    }
}

/// Ephemeral typing or delivery/read receipt signal record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EphemeralSignal {
    /// Recipient mailbox ID.
    pub mailbox_id: String,
    /// Decentralized Identifier of the signal origin.
    pub sender_did: String,
    /// Type of ephemeral signal.
    pub signal_type: SignalType,
    /// Optional envelope ID referenced by delivery or read receipts.
    pub envelope_id: Option<String>,
    /// Unix epoch expiration timestamp after which the signal is purged.
    pub expires_at_epoch: u64,
}

impl EphemeralSignal {
    /// Serializes this signal to a JSON object string.
    #[must_use]
    pub fn to_json(&self) -> String {
        let env = self.envelope_id.as_deref().map_or("null", |id| id);
        let env_field = if self.envelope_id.is_some() {
            format!("\"{env}\"")
        } else {
            "null".to_string()
        };
        format!(
            "{{\"sender_did\":\"{}\",\"signal_type\":\"{}\",\"envelope_id\":{env_field},\"expires_at_epoch\":{}}}",
            self.sender_did, self.signal_type.as_str(), self.expires_at_epoch
        )
    }
}

/// In-memory blind push wake-up registry and ephemeral signal store.
#[derive(Debug, Default, Clone)]
pub struct PushSignalRegistry {
    registrations: HashMap<String, PushRegistration>,
    signals: HashMap<String, Vec<EphemeralSignal>>,
    wake_up_counts: HashMap<String, u64>,
}

impl PushSignalRegistry {
    /// Creates an empty [`PushSignalRegistry`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a device push token, computing its SHA-256 digest blindly.
    pub fn register_push_token(
        &mut self,
        mailbox_id: &str,
        platform: PushPlatform,
        device_token: &str,
        endpoint_hint: Option<&str>,
        _now_epoch: u64,
    ) -> PushRegistration {
        let reg = PushRegistration {
            mailbox_id: mailbox_id.to_string(),
            platform,
            token_hash: sha256_hex(device_token.as_bytes()),
            endpoint_hint: endpoint_hint.map(ToString::to_string),
        };
        self.registrations
            .insert(mailbox_id.to_string(), reg.clone());
        reg
    }

    /// Returns the registered push metadata for a mailbox, if present.
    #[must_use]
    pub fn get_registration(&self, mailbox_id: &str) -> Option<&PushRegistration> {
        self.registrations.get(mailbox_id)
    }

    /// Returns `true` if a push token is registered for `mailbox_id`.
    #[must_use]
    pub fn has_registration(&self, mailbox_id: &str) -> bool {
        self.registrations.contains_key(mailbox_id)
    }

    /// Constructs a content-free wake-up payload descriptor containing zero metadata.
    #[must_use]
    pub fn build_silent_wakeup_payload(&self, mailbox_id: &str) -> Option<String> {
        self.has_registration(mailbox_id).then(|| {
            format!("{{\"mailbox_id\":\"{mailbox_id}\",\"wake\":true,\"has_pending\":true}}")
        })
    }

    /// Records a silent wake-up trigger for `mailbox_id`, incrementing its counter.
    pub fn record_wake_up(&mut self, mailbox_id: &str) -> bool {
        if self.has_registration(mailbox_id) {
            let entry = self
                .wake_up_counts
                .entry(mailbox_id.to_string())
                .or_insert(0);
            *entry = entry.saturating_add(1);
            true
        } else {
            false
        }
    }

    /// Returns total silent wake-up triggers queued for `mailbox_id`.
    #[must_use]
    pub fn wake_up_count(&self, mailbox_id: &str) -> u64 {
        self.wake_up_counts.get(mailbox_id).copied().unwrap_or(0)
    }

    /// Records an ephemeral typing or delivery/read receipt signal.
    pub fn record_signal(
        &mut self,
        mailbox_id: &str,
        sender_did: &str,
        signal_type: SignalType,
        envelope_id: Option<&str>,
        now_epoch: u64,
    ) -> EphemeralSignal {
        let signal = EphemeralSignal {
            mailbox_id: mailbox_id.to_string(),
            sender_did: sender_did.to_string(),
            signal_type,
            envelope_id: envelope_id.map(ToString::to_string),
            expires_at_epoch: now_epoch.saturating_add(signal_type.default_ttl_secs()),
        };
        self.signals
            .entry(mailbox_id.to_string())
            .or_default()
            .push(signal.clone());
        signal
    }

    /// Drains all active non-expired signals for `mailbox_id`.
    pub fn drain_signals(&mut self, mailbox_id: &str, now_epoch: u64) -> Vec<EphemeralSignal> {
        let Some(list) = self.signals.remove(mailbox_id) else {
            return Vec::new();
        };
        list.into_iter()
            .filter(|sig| sig.expires_at_epoch > now_epoch)
            .collect()
    }
}

/// Standard SHA-256 digest computation (FIPS 180-4).
///
/// Canonical implementation lives in [`crate::crypto::sha256_hex`]; this
/// re-export preserves the existing public path used by push registration.
pub use crate::crypto::sha256_hex;
