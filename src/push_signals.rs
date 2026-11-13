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
#[allow(clippy::chunks_exact_to_as_chunks)]
#[rustfmt::skip]
#[must_use]
pub fn sha256_hex(data: &[u8]) -> String {
    let mut h: [u32; 8] = [
        0x6a09_e667, 0xbb67_ae85, 0x3c6e_f372, 0xa54f_f53a,
        0x510e_527f, 0x9b05_688c, 0x1f83_d9ab, 0x5be0_cd19,
    ];
    let k: [u32; 64] = [
        0x428a_2f98, 0x7137_4491, 0xb5c0_fbcf, 0xe9b5_dba5, 0x3956_c25b, 0x59f1_11f1, 0x923f_82a4, 0xab1c_5ed5, 0xd807_aa98, 0x1283_5b01, 0x2431_85be, 0x550c_7dc3, 0x72be_5d74, 0x80de_b1fe, 0x9bdc_06a7, 0xc19b_f174,
        0xe49b_69c1, 0xefbe_4786, 0x0fc1_9dc6, 0x240c_a1cc, 0x2de9_2c6f, 0x4a74_84aa, 0x5cb0_a9dc, 0x76f9_88da, 0x983e_5152, 0xa831_c66d, 0xb003_27c8, 0xbf59_7fc7, 0xc6e0_0bf3, 0xd5a7_9147, 0x06ca_6351, 0x1429_2967,
        0x27b7_0a85, 0x2e1b_2138, 0x4d2c_6dfc, 0x5338_0d13, 0x650a_7354, 0x766a_0abb, 0x81c2_c92e, 0x9272_2c85, 0xa2bf_e8a1, 0xa81a_664b, 0xc24b_8b70, 0xc76c_51a3, 0xd192_e819, 0xd699_0624, 0xf40e_3585, 0x106a_a070,
        0x19a4_c116, 0x1e37_6c08, 0x2748_774c, 0x34b0_bcb5, 0x391c_0cb3, 0x4ed8_aa4a, 0x5b9c_ca4f, 0x682e_6ff3, 0x748f_82ee, 0x78a5_636f, 0x84c8_7814, 0x8cc7_0208, 0x90be_fffa, 0xa450_6ceb, 0xbef9_a3f7, 0xc671_78f2,
    ];
    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut msg = data.to_vec();
    msg.push(0x80);
    while !(msg.len() + 8).is_multiple_of(64) {
        msg.push(0x00);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in msg.chunks_exact(64) {
        let mut w = [0u32; 64];
        for (i, part) in chunk.chunks_exact(4).enumerate() {
            w[i] = u32::from_be_bytes([part[0], part[1], part[2], part[3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h_val] = h;
        for (i, &ki) in k.iter().enumerate() {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h_val.wrapping_add(s1).wrapping_add(ch).wrapping_add(ki).wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h_val = g; g = f; f = e;
            e = d.wrapping_add(temp1);
            d = c; c = b; b = a;
            a = temp1.wrapping_add(temp2);
        }
        for (hi, val) in h.iter_mut().zip([a, b, c, d, e, f, g, h_val]) {
            *hi = hi.wrapping_add(val);
        }
    }
    format!(
        "{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}",
        h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]
    )
}
