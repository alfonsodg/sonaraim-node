//! Health telemetry snapshot and `/health` JSON payload serializer.

use crate::config::NodeConfig;
use crate::merkle::KeyTransparencyLog;
use crate::relay::MailboxStore;

/// Point-in-time operational health report for a `sonaraim-node` instance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HealthStatus {
    /// Service readiness indicator (`"ok"`).
    pub status: String,
    /// Logical identifier of the relay node.
    pub node_id: String,
    /// Bound HTTP address (`<host>:<port>`).
    pub http_bind: String,
    /// Configured P2P multiaddr.
    pub p2p_listen_addr: String,
    /// Number of currently queued sealed envelopes across all mailboxes.
    pub queued_envelopes: usize,
    /// Number of identity entries in the Key Transparency log.
    pub kt_log_entries: usize,
    /// Current hexadecimal root hash of the Key Transparency log.
    pub kt_tree_head: String,
}

impl HealthStatus {
    /// Builds a [`HealthStatus`] snapshot from the active node subsystems.
    #[must_use]
    pub fn from_state(
        config: &NodeConfig,
        relay: &MailboxStore,
        kt_log: &KeyTransparencyLog,
    ) -> Self {
        Self {
            status: "ok".to_string(),
            node_id: config.node_id.clone(),
            http_bind: config.http_bind_address(),
            p2p_listen_addr: config.p2p_listen_addr.clone(),
            queued_envelopes: relay.total_queued(),
            kt_log_entries: kt_log.len(),
            kt_tree_head: kt_log.tree_head(),
        }
    }

    /// Serializes this [`HealthStatus`] report into a deterministic JSON string
    /// suitable for HTTP `/health` responses and structured logs.
    #[must_use]
    pub fn to_json(&self) -> String {
        format!(
            concat!(
                "{{",
                "\"status\":\"{}\",",
                "\"node_id\":\"{}\",",
                "\"http_bind\":\"{}\",",
                "\"p2p_listen_addr\":\"{}\",",
                "\"queued_envelopes\":{},",
                "\"kt_log_entries\":{},",
                "\"kt_tree_head\":\"{}\"",
                "}}"
            ),
            escape_json(&self.status),
            escape_json(&self.node_id),
            escape_json(&self.http_bind),
            escape_json(&self.p2p_listen_addr),
            self.queued_envelopes,
            self.kt_log_entries,
            escape_json(&self.kt_tree_head),
        )
    }
}

/// Escapes backslashes and double quotes for safe JSON string interpolation.
fn escape_json(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}
