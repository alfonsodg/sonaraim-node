//! Health telemetry snapshot, `/health` JSON payload serializer, and Prometheus `/metrics` formatter.

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
    /// Last Redis error observed by the relay paths, if any.
    pub redis_last_error: Option<String>,
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
            redis_last_error: None,
        }
    }

    /// Builds a [`HealthStatus`] snapshot including the last Redis error.
    #[must_use]
    pub fn from_state_with_redis_error(
        config: &NodeConfig,
        relay: &MailboxStore,
        kt_log: &KeyTransparencyLog,
        redis_last_error: Option<&str>,
    ) -> Self {
        let mut status = Self::from_state(config, relay, kt_log);
        status.redis_last_error = redis_last_error.map(ToString::to_string);
        if status.redis_last_error.is_some() {
            status.status = "degraded".to_string();
        }
        status
    }

    /// Serializes this [`HealthStatus`] report into a deterministic JSON string
    /// suitable for HTTP `/health` responses and structured logs.
    #[must_use]
    pub fn to_json(&self) -> String {
        let redis_field = self
            .redis_last_error
            .as_deref()
            .map_or("null".to_string(), |e| format!("\"{}\"", escape_json(e)));
        format!(
            concat!(
                "{{",
                "\"status\":\"{}\",",
                "\"node_id\":\"{}\",",
                "\"http_bind\":\"{}\",",
                "\"p2p_listen_addr\":\"{}\",",
                "\"queued_envelopes\":{},",
                "\"kt_log_entries\":{},",
                "\"kt_tree_head\":\"{}\",",
                "\"redis_last_error\":{}",
                "}}"
            ),
            escape_json(&self.status),
            escape_json(&self.node_id),
            escape_json(&self.http_bind),
            escape_json(&self.p2p_listen_addr),
            self.queued_envelopes,
            self.kt_log_entries,
            escape_json(&self.kt_tree_head),
            redis_field,
        )
    }

    /// Formats Prometheus `text/plain; version=0.0.4` metrics for `/metrics`.
    #[must_use]
    pub fn format_prometheus_metrics(kt_entries: usize, queued_envelopes: usize) -> String {
        format!(
            "# HELP sonaraim_node_kt_entries_total Total Key Transparency log entries\n\
             # TYPE sonaraim_node_kt_entries_total counter\n\
             sonaraim_node_kt_entries_total {kt_entries}\n\
             # HELP sonaraim_node_queued_envelopes Currently queued relay envelopes\n\
             # TYPE sonaraim_node_queued_envelopes gauge\n\
             sonaraim_node_queued_envelopes {queued_envelopes}\n"
        )
    }
}

/// Escapes backslashes and double quotes for safe JSON string interpolation.
fn escape_json(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}
