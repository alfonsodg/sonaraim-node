//! Zero-hardcode runtime configuration loader for `sonaraim-node`.
//!
//! Reads and validates all required environment variables without embedding
//! fallback constants in source code.

use std::collections::HashMap;
use std::env;
use std::fmt;

/// Errors returned when loading or validating [`NodeConfig`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    /// A required environment variable is missing or empty.
    MissingVariable(String),
    /// An environment variable contains an unparseable or out-of-range value.
    InvalidValue {
        /// Name of the invalid environment variable.
        key: String,
        /// Explanation of why validation failed.
        reason: String,
    },
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingVariable(key) => {
                write!(f, "missing required environment variable: {key}")
            }
            Self::InvalidValue { key, reason } => {
                write!(f, "invalid value for {key}: {reason}")
            }
        }
    }
}

impl std::error::Error for ConfigError {}

/// Validated runtime configuration for a `sonaraim-node` instance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeConfig {
    /// Unique identifier for the relay node.
    pub node_id: String,
    /// Host address for the HTTP `/health` endpoint.
    pub http_host: String,
    /// TCP port for the HTTP `/health` endpoint.
    pub http_port: u16,
    /// Multiaddr where the P2P transport listens.
    pub p2p_listen_addr: String,
    /// Time-to-live in seconds for queued sealed envelopes.
    pub envelope_ttl_seconds: u64,
}

impl NodeConfig {
    /// Loads and validates [`NodeConfig`] from the current process environment.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] if any required variable is missing or invalid.
    pub fn from_env() -> Result<Self, ConfigError> {
        let mut vars = HashMap::new();
        for key in [
            "NODE_ID",
            "NODE_HTTP_HOST",
            "NODE_HTTP_PORT",
            "NODE_P2P_LISTEN_ADDR",
            "NODE_ENVELOPE_TTL_SECONDS",
        ] {
            if let Ok(val) = env::var(key) {
                vars.insert(key.to_string(), val);
            }
        }
        Self::from_map(&vars)
    }

    /// Loads and validates [`NodeConfig`] from an explicit key-value map.
    ///
    /// # Parameters
    ///
    /// - `vars`: Map of environment variable names to raw string values.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] if any required variable is missing or fails validation.
    pub fn from_map(vars: &HashMap<String, String>) -> Result<Self, ConfigError> {
        let node_id = Self::require_non_empty(vars, "NODE_ID")?;
        let http_host = Self::require_non_empty(vars, "NODE_HTTP_HOST")?;
        let raw_port = Self::require_non_empty(vars, "NODE_HTTP_PORT")?;
        let p2p_listen_addr = Self::require_non_empty(vars, "NODE_P2P_LISTEN_ADDR")?;
        let raw_ttl = Self::require_non_empty(vars, "NODE_ENVELOPE_TTL_SECONDS")?;

        let http_port = raw_port
            .parse::<u16>()
            .map_err(|_| ConfigError::InvalidValue {
                key: "NODE_HTTP_PORT".to_string(),
                reason: "must be a valid u16 integer".to_string(),
            })?;
        if http_port == 0 {
            return Err(ConfigError::InvalidValue {
                key: "NODE_HTTP_PORT".to_string(),
                reason: "port must be greater than 0".to_string(),
            });
        }

        if !p2p_listen_addr.starts_with('/') {
            return Err(ConfigError::InvalidValue {
                key: "NODE_P2P_LISTEN_ADDR".to_string(),
                reason: "must be a valid multiaddr starting with '/'".to_string(),
            });
        }

        let envelope_ttl_seconds =
            raw_ttl
                .parse::<u64>()
                .map_err(|_| ConfigError::InvalidValue {
                    key: "NODE_ENVELOPE_TTL_SECONDS".to_string(),
                    reason: "must be a valid u64 integer".to_string(),
                })?;
        if envelope_ttl_seconds == 0 {
            return Err(ConfigError::InvalidValue {
                key: "NODE_ENVELOPE_TTL_SECONDS".to_string(),
                reason: "TTL must be greater than 0".to_string(),
            });
        }

        Ok(Self {
            node_id,
            http_host,
            http_port,
            p2p_listen_addr,
            envelope_ttl_seconds,
        })
    }

    /// Formats the HTTP bind socket string (`<http_host>:<http_port>`).
    #[must_use]
    pub fn http_bind_address(&self) -> String {
        format!("{}:{}", self.http_host, self.http_port)
    }

    /// Extracts a non-empty trimmed string value for `key` from `vars`.
    fn require_non_empty(vars: &HashMap<String, String>, key: &str) -> Result<String, ConfigError> {
        match vars.get(key) {
            Some(val) if !val.trim().is_empty() => Ok(val.trim().to_string()),
            _ => Err(ConfigError::MissingVariable(key.to_string())),
        }
    }
}
