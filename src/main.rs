//! Binary entrypoint for `sonaraim-node`.
//!
//! Validates runtime configuration from environment variables, initializes the
//! ephemeral store-and-forward queue and Key Transparency Merkle log, and emits
//! structured JSON startup and `/health` telemetry.

use std::process::ExitCode;

use sonaraim_node::config::NodeConfig;
use sonaraim_node::health::HealthStatus;
use sonaraim_node::merkle::KeyTransparencyLog;
use sonaraim_node::relay::MailboxStore;

/// Entrypoint for the `sonaraim-node` daemon.
fn main() -> ExitCode {
    let config = match NodeConfig::from_env() {
        Ok(cfg) => cfg,
        Err(err) => {
            eprintln!("{{\"level\":\"ERROR\",\"event\":\"config_validation_failed\",\"error\":\"{err}\"}}");
            return ExitCode::FAILURE;
        }
    };

    let relay = MailboxStore::new(config.envelope_ttl_seconds);
    let kt_log = KeyTransparencyLog::new();
    let health = HealthStatus::from_state(&config, &relay, &kt_log);

    println!(
        "{{\"level\":\"INFO\",\"event\":\"node_initialized\",\"health\":{}}}",
        health.to_json()
    );

    ExitCode::SUCCESS
}
