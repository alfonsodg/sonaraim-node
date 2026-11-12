//! Entrypoint for the `sonaraim-node` core P2P relay and Key Transparency daemon.

use sonaraim_node::config::NodeConfig;
use sonaraim_node::health::HealthStatus;
use sonaraim_node::http_server::{run_server, NodeState};
use sonaraim_node::merkle::KeyTransparencyLog;
use sonaraim_node::relay::MailboxStore;
use std::process::ExitCode;

fn main() -> ExitCode {
    let config = match NodeConfig::from_env() {
        Ok(cfg) => cfg,
        Err(err) => {
            eprintln!("{{\"level\":\"ERROR\",\"error\":\"{err}\"}}");
            return ExitCode::FAILURE;
        }
    };

    let relay = MailboxStore::new(config.envelope_ttl_seconds);
    let kt_log = KeyTransparencyLog::default();
    let health = HealthStatus::from_state(&config, &relay, &kt_log);
    println!("{}", health.to_json());

    let state = NodeState::new(config, relay, kt_log);
    if let Err(err) = run_server(state) {
        eprintln!("{{\"level\":\"ERROR\",\"error\":\"{err}\"}}");
        return ExitCode::FAILURE;
    }

    ExitCode::SUCCESS
}
