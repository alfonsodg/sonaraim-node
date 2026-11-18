//! Entrypoint for the `sonaraim-node` core P2P relay and Key Transparency daemon.

use sonaraim_node::config::NodeConfig;
use sonaraim_node::gossip_daemon::spawn_gossip_daemon;
use sonaraim_node::health::HealthStatus;
use sonaraim_node::http_server::{run_server_shared, NodeState};
use sonaraim_node::merkle::KeyTransparencyLog;
use sonaraim_node::relay::MailboxStore;
use std::process::ExitCode;
use std::sync::{Arc, Mutex};

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
    let shared = Arc::new(Mutex::new(state));
    let _gossip = match spawn_gossip_daemon(Arc::clone(&shared)) {
        Ok((udp_addr, handle)) => {
            eprintln!("{{\"level\":\"INFO\",\"msg\":\"gossip daemon bound\",\"udp_addr\":\"{udp_addr}\"}}");
            handle
        }
        Err(err) => {
            eprintln!("{{\"level\":\"ERROR\",\"error\":\"gossip daemon failed: {err}\"}}");
            return ExitCode::FAILURE;
        }
    };
    if let Err(err) = run_server_shared(shared) {
        eprintln!("{{\"level\":\"ERROR\",\"error\":\"{err}\"}}");
        return ExitCode::FAILURE;
    }

    ExitCode::SUCCESS
}
