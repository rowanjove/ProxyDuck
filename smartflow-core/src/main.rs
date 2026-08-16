mod api;
mod config;
mod engine;
mod model;
mod process;
mod proxy_test;
mod routing_plan;
mod state;
mod validation;
mod watcher;

use std::{net::SocketAddr, path::PathBuf};

use anyhow::{Context, Result};
use clap::Parser;
use model::UiLogEvent;

use crate::state::CoreState;

#[derive(Debug, Parser)]
#[command(author, version, about = "ProxyDuck core service")]
struct Cli {
    #[arg(long, default_value = "127.0.0.1:46666")]
    bind: String,

    #[arg(long)]
    config: Option<PathBuf>,

    #[arg(long, default_value = "info")]
    log_level: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    if let Err(error) = proxyduck_common::install_panic_hook("core") {
        eprintln!("failed to initialize crash logging: {error}");
    }
    let cli = Cli::parse();
    init_tracing(&cli.log_level)?;

    let bind: SocketAddr = cli
        .bind
        .parse()
        .with_context(|| format!("invalid bind address: {}", cli.bind))?;

    let config_path = match cli.config {
        Some(path) => path,
        None => config::resolve_config_path()?,
    };

    let auth_token = proxyduck_common::load_or_create_token()?;
    let cfg = config::load_or_init(&config_path)?;
    validation::validate_config(&cfg)?;
    let state = CoreState::new(config_path, auth_token, cfg);
    state.add_log(UiLogEvent::new(
        "info",
        "bootstrap",
        "core service starting",
    ));

    start_data_plane(&state);

    watcher::start_process_watcher(state.clone());

    api::run_http(state, bind).await
}

fn start_data_plane(state: &CoreState) {
    let snapshot = state.config_snapshot();
    if let Err(error) = state.engine.start(&snapshot) {
        tracing::error!(%error, "data plane failed during startup; control API remains available");
        state.add_log(UiLogEvent::new(
            "error",
            "engine",
            format!("data plane startup failed: {error}"),
        ));
    }
}

fn init_tracing(level: &str) -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(format!("proxyduck_core={level},tower_http=info"))
        .json()
        .init();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_plane_failure_does_not_abort_core_bootstrap() {
        let mut config = model::AppConfig::default();
        config.runtime.enabled = true;
        config.proxies[0].enabled = false;
        let state = CoreState::new(PathBuf::from("unused.json5"), "test-token".into(), config);

        start_data_plane(&state);

        assert!(state
            .list_logs()
            .iter()
            .any(|event| event.message.contains("data plane startup failed")));
        assert_eq!(state.engine.status().phase, model::DataPlanePhase::Error);
    }
}
