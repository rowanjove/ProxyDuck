mod api;
mod auth;
mod config;
mod engine;
mod model;
mod process;
mod state;
mod watcher;

use std::{net::SocketAddr, path::PathBuf};

use anyhow::{Context, Result};
use clap::Parser;
use model::UiLogEvent;

use crate::state::CoreState;

#[derive(Debug, Parser)]
#[command(author, version, about = "SmartFlow core service")]
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

    let auth_token = auth::load_or_create_token()?;
    let cfg = config::load_or_init(&config_path)?;
    let state = CoreState::new(config_path, auth_token, cfg);
    state.add_log(UiLogEvent::new(
        "info",
        "bootstrap",
        "core service starting",
    ));

    {
        let snapshot = state.config_snapshot();
        state.engine.start(&snapshot)?;
    }

    watcher::start_process_watcher(state.clone());

    let state_for_signal = state.clone();
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            let _ = state_for_signal.engine.stop();
        }
    });

    api::run_http(state, bind).await
}

fn init_tracing(level: &str) -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(format!("smartflow_core={level},tower_http=info"))
        .json()
        .init();
    Ok(())
}
