pub mod api;
pub mod config;
pub mod config_studio;
pub mod endpoint;
pub mod engine;
pub mod events;
pub mod health;
pub mod ipc;
pub mod model;
pub mod network;
pub mod observability;
pub mod policy;
pub mod process;
pub mod proxy_import;
pub mod proxy_test;
pub mod routing_plan;
pub mod state;
pub mod timeline;
pub mod validation;
pub mod watcher;

pub use engine::{is_mock_data_plane, set_mock_data_plane};

use std::{net::SocketAddr, path::PathBuf};

use anyhow::{Context, Result};
use tokio::sync::oneshot;

use crate::{model::UiLogEvent, state::CoreState};

/// Runtime options shared by the command-line executable and the Windows
/// Service host. Keeping bootstrap in the library ensures both entry points
/// use exactly the same config validation, engine and cleanup paths.
#[derive(Debug, Clone)]
pub struct CoreOptions {
    pub bind: SocketAddr,
    pub config_path: Option<PathBuf>,
    pub log_level: String,
    pub ipc_pipe: bool,
    pub no_http: bool,
    /// Service mode keeps a minimal control plane alive when both the primary
    /// config and its backup are corrupt, so the desktop can PUT a repaired
    /// config over the local pipe instead of entering a restart deadlock.
    pub allow_recovery: bool,
}

/// Start ProxyDuck Core and run until Ctrl-C (interactive mode) or an
/// explicit shutdown signal (service mode) is received.
pub async fn run_core(options: CoreOptions, shutdown: Option<oneshot::Receiver<()>>) -> Result<()> {
    run_core_with_readiness(options, shutdown, None).await
}

/// Starts ProxyDuck Core and optionally reports readiness of the requested
/// local IPC listener.  The signal is deliberately emitted only after the
/// Named Pipe has been created with its ACL, so a Windows service is not
/// advertised as Running while its control plane is still retrying setup.
pub async fn run_core_with_readiness(
    options: CoreOptions,
    shutdown: Option<oneshot::Receiver<()>>,
    ready_tx: Option<oneshot::Sender<Result<(), String>>>,
) -> Result<()> {
    if let Err(error) = proxyduck_common::install_panic_hook("core") {
        eprintln!("failed to initialize crash logging: {error}");
    }
    init_tracing(&options.log_level)?;

    if options.no_http && !cfg!(target_os = "windows") {
        anyhow::bail!("--no-http --ipc-pipe is only supported on Windows");
    }

    let config_path = match options.config_path {
        Some(path) => path,
        None => config::resolve_config_path()?,
    };

    let auth_token = proxyduck_common::load_or_create_token()?;
    let (cfg, recovered) = match config::load_or_init(&config_path).and_then(|cfg| {
        validation::validate_config(&cfg)?;
        Ok(cfg)
    }) {
        Ok(cfg) => (cfg, false),
        Err(error) if options.allow_recovery => {
            tracing::error!(%error, "configuration load/validation failed; starting recovery control plane");
            let mut cfg = model::AppConfig::default();
            cfg.runtime.enabled = false;
            (cfg, true)
        }
        Err(error) => return Err(error),
    };
    let state = CoreState::new(config_path, auth_token, cfg);
    if recovered {
        state.add_log(UiLogEvent::with_event_id(
            "warn",
            "bootstrap",
            events::id::CONFIG_RECOVERY,
            "configuration recovery control plane is active; replace the config before enabling the engine",
        ));
    }
    state.add_log(UiLogEvent::with_event_id(
        "info",
        "bootstrap",
        events::id::CORE_START,
        "core service starting",
    ));

    // Even the recovery config starts the ordinary supervisors with the
    // runtime disabled.  This keeps the engine in a reloadable state, so a
    // successful PUT /config can immediately restore normal operation without
    // requiring a second service restart.
    start_data_plane(&state);
    watcher::start_process_watcher(state.clone());
    health::start_health_supervisor(state.clone());
    if options.ipc_pipe {
        ipc::start_named_pipe(state.clone(), ready_tx);
    } else if let Some(tx) = ready_tx {
        let _ = tx.send(Err(
            "IPC readiness requested but IPC is disabled".to_string()
        ));
    }

    if options.no_http {
        await_shutdown(shutdown).await?;
        state
            .engine
            .stop()
            .context("stopping data plane during core shutdown")?;
        return Ok(());
    }

    let shutdown_signal = async move {
        match shutdown {
            Some(receiver) => {
                let _ = receiver.await;
            }
            None => {
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    };
    api::run_http_with_shutdown(state, options.bind, shutdown_signal).await
}

async fn await_shutdown(shutdown: Option<oneshot::Receiver<()>>) -> Result<()> {
    match shutdown {
        Some(receiver) => {
            let _ = receiver.await;
        }
        None => tokio::signal::ctrl_c()
            .await
            .context("waiting for Ctrl-C")?,
    }
    Ok(())
}

fn start_data_plane(state: &CoreState) {
    let snapshot = state.config_snapshot();
    if let Err(error) = state.engine.start(&snapshot) {
        tracing::error!(%error, "data plane failed during startup; control API remains available");
        state.add_log(UiLogEvent::with_event_id(
            "error",
            "engine",
            events::id::ENGINE_START_FAILED,
            format!("data plane startup failed: {error}"),
        ));
    }
}

fn init_tracing(level: &str) -> Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(format!("proxyduck_core={level},tower_http=info"))
        .json()
        .try_init();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_plane_failure_does_not_abort_core_bootstrap() {
        set_mock_data_plane(true);
        let mut config = model::AppConfig::default();
        config.runtime.enabled = true;
        config.proxies[0].enabled = false;
        config.rules.push(model::Rule::new(
            "requires proxy".into(),
            model::MatchCriteria {
                app_names: vec!["browser.exe".into()],
                ..Default::default()
            },
            "local-socks".into(),
        ));
        let state = CoreState::new(PathBuf::from("unused.json5"), "test-token".into(), config);

        start_data_plane(&state);

        assert!(state
            .list_logs()
            .iter()
            .any(|event| event.message.contains("data plane startup failed")));
        assert_eq!(state.engine.status().phase, model::DataPlanePhase::Error);
    }
}
