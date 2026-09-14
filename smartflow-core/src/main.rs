use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Parser;

use proxyduck_core::{run_core, CoreOptions};

#[derive(Debug, Parser)]
#[command(author, version, about = "ProxyDuck core service")]
struct Cli {
    #[arg(long, default_value = "127.0.0.1:46666")]
    bind: String,

    #[arg(long)]
    config: Option<PathBuf>,

    #[arg(long, default_value = "info")]
    log_level: String,

    /// Enables the local Windows Named Pipe adapter.
    #[arg(long)]
    ipc_pipe: bool,

    /// Runs only the Named Pipe adapter; requires --ipc-pipe.
    #[arg(long, requires = "ipc_pipe")]
    no_http: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let bind = cli
        .bind
        .parse()
        .with_context(|| format!("invalid bind address: {}", cli.bind))?;
    run_core(
        CoreOptions {
            bind,
            config_path: cli.config,
            log_level: cli.log_level,
            ipc_pipe: cli.ipc_pipe,
            no_http: cli.no_http,
            allow_recovery: false,
        },
        None,
    )
    .await
}
