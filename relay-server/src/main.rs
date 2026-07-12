use std::{path::PathBuf, sync::Arc};

use anyhow::Context;
use clap::Parser;
use relay_server::{NodeConnectorConfig, RelayConfig, RelayNodeConnector, RelayServer};
use tokio_util::sync::CancellationToken;
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(version, about)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, clap::Subcommand)]
enum Command {
    /// Run the public relay service.
    Serve {
        /// Relay server TOML configuration file.
        #[arg(long, env = "RELAY_CONFIG")]
        config: PathBuf,
    },
    /// Run one node-originated connector to a fixed loopback Xray target.
    RelayNode {
        /// Relay node connector TOML configuration file.
        #[arg(long, env = "RELAY_NODE_CONFIG")]
        config: PathBuf,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| "relay_server=info".into()),
        )
        .with_target(false)
        .compact()
        .init();

    let args = Args::parse();
    match args.command {
        Command::Serve { config } => run_server(config).await?,
        Command::RelayNode { config } => run_node(config).await?,
    }
    Ok(())
}

async fn run_server(config_path: PathBuf) -> anyhow::Result<()> {
    let config = RelayConfig::load(&config_path)
        .await
        .context("load relay configuration")?;
    let handle = RelayServer::start(config)
        .await
        .context("start relay server")?;
    handle.watch_config(config_path);
    tokio::signal::ctrl_c().await.context("wait for shutdown")?;
    handle.shutdown().await;
    Ok(())
}

async fn run_node(config_path: PathBuf) -> anyhow::Result<()> {
    let config = NodeConnectorConfig::load(&config_path)
        .await
        .context("load relay node configuration")?;
    let connector = Arc::new(
        RelayNodeConnector::new(config)
            .await
            .context("initialize relay node connector")?,
    );
    let shutdown = CancellationToken::new();
    let task_connector = connector.clone();
    let task_shutdown = shutdown.clone();
    let task = tokio::spawn(async move { task_connector.run(task_shutdown).await });
    tokio::signal::ctrl_c().await.context("wait for shutdown")?;
    shutdown.cancel();
    task.await.context("join relay node connector")?;
    Ok(())
}
