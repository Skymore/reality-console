use anyhow::Result;
use clap::{Parser, Subcommand};
use node_host::{
    configure_xray, initialize, join, run, status, sync_once, HostStatus, SyncLoopOptions,
};
use std::path::PathBuf;
use std::time::Duration;

#[derive(Debug, Parser)]
#[command(name = "node-host", about = "Reality Console node host")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Initialize persistent node-host state.
    Init {
        /// Persistent state directory.
        #[arg(long)]
        data_dir: PathBuf,
        /// Controller HTTP(S) origin.
        #[arg(long)]
        controller: String,
    },
    /// Join a private network using a one-time invitation file.
    Join {
        /// Persistent state directory.
        #[arg(long)]
        data_dir: PathBuf,
        /// JSON file returned by `CreateNodeInvitationResponse`.
        #[arg(long)]
        invitation_file: PathBuf,
        /// Name shown to the network operator.
        #[arg(long)]
        display_name: String,
        /// Confirms that you own or are authorized to operate this host.
        #[arg(long)]
        accept_host_owner: bool,
        /// Confirms that this network may expose your public IP as an exit IP.
        #[arg(long)]
        accept_exit_ip: bool,
    },
    /// Print non-secret local status.
    Status {
        /// Persistent state directory.
        #[arg(long)]
        data_dir: PathBuf,
    },
    /// Perform one outbound heartbeat and desired-state synchronization cycle.
    SyncOnce {
        /// Persistent state directory.
        #[arg(long)]
        data_dir: PathBuf,
    },
    /// Verify and pin an installer-provided Xray runtime without starting it.
    ConfigureXray {
        /// Persistent state directory.
        #[arg(long)]
        data_dir: PathBuf,
        /// Explicit absolute path to the installed Xray executable.
        #[arg(long)]
        binary_path: PathBuf,
        /// Trusted 64-character SHA-256 supplied by the installer manifest.
        #[arg(long)]
        sha256: String,
        /// Explicitly replace a different existing binary pin.
        #[arg(long)]
        replace: bool,
    },
    /// Run resilient outbound synchronization until the process is stopped.
    Run {
        /// Persistent state directory.
        #[arg(long)]
        data_dir: PathBuf,
        /// Base interval after successful synchronization.
        #[arg(long, default_value_t = 30)]
        sync_interval_seconds: u64,
        /// First retry delay after a failed synchronization.
        #[arg(long, default_value_t = 5)]
        initial_backoff_seconds: u64,
        /// Maximum retry delay after consecutive failures.
        #[arg(long, default_value_t = 300)]
        max_backoff_seconds: u64,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let status = match Cli::parse().command {
        Command::Init {
            data_dir,
            controller,
        } => initialize(&data_dir, &controller)?,
        Command::Join {
            data_dir,
            invitation_file,
            display_name,
            accept_host_owner,
            accept_exit_ip,
        } => {
            join(
                &data_dir,
                &invitation_file,
                &display_name,
                accept_host_owner,
                accept_exit_ip,
            )
            .await?
        }
        Command::Status { data_dir } => status(&data_dir)?,
        Command::SyncOnce { data_dir } => sync_once(&data_dir).await?,
        Command::ConfigureXray {
            data_dir,
            binary_path,
            sha256,
            replace,
        } => configure_xray(&data_dir, &binary_path, &sha256, replace).await?,
        Command::Run {
            data_dir,
            sync_interval_seconds,
            initial_backoff_seconds,
            max_backoff_seconds,
        } => {
            init_logging();
            run(
                &data_dir,
                SyncLoopOptions {
                    success_interval: Duration::from_secs(sync_interval_seconds),
                    initial_backoff: Duration::from_secs(initial_backoff_seconds),
                    max_backoff: Duration::from_secs(max_backoff_seconds),
                },
            )
            .await?;
            return Ok(());
        }
    };
    print_status(&status);
    Ok(())
}

fn init_logging() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("node_host=info"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_ansi(false)
        .with_target(false)
        .try_init();
}

fn print_status(status: &HostStatus) {
    println!("initialized: yes");
    println!("controller: {}", status.controller);
    println!(
        "identity_public_key: {}",
        status.identity_public_key.as_str()
    );
    println!(
        "encryption_public_key: {}",
        status.encryption_public_key.as_str()
    );
    println!("schema_version: {}", status.schema_version);
    println!("enrollment: {}", status.enrollment_state);
    match status.node_id {
        Some(node_id) => println!("node_id: {node_id}"),
        None => println!("node_id: none"),
    }
    match status.credential_expires_at {
        Some(expires_at) => println!("credential_expires_at: {expires_at}"),
        None => println!("credential_expires_at: none"),
    }
    match status.last_heartbeat_at {
        Some(timestamp) => println!("last_heartbeat_at: {timestamp}"),
        None => println!("last_heartbeat_at: none"),
    }
    match status.last_sync_at {
        Some(timestamp) => println!("last_sync_at: {timestamp}"),
        None => println!("last_sync_at: none"),
    }
    println!(
        "desired_revision_cursor: {}",
        status.desired_revision_cursor
    );
    println!("xray_configured: {}", status.xray_configured);
    match &status.xray_binary_path {
        Some(path) => println!("xray_binary_path: {}", path.display()),
        None => println!("xray_binary_path: none"),
    }
    match &status.xray_expected_sha256 {
        Some(digest) => println!("xray_expected_sha256: {digest}"),
        None => println!("xray_expected_sha256: none"),
    }
    match &status.xray_version {
        Some(version) => println!("xray_version: {version}"),
        None => println!("xray_version: none"),
    }
    match &status.reality_public_key {
        Some(public_key) => println!("reality_public_key: {}", public_key.as_str()),
        None => println!("reality_public_key: none"),
    }
    match &status.reality_short_id {
        Some(short_id) => println!("reality_short_id: {short_id}"),
        None => println!("reality_short_id: none"),
    }
}
