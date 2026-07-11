use anyhow::Result;
use clap::{Parser, Subcommand};
use control_protocol::node::NodeRuntimeState;
use node_host::{
    bootstrap, bootstrap_and_install_user_service, configure_xray, initialize,
    install_user_service, join, query_local_service_status, remove_user_service, run, status,
    sync_once, user_service_status, BackgroundServiceStatus, BootstrapRequest, HostStatus,
    LocalServiceStatus, SyncLoopOptions, UserServiceInstallRequest,
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
    /// Run installer-owned local setup and one-time node enrollment.
    Bootstrap {
        /// Persistent state directory.
        #[arg(long)]
        data_dir: PathBuf,
        /// Owner-only JSON file returned by `CreateNodeInvitationResponse`.
        #[arg(long)]
        invitation_file: PathBuf,
        /// Name shown to the network operator.
        #[arg(long)]
        display_name: String,
        /// Explicit absolute path to the installer-bundled Xray executable.
        #[arg(long)]
        xray_binary_path: PathBuf,
        /// Trusted installer-manifest SHA-256 for the bundled Xray executable.
        #[arg(long)]
        xray_sha256: String,
        /// Confirms that you own or are authorized to operate this host.
        #[arg(long)]
        accept_host_owner: bool,
        /// Confirms that this network may expose your public IP as an exit IP.
        #[arg(long)]
        accept_exit_ip: bool,
        /// Enables one finite TCP router mapping after the disclosure is accepted.
        #[arg(long)]
        accept_router_mapping: bool,
        /// Registers the enrolled host as the current user's macOS `LaunchAgent`.
        #[arg(long)]
        install_user_service: bool,
        /// Explicit installed Node Host agent path; defaults to this executable.
        #[arg(long, requires = "install_user_service")]
        agent_binary_path: Option<PathBuf>,
    },
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
    /// Manage the preview current-user macOS background service.
    Service {
        #[command(subcommand)]
        command: ServiceCommand,
    },
}

#[derive(Debug, Subcommand)]
enum ServiceCommand {
    /// Register and start an already-enrolled Node Host.
    Install {
        /// Persistent state directory for the enrolled Node Host.
        #[arg(long)]
        data_dir: PathBuf,
        /// Explicit installed Node Host path; defaults to this executable.
        #[arg(long)]
        agent_binary_path: Option<PathBuf>,
    },
    /// Print safe launchd registration state.
    Status,
    /// Query live service and data-plane state through same-user local IPC.
    LiveStatus {
        /// Persistent state directory for the enrolled Node Host.
        #[arg(long)]
        data_dir: PathBuf,
    },
    /// Stop and unregister the service while retaining identity and state.
    Remove,
}

#[tokio::main]
async fn main() -> Result<()> {
    let status = match Cli::parse().command {
        Command::Bootstrap {
            data_dir,
            invitation_file,
            display_name,
            xray_binary_path,
            xray_sha256,
            accept_host_owner,
            accept_exit_ip,
            accept_router_mapping,
            install_user_service,
            agent_binary_path,
        } => {
            let request = BootstrapRequest::from_invitation_file(
                &invitation_file,
                display_name,
                xray_binary_path,
                xray_sha256,
                accept_host_owner,
                accept_exit_ip,
                accept_router_mapping,
            )?;
            if install_user_service {
                let agent_binary_path = agent_binary_path.map_or_else(std::env::current_exe, Ok)?;
                let outcome = bootstrap_and_install_user_service(
                    &data_dir,
                    request,
                    &UserServiceInstallRequest::new(agent_binary_path),
                )
                .await?;
                print_service_status(&outcome.service);
                outcome.host
            } else {
                bootstrap(&data_dir, request).await?
            }
        }
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
        Command::Service { command } => {
            handle_service_command(command).await?;
            return Ok(());
        }
    };
    print_status(&status);
    Ok(())
}

async fn handle_service_command(command: ServiceCommand) -> Result<()> {
    let service = match command {
        ServiceCommand::Install {
            data_dir,
            agent_binary_path,
        } => {
            let agent_binary_path = agent_binary_path.map_or_else(std::env::current_exe, Ok)?;
            install_user_service(
                &data_dir,
                &UserServiceInstallRequest::new(agent_binary_path),
            )
            .await?
        }
        ServiceCommand::Status => user_service_status().await?,
        ServiceCommand::LiveStatus { data_dir } => {
            let status = query_local_service_status(&data_dir).await?;
            print_local_service_status(&status);
            return Ok(());
        }
        ServiceCommand::Remove => remove_user_service().await?,
    };
    print_service_status(&service);
    Ok(())
}

fn print_local_service_status(status: &LocalServiceStatus) {
    println!("local_schema_version: {}", status.schema_version);
    println!("service_instance_id: {}", status.service_instance_id);
    println!("observed_at: {}", status.observed_at);
    println!("service_phase: {}", status.phase);
    println!("node_id: {}", status.node_id);
    println!(
        "runtime_state: {}",
        runtime_state_name(status.runtime_state)
    );
    match status.last_sync_at {
        Some(timestamp) => println!("last_sync_at: {timestamp}"),
        None => println!("last_sync_at: none"),
    }
    match status.applied_revision {
        Some(revision) => println!("applied_revision: {}", revision.get()),
        None => println!("applied_revision: none"),
    }
    match &status.last_error {
        Some(error) => println!("last_error: {} at {}", error.code, error.occurred_at),
        None => println!("last_error: none"),
    }
}

const fn runtime_state_name(state: NodeRuntimeState) -> &'static str {
    match state {
        NodeRuntimeState::Pending => "pending",
        NodeRuntimeState::Idle => "idle",
        NodeRuntimeState::Serving => "serving",
        NodeRuntimeState::ProviderPaused => "providerPaused",
        NodeRuntimeState::Degraded => "degraded",
        NodeRuntimeState::Quarantined => "quarantined",
        NodeRuntimeState::Stopped => "stopped",
    }
}

fn print_service_status(status: &BackgroundServiceStatus) {
    println!("service_platform: {}", status.platform);
    println!("service_label: {}", status.label);
    println!("service_installed: {}", status.installed);
    println!("service_loaded: {}", status.loaded);
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
    match status.applied_revision {
        Some(revision) => println!("applied_revision: {}", revision.get()),
        None => println!("applied_revision: none"),
    }
    match &status.xray_activation_phase {
        Some(phase) => println!("xray_activation_phase: {phase}"),
        None => println!("xray_activation_phase: none"),
    }
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
    println!(
        "router_mapping: {} ({:?})",
        status.router_mapping.enabled, status.router_mapping.state
    );
}
