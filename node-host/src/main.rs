use anyhow::Result;
use clap::{Parser, Subcommand};
use control_protocol::node::NodeRuntimeState;
use node_host::{
    bootstrap, bootstrap_and_install_user_service, clear_manual_endpoint,
    configure_manual_endpoint, configure_provider_policy, configure_relay, configure_xray,
    initialize, install_user_service, join, pause_provider, query_local_service_status,
    remove_user_service, resume_provider, revoke_relay, run, status, support_bundle, sync_once,
    uninstall_local, user_service_status, BackgroundServiceStatus, BootstrapRequest, HostStatus,
    LocalServiceStatus, ManualEndpointInput, ProviderPolicy, SyncLoopOptions,
    UserServiceInstallRequest,
};
#[cfg(target_os = "macos")]
use node_host::{SetupInvitation, SystemServiceClient, SystemSetupOperation, SystemSetupOutcome};
use std::fs;
#[cfg(target_os = "macos")]
use std::io::Read as _;
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
    /// Install or rotate one controller-issued relay assignment.
    ConfigureRelay {
        /// Persistent state directory.
        #[arg(long)]
        data_dir: PathBuf,
        /// Owner-only JSON assignment file with owner-only referenced secrets.
        #[arg(long)]
        assignment_file: PathBuf,
        /// Confirms this host may maintain an outbound relay tunnel and serve as an exit node.
        #[arg(long)]
        accept_relay: bool,
        /// Explicitly replace a different active relay assignment.
        #[arg(long)]
        replace: bool,
    },
    /// Revoke this host's assigned relay route and delete its local relay credentials.
    RevokeRelay {
        /// Persistent state directory.
        #[arg(long)]
        data_dir: PathBuf,
        /// Exact active endpoint ID used as destructive-operation confirmation.
        #[arg(long)]
        confirm_endpoint_id: control_protocol::id::EndpointId,
    },
    /// Replace the complete provider-local policy from a closed JSON DTO.
    ConfigureProviderPolicy {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        policy_file: PathBuf,
    },
    /// Immediately stop sharing without deleting enrollment or applied state.
    PauseProvider {
        #[arg(long)]
        data_dir: PathBuf,
    },
    /// Re-enable sharing subject to schedule and quota policy.
    ResumeProvider {
        #[arg(long)]
        data_dir: PathBuf,
    },
    /// Advertise an explicit finite public endpoint for the current revision.
    ConfigureManualEndpoint {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        address: String,
        #[arg(long)]
        public_port: u16,
        #[arg(long)]
        forwarded_local_port: u16,
        #[arg(long, default_value_t = 86_400)]
        ttl_seconds: u32,
    },
    /// Withdraw the provider-owned manual endpoint candidate.
    ClearManualEndpoint {
        #[arg(long)]
        data_dir: PathBuf,
    },
    /// Run the installer-owned macOS `LaunchDaemon` using fixed package paths.
    SystemService,
    /// Control the installed macOS system service through authenticated fixed-path IPC.
    SystemControl {
        #[command(subcommand)]
        command: SystemControlCommand,
    },
    /// Rebind a package-migrated identity to the fixed macOS system layout.
    #[command(hide = true)]
    MigrateSystemLayout,
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
    /// Print an allowlisted JSON support bundle with no credentials or endpoints.
    SupportBundle {
        /// Persistent state directory.
        #[arg(long)]
        data_dir: PathBuf,
    },
    /// Stop the user service and irreversibly remove this node's local state.
    Uninstall {
        /// Persistent state directory.
        #[arg(long)]
        data_dir: PathBuf,
        /// Exact enrolled node ID used as destructive-operation confirmation.
        #[arg(long)]
        confirm_node_id: control_protocol::id::NodeId,
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

#[derive(Debug, Subcommand)]
enum SystemControlCommand {
    /// Print the installed service's secret-free status as JSON.
    Status,
    /// Consume one setup invitation read only from stdin.
    ConfirmSetup {
        #[arg(long)]
        provider_policy_file: PathBuf,
        #[arg(long)]
        accept_host_owner: bool,
        #[arg(long)]
        accept_exit_ip: bool,
        #[arg(long)]
        accept_router_mapping: bool,
        #[arg(long)]
        accept_relay: bool,
    },
    /// Replace the complete provider-local policy from a closed JSON DTO.
    UpdateProviderPolicy {
        #[arg(long)]
        provider_policy_file: PathBuf,
    },
    /// Immediately withdraw every shared data path.
    Pause,
    /// Resume sharing subject to the provider-owned policy.
    Resume,
    /// Publish one finite explicit direct endpoint candidate.
    ConfigureManualEndpoint {
        #[arg(long)]
        address: String,
        #[arg(long)]
        public_port: u16,
        #[arg(long)]
        forwarded_local_port: u16,
        #[arg(long, default_value_t = 86_400)]
        ttl_seconds: u32,
    },
    /// Withdraw the provider-owned manual endpoint candidate.
    ClearManualEndpoint,
    /// Stop every live data path and remove enrollment with exact-ID confirmation.
    Unpair {
        #[arg(long)]
        confirm_node_id: control_protocol::id::NodeId,
    },
}

#[tokio::main]
#[allow(clippy::too_many_lines)]
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
        Command::ConfigureRelay {
            data_dir,
            assignment_file,
            accept_relay,
            replace,
        } => {
            configure_relay(&data_dir, &assignment_file, accept_relay, replace).await?;
            status(&data_dir)?
        }
        Command::RevokeRelay {
            data_dir,
            confirm_endpoint_id,
        } => {
            revoke_relay(&data_dir, confirm_endpoint_id)?;
            status(&data_dir)?
        }
        Command::ConfigureProviderPolicy {
            data_dir,
            policy_file,
        } => {
            let policy = load_provider_policy(&policy_file)?;
            configure_provider_policy(&data_dir, &policy)?;
            status(&data_dir)?
        }
        Command::PauseProvider { data_dir } => {
            pause_provider(&data_dir)?;
            status(&data_dir)?
        }
        Command::ResumeProvider { data_dir } => {
            resume_provider(&data_dir)?;
            status(&data_dir)?
        }
        Command::ConfigureManualEndpoint {
            data_dir,
            address,
            public_port,
            forwarded_local_port,
            ttl_seconds,
        } => {
            configure_manual_endpoint(
                &data_dir,
                &ManualEndpointInput {
                    address,
                    public_port,
                    forwarded_local_port,
                    ttl_seconds,
                },
            )?;
            status(&data_dir)?
        }
        Command::ClearManualEndpoint { data_dir } => {
            clear_manual_endpoint(&data_dir)?;
            status(&data_dir)?
        }
        Command::SystemService => {
            init_logging();
            #[cfg(target_os = "macos")]
            node_host::run_system_service().await?;
            #[cfg(not(target_os = "macos"))]
            anyhow::bail!("system-service is supported only by the macOS package");
            return Ok(());
        }
        Command::SystemControl { command } => {
            #[cfg(target_os = "macos")]
            handle_system_control(command).await?;
            #[cfg(not(target_os = "macos"))]
            {
                let _ = command;
                anyhow::bail!("system-control is supported only by the macOS package");
            }
            return Ok(());
        }
        Command::MigrateSystemLayout => {
            #[cfg(target_os = "macos")]
            node_host::migrate_system_layout_binding()?;
            #[cfg(not(target_os = "macos"))]
            anyhow::bail!("system layout migration is supported only by the macOS package");
            return Ok(());
        }
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
        Command::SupportBundle { data_dir } => {
            println!(
                "{}",
                serde_json::to_string_pretty(&support_bundle(&data_dir)?)?
            );
            return Ok(());
        }
        Command::Uninstall {
            data_dir,
            confirm_node_id,
        } => {
            let _ = remove_user_service().await?;
            uninstall_local(&data_dir, confirm_node_id)?;
            println!("uninstalled_node_id: {confirm_node_id}");
            return Ok(());
        }
    };
    print_status(&status);
    Ok(())
}

fn load_provider_policy(path: &std::path::Path) -> Result<ProviderPolicy> {
    let bytes = fs::read(path)?;
    if bytes.is_empty() || bytes.len() > 64 * 1024 {
        anyhow::bail!("provider policy file must contain between 1 and 65536 bytes");
    }
    Ok(serde_json::from_slice(&bytes)?)
}

#[cfg(target_os = "macos")]
async fn handle_system_control(command: SystemControlCommand) -> Result<()> {
    let operation = match command {
        SystemControlCommand::Status => SystemSetupOperation::Status {},
        SystemControlCommand::ConfirmSetup {
            provider_policy_file,
            accept_host_owner,
            accept_exit_ip,
            accept_router_mapping,
            accept_relay,
        } => {
            let mut invitation = String::new();
            std::io::stdin()
                .take(32 * 1024 + 1)
                .read_to_string(&mut invitation)?;
            while invitation.ends_with('\r') || invitation.ends_with('\n') {
                invitation.pop();
            }
            if invitation.is_empty() || invitation.len() > 32 * 1024 {
                zeroize::Zeroize::zeroize(&mut invitation);
                anyhow::bail!("setup invitation stdin length is invalid");
            }
            SystemSetupOperation::ConfirmSetup {
                setup_invitation: SetupInvitation::new(invitation),
                accept_host_owner,
                accept_exit_ip,
                accept_router_mapping,
                accept_relay,
                provider_policy: load_provider_policy(&provider_policy_file)?,
            }
        }
        SystemControlCommand::UpdateProviderPolicy {
            provider_policy_file,
        } => SystemSetupOperation::UpdateProviderPolicy {
            provider_policy: load_provider_policy(&provider_policy_file)?,
        },
        SystemControlCommand::Pause => SystemSetupOperation::Pause {},
        SystemControlCommand::Resume => SystemSetupOperation::Resume {},
        SystemControlCommand::ConfigureManualEndpoint {
            address,
            public_port,
            forwarded_local_port,
            ttl_seconds,
        } => SystemSetupOperation::ConfigureManualEndpoint {
            endpoint: ManualEndpointInput {
                address,
                public_port,
                forwarded_local_port,
                ttl_seconds,
            },
        },
        SystemControlCommand::ClearManualEndpoint => SystemSetupOperation::ClearManualEndpoint {},
        SystemControlCommand::Unpair { confirm_node_id } => {
            SystemSetupOperation::Unpair { confirm_node_id }
        }
    };
    let response = SystemServiceClient::production()?
        .request(operation)
        .await?;
    let failed = matches!(response.outcome, SystemSetupOutcome::Error { .. });
    println!("{}", serde_json::to_string_pretty(&response)?);
    if failed {
        anyhow::bail!("installed Node Host service rejected the operation");
    }
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
    print_controller_status(status.controller_status.as_ref());
    match status.applied_revision {
        Some(revision) => println!("applied_revision: {}", revision.get()),
        None => println!("applied_revision: none"),
    }
    match &status.last_error {
        Some(error) => println!("last_error: {} at {}", error.code, error.occurred_at),
        None => println!("last_error: none"),
    }
    println!("relay_runtime: {:?}", status.relay_runtime);
    println!(
        "provider_availability: {:?}",
        status.provider_policy.availability
    );
    println!(
        "admission_active_sessions: {}",
        status.admission.active_sessions
    );
    println!(
        "admission_rejected_session_limit: {}",
        status.admission.rejected_session_limit
    );
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
    print_controller_status(status.controller_status.as_ref());
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
    println!("relay_assignment: {:?}", status.relay.state);
    match status.relay.endpoint_id {
        Some(endpoint_id) => println!("relay_endpoint_id: {endpoint_id}"),
        None => println!("relay_endpoint_id: none"),
    }
    println!(
        "provider_availability: {:?}",
        status.provider_policy.availability
    );
    println!("provider_paused: {}", status.provider_policy.policy.paused);
    println!(
        "provider_month_usage: {} {} ({})",
        status.provider_policy.month_usage.utc_month,
        status.provider_policy.month_usage.observed_bytes,
        status.provider_policy.month_usage.coverage
    );
    println!(
        "manual_endpoint: configured={} current={}",
        status.provider_policy.manual_endpoint.configured,
        status.provider_policy.manual_endpoint.current
    );
}

fn print_controller_status(status: Option<&control_protocol::node::NodeHeartbeatStatus>) {
    let Some(status) = status else {
        println!("controller_status: unknown");
        return;
    };
    println!("controller_lifecycle: {}", status.lifecycle.as_str());
    println!(
        "controller_status_generation: {}",
        status.heartbeat_generation.get()
    );
    for endpoint in &status.endpoints {
        println!(
            "controller_endpoint: {} {}",
            endpoint.endpoint_id,
            endpoint.readiness.as_str()
        );
    }
}

#[cfg(test)]
mod cli_tests {
    use super::*;

    #[test]
    fn system_control_exposes_only_closed_subcommands() {
        assert!(Cli::try_parse_from(["node-host", "system-control", "status"]).is_ok());
        assert!(
            Cli::try_parse_from(["node-host", "system-control", "raw", "--method", "exec"])
                .is_err()
        );
    }

    #[test]
    fn setup_invitation_has_no_command_line_argument() {
        assert!(Cli::try_parse_from([
            "node-host",
            "system-control",
            "confirm-setup",
            "--provider-policy-file",
            "/tmp/policy.json",
            "--accept-host-owner",
            "--accept-exit-ip",
        ])
        .is_ok());
        assert!(Cli::try_parse_from([
            "node-host",
            "system-control",
            "confirm-setup",
            "--provider-policy-file",
            "/tmp/policy.json",
            "--setup-invitation",
            "secret",
        ])
        .is_err());
    }
}
