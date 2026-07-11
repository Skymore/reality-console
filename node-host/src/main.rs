use anyhow::Result;
use clap::{Parser, Subcommand};
use node_host::{initialize, join, status, sync_once, HostStatus};
use std::path::PathBuf;

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
    };
    print_status(&status);
    Ok(())
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
}
