use anyhow::Result;
use clap::{Parser, Subcommand};
use node_host::{initialize, status, HostStatus};
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
    /// Print non-secret local status.
    Status {
        /// Persistent state directory.
        #[arg(long)]
        data_dir: PathBuf,
    },
}

fn main() -> Result<()> {
    let status = match Cli::parse().command {
        Command::Init {
            data_dir,
            controller,
        } => initialize(&data_dir, &controller)?,
        Command::Status { data_dir } => status(&data_dir)?,
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
}
