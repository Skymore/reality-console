//! Standalone HTTP control service.

pub mod auth;
pub mod config;
pub mod db;
mod desired;
pub mod error;
pub mod http;
pub mod identity;
pub mod probe;
pub mod protocol;

pub use config::ServiceConfig;
pub use db::Database;
pub use http::{build_router, AppState};
pub use probe::{ProbeMode, RemoteTcpProbeConfig, TcpProbeLoopOptions};
