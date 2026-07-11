use crate::auth::{BootstrapTokenError, BootstrapTokenVerifier};
use std::env;
use std::net::{AddrParseError, SocketAddr};
use std::path::PathBuf;
use std::time::Duration;
use thiserror::Error;

const DEFAULT_BIND_ADDRESS: &str = "127.0.0.1:8787";
const DEFAULT_DATABASE_PATH: &str = "data/control-service.sqlite3";
const DEFAULT_NETWORK_NAME: &str = "Private Network";
const DEFAULT_TIMEOUT_SECONDS: u64 = 10;

#[derive(Clone, Debug)]
pub struct ServiceConfig {
    pub bind_address: SocketAddr,
    pub database_path: PathBuf,
    pub network_display_name: String,
    pub bootstrap_token: BootstrapTokenVerifier,
    pub request_timeout: Duration,
}

impl ServiceConfig {
    /// Loads and validates service configuration from `CONTROL_*` variables.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] when a required variable is absent or any
    /// configured value violates the service bounds.
    pub fn from_env() -> Result<Self, ConfigError> {
        let bind_address = env::var("CONTROL_BIND_ADDRESS")
            .unwrap_or_else(|_| DEFAULT_BIND_ADDRESS.to_string())
            .parse()?;
        let database_path = env::var("CONTROL_DATABASE_PATH")
            .map_or_else(|_| PathBuf::from(DEFAULT_DATABASE_PATH), PathBuf::from);
        let network_display_name =
            env::var("CONTROL_NETWORK_NAME").unwrap_or_else(|_| DEFAULT_NETWORK_NAME.to_string());
        validate_network_name(&network_display_name)?;

        let raw_token =
            env::var("CONTROL_BOOTSTRAP_TOKEN").map_err(|_| ConfigError::MissingBootstrapToken)?;
        let bootstrap_token = BootstrapTokenVerifier::new(&raw_token)?;
        drop(raw_token);

        let request_timeout_seconds = env::var("CONTROL_REQUEST_TIMEOUT_SECONDS")
            .map_or(Ok(DEFAULT_TIMEOUT_SECONDS), |value| value.parse())?;
        if !(1..=60).contains(&request_timeout_seconds) {
            return Err(ConfigError::InvalidTimeout);
        }

        Ok(Self {
            bind_address,
            database_path,
            network_display_name,
            bootstrap_token,
            request_timeout: Duration::from_secs(request_timeout_seconds),
        })
    }

    /// Creates deterministic non-secret defaults for integration tests.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] when the supplied bootstrap token is invalid.
    pub fn for_test(database_path: PathBuf, bootstrap_token: &str) -> Result<Self, ConfigError> {
        Ok(Self {
            bind_address: DEFAULT_BIND_ADDRESS.parse()?,
            database_path,
            network_display_name: DEFAULT_NETWORK_NAME.to_string(),
            bootstrap_token: BootstrapTokenVerifier::new(bootstrap_token)?,
            request_timeout: Duration::from_secs(DEFAULT_TIMEOUT_SECONDS),
        })
    }
}

/// Validates the durable display-name bounds used by the database schema.
///
/// # Errors
///
/// Returns [`ConfigError::InvalidNetworkName`] for empty, untrimmed, or
/// overlong names.
pub fn validate_network_name(value: &str) -> Result<(), ConfigError> {
    let length = value.chars().count();
    if !(1..=128).contains(&length) || value.trim() != value {
        return Err(ConfigError::InvalidNetworkName);
    }
    Ok(())
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("CONTROL_BOOTSTRAP_TOKEN is required")]
    MissingBootstrapToken,
    #[error(transparent)]
    InvalidBootstrapToken(#[from] BootstrapTokenError),
    #[error("CONTROL_BIND_ADDRESS is invalid")]
    InvalidBindAddress(#[from] AddrParseError),
    #[error("CONTROL_REQUEST_TIMEOUT_SECONDS must be an integer")]
    InvalidTimeoutNumber(#[from] std::num::ParseIntError),
    #[error("CONTROL_REQUEST_TIMEOUT_SECONDS must be between 1 and 60")]
    InvalidTimeout,
    #[error("CONTROL_NETWORK_NAME must be trimmed and contain 1 to 128 characters")]
    InvalidNetworkName,
}
