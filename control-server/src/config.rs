use crate::auth::{BootstrapTokenError, BootstrapTokenVerifier};
use crate::probe::{
    ProbeMode, RemoteTcpProbeConfig, RemoteTcpProbeConfigError, TcpProbeLoopOptions,
};
use crate::protocol_canary::{CanaryConfigError, ProtocolCanaryConfig, ProtocolCanaryLoopOptions};
use std::env;
use std::net::{AddrParseError, SocketAddr};
use std::path::PathBuf;
use std::time::Duration;
use thiserror::Error;
use url::{Host, Url};

const DEFAULT_BIND_ADDRESS: &str = "127.0.0.1:8787";
const DEFAULT_DATABASE_PATH: &str = "data/control-service.sqlite3";
const DEFAULT_NETWORK_NAME: &str = "Private Network";
const DEFAULT_TIMEOUT_SECONDS: u64 = 10;
const DEFAULT_TEST_CONTROLLER_ORIGIN: &str = "https://control.test";

#[derive(Clone, Debug)]
pub struct ServiceConfig {
    pub bind_address: SocketAddr,
    pub database_path: PathBuf,
    pub network_display_name: String,
    pub bootstrap_token: BootstrapTokenVerifier,
    pub controller_origin: String,
    pub request_timeout: Duration,
    pub probe_mode: ProbeMode,
    pub probe_options: TcpProbeLoopOptions,
    pub remote_probe: Option<RemoteTcpProbeConfig>,
    pub protocol_canary: Option<ProtocolCanaryConfig>,
    pub protocol_canary_options: ProtocolCanaryLoopOptions,
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

        let controller_origin = normalize_controller_origin(
            &env::var("CONTROL_PUBLIC_ORIGIN").map_err(|_| ConfigError::MissingControllerOrigin)?,
        )?;

        let request_timeout_seconds = env::var("CONTROL_REQUEST_TIMEOUT_SECONDS")
            .map_or(Ok(DEFAULT_TIMEOUT_SECONDS), |value| value.parse())?;
        if !(1..=60).contains(&request_timeout_seconds) {
            return Err(ConfigError::InvalidTimeout);
        }
        let probe_mode = env::var("CONTROL_PROBE_MODE")
            .map_or(Ok(ProbeMode::Disabled), |value| value.parse())
            .map_err(|_| ConfigError::InvalidProbeMode)?;
        let remote_url = optional_env("CONTROL_TCP_PROBE_URL")?;
        let remote_token = optional_env("CONTROL_TCP_PROBE_TOKEN")?;
        let remote_probe = build_remote_probe_config(probe_mode, remote_url, remote_token)?;
        let canary_path = optional_env("CONTROL_PROTOCOL_CANARY_XRAY_PATH")?;
        let canary_sha256 = optional_env("CONTROL_PROTOCOL_CANARY_XRAY_SHA256")?;
        let protocol_canary = build_protocol_canary_config(canary_path, canary_sha256)?;

        Ok(Self {
            bind_address,
            database_path,
            network_display_name,
            bootstrap_token,
            controller_origin,
            request_timeout: Duration::from_secs(request_timeout_seconds),
            probe_mode,
            probe_options: TcpProbeLoopOptions::default(),
            remote_probe,
            protocol_canary,
            protocol_canary_options: ProtocolCanaryLoopOptions::default(),
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
            controller_origin: DEFAULT_TEST_CONTROLLER_ORIGIN.to_string(),
            request_timeout: Duration::from_secs(DEFAULT_TIMEOUT_SECONDS),
            probe_mode: ProbeMode::Disabled,
            probe_options: TcpProbeLoopOptions::default(),
            remote_probe: None,
            protocol_canary: None,
            protocol_canary_options: ProtocolCanaryLoopOptions::default(),
        })
    }
}

fn build_protocol_canary_config(
    path: Option<String>,
    sha256: Option<String>,
) -> Result<Option<ProtocolCanaryConfig>, ConfigError> {
    match (path, sha256) {
        (None, None) => Ok(None),
        (Some(path), Some(sha256)) => Ok(Some(ProtocolCanaryConfig::new(
            PathBuf::from(path),
            sha256,
        )?)),
        _ => Err(ConfigError::IncompleteProtocolCanary),
    }
}

fn optional_env(name: &'static str) -> Result<Option<String>, ConfigError> {
    match env::var(name) {
        Ok(value) => Ok(Some(value)),
        Err(env::VarError::NotPresent) => Ok(None),
        Err(env::VarError::NotUnicode(_)) => Err(ConfigError::InvalidEnvironment(name)),
    }
}

fn build_remote_probe_config(
    mode: ProbeMode,
    url: Option<String>,
    token: Option<String>,
) -> Result<Option<RemoteTcpProbeConfig>, ConfigError> {
    match (mode, url, token) {
        (ProbeMode::RemoteHttp, Some(url), Some(token)) => {
            Ok(Some(RemoteTcpProbeConfig::new(&url, token)?))
        }
        (ProbeMode::RemoteHttp, None, _) => Err(ConfigError::MissingRemoteProbeUrl),
        (ProbeMode::RemoteHttp, _, None) => Err(ConfigError::MissingRemoteProbeToken),
        (_, None, None) => Ok(None),
        _ => Err(ConfigError::RemoteProbeSettingsWithoutMode),
    }
}

/// Validates and canonicalizes the externally reachable controller origin.
///
/// # Errors
///
/// Returns [`ConfigError::InvalidControllerOrigin`] unless `value` is an
/// HTTP(S) origin without credentials, path, query, or fragment.
pub fn normalize_controller_origin(value: &str) -> Result<String, ConfigError> {
    let parsed = Url::parse(value).map_err(|_| ConfigError::InvalidControllerOrigin)?;
    let loopback_http = parsed.scheme() == "http"
        && match parsed.host() {
            Some(Host::Ipv4(address)) => address.is_loopback(),
            Some(Host::Ipv6(address)) => address.is_loopback(),
            Some(Host::Domain(domain)) => domain == "localhost",
            None => false,
        };
    if (!loopback_http && parsed.scheme() != "https")
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || !matches!(parsed.path(), "" | "/")
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(ConfigError::InvalidControllerOrigin);
    }
    Ok(parsed.origin().ascii_serialization())
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
    #[error("CONTROL_PUBLIC_ORIGIN is required")]
    MissingControllerOrigin,
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
    #[error("CONTROL_PUBLIC_ORIGIN must be an HTTP(S) origin without credentials or a path")]
    InvalidControllerOrigin,
    #[error("CONTROL_PROBE_MODE must be disabled, local-tcp, or remote-http")]
    InvalidProbeMode,
    #[error("{0} must contain valid UTF-8")]
    InvalidEnvironment(&'static str),
    #[error("CONTROL_TCP_PROBE_URL is required for remote-http mode")]
    MissingRemoteProbeUrl,
    #[error("CONTROL_TCP_PROBE_TOKEN is required for remote-http mode")]
    MissingRemoteProbeToken,
    #[error("CONTROL_TCP_PROBE_URL and CONTROL_TCP_PROBE_TOKEN require remote-http mode")]
    RemoteProbeSettingsWithoutMode,
    #[error(transparent)]
    InvalidRemoteProbe(#[from] RemoteTcpProbeConfigError),
    #[error("CONTROL_PROTOCOL_CANARY_XRAY_PATH and CONTROL_PROTOCOL_CANARY_XRAY_SHA256 must be set together")]
    IncompleteProtocolCanary,
    #[error(transparent)]
    InvalidProtocolCanary(#[from] CanaryConfigError),
}

#[cfg(test)]
mod tests {
    use super::{build_remote_probe_config, normalize_controller_origin, ConfigError};
    use crate::probe::ProbeMode;

    const TOKEN: &str = "remote-config-test-token-with-at-least-32-bytes";

    #[test]
    fn controller_origin_is_strict_and_canonical() {
        assert_eq!(
            normalize_controller_origin("https://control.example:8443/").unwrap(),
            "https://control.example:8443"
        );
        assert!(normalize_controller_origin("https://control.example/path").is_err());
        assert!(normalize_controller_origin("https://user@control.example").is_err());
        assert!(normalize_controller_origin("ftp://control.example").is_err());
        assert!(normalize_controller_origin("http://control.example").is_err());
        assert!(normalize_controller_origin("http://localhost.evil").is_err());
        assert_eq!(
            normalize_controller_origin("http://127.0.0.1:8787").unwrap(),
            "http://127.0.0.1:8787"
        );
        assert_eq!(
            normalize_controller_origin("http://[::1]:8787/").unwrap(),
            "http://[::1]:8787"
        );
    }

    #[test]
    fn remote_probe_settings_are_complete_and_mode_scoped() {
        assert!(build_remote_probe_config(ProbeMode::Disabled, None, None)
            .unwrap()
            .is_none());
        assert!(build_remote_probe_config(
            ProbeMode::RemoteHttp,
            Some("https://probe.example/v1/tcp-probe".to_string()),
            Some(TOKEN.to_string())
        )
        .unwrap()
        .is_some());
        assert!(matches!(
            build_remote_probe_config(ProbeMode::RemoteHttp, None, Some(TOKEN.to_string())),
            Err(ConfigError::MissingRemoteProbeUrl)
        ));
        assert!(matches!(
            build_remote_probe_config(
                ProbeMode::RemoteHttp,
                Some("https://probe.example/v1/tcp-probe".to_string()),
                None
            ),
            Err(ConfigError::MissingRemoteProbeToken)
        ));
        assert!(matches!(
            build_remote_probe_config(
                ProbeMode::Disabled,
                Some("https://probe.example/v1/tcp-probe".to_string()),
                Some(TOKEN.to_string())
            ),
            Err(ConfigError::RemoteProbeSettingsWithoutMode)
        ));
    }
}
