use std::{
    collections::HashSet,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    time::Duration,
};

use control_protocol::{crypto::Ed25519PublicKey, id::RelayId};
use serde::Deserialize;
use subtle::ConstantTimeEq;
use time::OffsetDateTime;

use crate::error::{RelayError, Result};

const MIN_FRAME_BYTES: usize = 1_024;
const MAX_FRAME_BYTES: usize = 1_048_576;
const MIN_ROUTE_ID_LEN: usize = 16;
const MAX_ROUTE_ID_LEN: usize = 128;
const MAX_MANAGED_ROUTES: usize = 8_192;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RelayConfig {
    pub server: ServerConfig,
    #[serde(default)]
    pub managed_routes: Option<ManagedRoutesConfig>,
    #[serde(default)]
    pub routes: Vec<RouteConfig>,
}

/// Immutable controller-managed route registry settings.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ManagedRoutesConfig {
    pub relay_id: RelayId,
    pub managed_routes_directory: PathBuf,
    pub quota_state_directory: PathBuf,
    pub controller_public_key: Ed25519PublicKey,
    pub public_listen_ip: IpAddr,
    pub public_port_start: u16,
    pub public_port_end: u16,
    pub max_concurrent_streams: u16,
    pub max_bytes_per_second: u64,
    pub max_bytes_per_connection: u64,
    pub monthly_byte_limit: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    pub node_listen: SocketAddr,
    pub metrics_listen: SocketAddr,
    pub tls_cert_path: PathBuf,
    pub tls_key_path: PathBuf,
    pub client_ca_path: PathBuf,
    #[serde(default = "default_max_frame_bytes")]
    pub max_frame_bytes: usize,
    #[serde(default = "default_command_queue_frames")]
    pub command_queue_frames: usize,
    #[serde(default = "default_stream_buffer_frames")]
    pub stream_buffer_frames: usize,
    #[serde(default = "default_initial_window_bytes")]
    pub initial_window_bytes: u32,
    #[serde(default = "default_open_timeout_secs")]
    pub open_timeout_secs: u64,
    #[serde(default = "default_no_payload_timeout_secs")]
    pub no_payload_timeout_secs: u64,
    #[serde(default = "default_idle_timeout_secs")]
    pub idle_timeout_secs: u64,
    #[serde(default = "default_heartbeat_interval_secs")]
    pub heartbeat_interval_secs: u64,
    #[serde(default = "default_heartbeat_timeout_secs")]
    pub heartbeat_timeout_secs: u64,
    #[serde(default = "default_reload_interval_secs")]
    pub reload_interval_secs: u64,
    #[serde(default = "default_max_routes")]
    pub max_routes: usize,
    #[serde(default = "default_max_node_connections")]
    pub max_node_connections: usize,
}

impl ServerConfig {
    #[must_use]
    pub fn open_timeout(&self) -> Duration {
        Duration::from_secs(self.open_timeout_secs)
    }

    #[must_use]
    pub fn no_payload_timeout(&self) -> Duration {
        Duration::from_secs(self.no_payload_timeout_secs)
    }

    #[must_use]
    pub fn idle_timeout(&self) -> Duration {
        Duration::from_secs(self.idle_timeout_secs)
    }

    #[must_use]
    pub fn heartbeat_interval(&self) -> Duration {
        Duration::from_secs(self.heartbeat_interval_secs)
    }

    #[must_use]
    pub fn heartbeat_timeout(&self) -> Duration {
        Duration::from_secs(self.heartbeat_timeout_secs)
    }

    #[must_use]
    pub fn reload_interval(&self) -> Duration {
        Duration::from_secs(self.reload_interval_secs)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RouteConfig {
    pub route_id: String,
    pub public_listen: SocketAddr,
    pub node_token_sha256: String,
    pub node_cert_sha256: String,
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: OffsetDateTime,
    #[serde(default = "default_route_enabled")]
    pub enabled: bool,
    #[serde(default = "default_max_concurrent_streams")]
    pub max_concurrent_streams: usize,
    #[serde(default = "default_max_bytes_per_second")]
    pub max_bytes_per_second: u64,
    #[serde(default = "default_max_bytes_per_connection")]
    pub max_bytes_per_connection: u64,
    /// Finite UTC calendar-month allowance. Controller-managed routes always set this.
    #[serde(default)]
    pub monthly_byte_limit: Option<u64>,
}

impl RouteConfig {
    #[must_use]
    pub fn is_expired(&self, now: OffsetDateTime) -> bool {
        now >= self.expires_at
    }

    #[must_use]
    pub fn token_matches(&self, candidate: &[u8]) -> bool {
        let Ok(expected) = hex::decode(&self.node_token_sha256) else {
            return false;
        };
        expected.ct_eq(candidate).into()
    }

    #[must_use]
    pub fn cert_matches(&self, candidate: &[u8]) -> bool {
        let Ok(expected) = hex::decode(&self.node_cert_sha256) else {
            return false;
        };
        expected.ct_eq(candidate).into()
    }
}

impl RelayConfig {
    /// Loads and validates a relay configuration file.
    ///
    /// # Errors
    ///
    /// Returns an error when the file cannot be read, is not valid UTF-8/TOML, or violates a
    /// bounded-listener, route-identity, timeout, or resource-limit invariant.
    pub async fn load(path: &Path) -> Result<Self> {
        let bytes = tokio::fs::read(path).await.map_err(|error| {
            RelayError::Config(format!("cannot read {}: {error}", path.display()))
        })?;
        let text = std::str::from_utf8(&bytes)
            .map_err(|_| RelayError::Config("configuration is not UTF-8".to_owned()))?;
        let mut config: Self = toml::from_str(text)
            .map_err(|error| RelayError::Config(format!("invalid TOML: {error}")))?;
        let base = path.parent().unwrap_or_else(|| Path::new("."));
        for candidate in [
            &mut config.server.tls_cert_path,
            &mut config.server.tls_key_path,
            &mut config.server.client_ca_path,
        ] {
            if candidate.is_relative() {
                *candidate = base.join(&*candidate);
            }
        }
        if let Some(managed) = &mut config.managed_routes {
            if managed.managed_routes_directory.is_relative() {
                managed.managed_routes_directory = base.join(&managed.managed_routes_directory);
            }
            if managed.quota_state_directory.is_relative() {
                managed.quota_state_directory = base.join(&managed.quota_state_directory);
            }
        }
        config.validate()?;
        Ok(config)
    }

    /// Validates all static and per-route safety bounds.
    ///
    /// # Errors
    ///
    /// Returns an error for unknown/duplicate identities, listener conflicts, malformed digests,
    /// public metrics binding, unbounded queues, or inconsistent limits and timeouts.
    pub fn validate(&self) -> Result<()> {
        let server = &self.server;
        if self.routes.len() > server.max_routes {
            return Err(RelayError::Config(
                "route count exceeds max_routes".to_owned(),
            ));
        }
        if !(MIN_FRAME_BYTES..=MAX_FRAME_BYTES).contains(&server.max_frame_bytes) {
            return Err(RelayError::Config(format!(
                "max_frame_bytes must be between {MIN_FRAME_BYTES} and {MAX_FRAME_BYTES}"
            )));
        }
        if server.command_queue_frames == 0 || server.stream_buffer_frames == 0 {
            return Err(RelayError::Config(
                "frame queue capacities must be non-zero".to_owned(),
            ));
        }
        if server.initial_window_bytes == 0
            || usize::try_from(server.initial_window_bytes)
                .map_or(true, |window| window < server.max_frame_bytes)
        {
            return Err(RelayError::Config(
                "initial_window_bytes must fit at least one maximum frame".to_owned(),
            ));
        }
        if server.open_timeout_secs == 0
            || server.no_payload_timeout_secs == 0
            || server.idle_timeout_secs < server.no_payload_timeout_secs
            || server.heartbeat_interval_secs == 0
            || server.heartbeat_timeout_secs <= server.heartbeat_interval_secs
            || server.reload_interval_secs == 0
            || server.max_routes == 0
            || server.max_node_connections == 0
        {
            return Err(RelayError::Config(
                "timeouts, reload interval, and max_routes are inconsistent".to_owned(),
            ));
        }
        if !server.metrics_listen.ip().is_loopback() {
            return Err(RelayError::Config(
                "metrics_listen must use a loopback address".to_owned(),
            ));
        }

        if let Some(managed) = &self.managed_routes {
            if server.max_routes > MAX_MANAGED_ROUTES {
                return Err(RelayError::Config(format!(
                    "managed max_routes must not exceed {MAX_MANAGED_ROUTES}"
                )));
            }
            if managed.public_port_start == 0
                || managed.public_port_start > managed.public_port_end
                || managed.max_concurrent_streams == 0
                || managed.max_bytes_per_second < u64::from(server.initial_window_bytes)
                || managed.max_bytes_per_connection < u64::from(server.initial_window_bytes)
                || managed.monthly_byte_limit < u64::from(server.initial_window_bytes)
            {
                return Err(RelayError::Config(
                    "managed route bounds are inconsistent".to_owned(),
                ));
            }
            if managed.managed_routes_directory == managed.quota_state_directory {
                return Err(RelayError::Config(
                    "managed route registry and quota state directories must be distinct"
                        .to_owned(),
                ));
            }
            for address in [server.node_listen, server.metrics_listen] {
                if address.ip() == managed.public_listen_ip
                    && (managed.public_port_start..=managed.public_port_end)
                        .contains(&address.port())
                {
                    return Err(RelayError::Config(
                        "managed public port range conflicts with a service listener".to_owned(),
                    ));
                }
            }
        }

        if self.managed_routes.is_none()
            && self
                .routes
                .iter()
                .any(|route| route.monthly_byte_limit.is_some())
        {
            return Err(RelayError::Config(
                "finite monthly route limits require managed quota state".to_owned(),
            ));
        }

        self.validate_routes(&self.routes)
    }

    pub(crate) fn validate_routes(&self, routes: &[RouteConfig]) -> Result<()> {
        if routes.len() > self.server.max_routes {
            return Err(RelayError::Config(
                "route count exceeds max_routes".to_owned(),
            ));
        }
        let mut route_ids = HashSet::new();
        let mut public_addresses = HashSet::new();
        for route in routes {
            validate_route_id(&route.route_id)?;
            validate_digest("node_token_sha256", &route.node_token_sha256)?;
            validate_digest("node_cert_sha256", &route.node_cert_sha256)?;
            if !route_ids.insert(route.route_id.as_str()) {
                return Err(RelayError::Config("duplicate route_id".to_owned()));
            }
            if !public_addresses.insert(route.public_listen) {
                return Err(RelayError::Config("duplicate public_listen".to_owned()));
            }
            if route.public_listen.port() != 0
                && (route.public_listen == self.server.node_listen
                    || route.public_listen == self.server.metrics_listen)
            {
                return Err(RelayError::Config(
                    "public listener conflicts with a service listener".to_owned(),
                ));
            }
            if route.max_concurrent_streams == 0
                || route.max_bytes_per_second < u64::from(self.server.initial_window_bytes)
                || route.max_bytes_per_connection < u64::from(self.server.initial_window_bytes)
                || route
                    .monthly_byte_limit
                    .is_some_and(|limit| limit < u64::from(self.server.initial_window_bytes))
            {
                return Err(RelayError::Config(
                    "route limits must be non-zero and at least initial_window_bytes".to_owned(),
                ));
            }
        }
        Ok(())
    }
}

fn validate_route_id(route_id: &str) -> Result<()> {
    if !(MIN_ROUTE_ID_LEN..=MAX_ROUTE_ID_LEN).contains(&route_id.len())
        || !route_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err(RelayError::Config(
            "route_id must be 16-128 ASCII URL-safe characters".to_owned(),
        ));
    }
    Ok(())
}

fn validate_digest(name: &str, value: &str) -> Result<()> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(RelayError::Config(format!(
            "{name} must be a 32-byte lowercase or uppercase hexadecimal digest"
        )));
    }
    Ok(())
}

const fn default_max_frame_bytes() -> usize {
    65_536
}
const fn default_command_queue_frames() -> usize {
    256
}
const fn default_stream_buffer_frames() -> usize {
    16
}
const fn default_initial_window_bytes() -> u32 {
    262_144
}
const fn default_open_timeout_secs() -> u64 {
    10
}
const fn default_no_payload_timeout_secs() -> u64 {
    120
}
const fn default_idle_timeout_secs() -> u64 {
    1_800
}
const fn default_heartbeat_interval_secs() -> u64 {
    15
}
const fn default_heartbeat_timeout_secs() -> u64 {
    45
}
const fn default_reload_interval_secs() -> u64 {
    2
}
const fn default_max_routes() -> usize {
    1_024
}
const fn default_max_node_connections() -> usize {
    1_024
}
const fn default_route_enabled() -> bool {
    true
}
const fn default_max_concurrent_streams() -> usize {
    16
}
const fn default_max_bytes_per_second() -> u64 {
    2_500_000
}
const fn default_max_bytes_per_connection() -> u64 {
    10 * 1024 * 1024 * 1024
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_config() -> RelayConfig {
        RelayConfig {
            server: ServerConfig {
                node_listen: "127.0.0.1:7443".parse().unwrap(),
                metrics_listen: "127.0.0.1:9090".parse().unwrap(),
                tls_cert_path: "server.pem".into(),
                tls_key_path: "server-key.pem".into(),
                client_ca_path: "ca.pem".into(),
                max_frame_bytes: 65_536,
                command_queue_frames: 32,
                stream_buffer_frames: 4,
                initial_window_bytes: 262_144,
                open_timeout_secs: 10,
                no_payload_timeout_secs: 120,
                idle_timeout_secs: 1_800,
                heartbeat_interval_secs: 15,
                heartbeat_timeout_secs: 45,
                reload_interval_secs: 2,
                max_routes: 16,
                max_node_connections: 16,
            },
            managed_routes: None,
            routes: vec![RouteConfig {
                route_id: "route_0123456789abcdef".to_owned(),
                public_listen: "0.0.0.0:24443".parse().unwrap(),
                node_token_sha256: "11".repeat(32),
                node_cert_sha256: "22".repeat(32),
                expires_at: OffsetDateTime::now_utc() + time::Duration::days(1),
                enabled: true,
                max_concurrent_streams: 16,
                max_bytes_per_second: 2_500_000,
                max_bytes_per_connection: 10 * 1024 * 1024 * 1024,
                monthly_byte_limit: None,
            }],
        }
    }

    #[test]
    fn validates_safe_config() {
        valid_config().validate().unwrap();
    }

    #[test]
    fn rejects_duplicate_and_short_routes() {
        let mut config = valid_config();
        config.routes[0].route_id = "short".to_owned();
        assert!(config.validate().is_err());

        let mut config = valid_config();
        config.routes.push(config.routes[0].clone());
        assert!(config.validate().is_err());
    }

    #[test]
    fn compares_auth_material_in_constant_time() {
        let route = &valid_config().routes[0];
        assert!(route.token_matches(&[0x11; 32]));
        assert!(!route.token_matches(&[0x12; 32]));
        assert!(route.cert_matches(&[0x22; 32]));
    }

    #[test]
    fn finite_monthly_limits_require_managed_quota_state() {
        let mut config = valid_config();
        config.routes[0].monthly_byte_limit = Some(1_000_000);
        assert!(config.validate().is_err());
    }

    #[test]
    fn example_server_configuration_stays_valid() {
        let config: RelayConfig = toml::from_str(include_str!("../config.example.toml")).unwrap();
        config.validate().unwrap();
    }
}
