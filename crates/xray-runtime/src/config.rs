use std::{
    collections::HashSet,
    fmt,
    net::{IpAddr, Ipv4Addr, SocketAddrV4},
};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::Serialize;
use thiserror::Error;
use uuid::Uuid;
use zeroize::Zeroizing;

const MAX_SERVER_NAMES: usize = 16;
const MAX_SHORT_IDS: usize = 32;
const MAX_USERS: usize = 10_000;
const MIN_SHORT_ID_HEX_LENGTH: usize = 8;
const MAX_SHORT_ID_HEX_LENGTH: usize = 16;

/// A validated DNS name accepted by REALITY as an SNI value.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ServerName(String);

impl ServerName {
    /// Parses and canonicalizes an ASCII DNS name.
    ///
    /// Names must be fully qualified, may not be IP addresses or wildcards, and
    /// are normalized to lowercase without a trailing dot.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigBuildError::InvalidServerName`] when the value is not a
    /// safe public-style DNS name.
    pub fn parse(value: &str) -> Result<Self, ConfigBuildError> {
        validate_dns_name(value).map(Self)
    }

    /// Returns the canonical DNS name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ServerName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("ServerName").field(&self.0).finish()
    }
}

/// A validated REALITY forwarding target.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RealityTarget {
    host: ServerName,
    port: u16,
}

impl RealityTarget {
    /// Creates a target from a DNS host and non-zero port.
    ///
    /// # Errors
    ///
    /// Returns an error when the host is invalid or the port is zero.
    pub fn new(host: &str, port: u16) -> Result<Self, ConfigBuildError> {
        if port == 0 {
            return Err(ConfigBuildError::InvalidTargetPort);
        }
        Ok(Self {
            host: ServerName::parse(host)?,
            port,
        })
    }

    /// Returns the canonical target host.
    #[must_use]
    pub fn host(&self) -> &ServerName {
        &self.host
    }

    /// Returns the target TCP port.
    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }

    fn authority(&self) -> String {
        format!("{}:{}", self.host.as_str(), self.port)
    }
}

/// A validated REALITY private key.
///
/// Parsing only verifies canonical base64url encoding and a 32-byte payload. It
/// never generates key material.
pub struct RealityPrivateKey(Zeroizing<[u8; 32]>);

impl RealityPrivateKey {
    /// Parses a canonical unpadded base64url-encoded 32-byte private key.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigBuildError::InvalidPrivateKey`] for malformed, padded,
    /// incorrectly sized, or all-zero key material.
    pub fn parse(value: &str) -> Result<Self, ConfigBuildError> {
        let decoded = Zeroizing::new(
            URL_SAFE_NO_PAD
                .decode(value)
                .map_err(|_| ConfigBuildError::InvalidPrivateKey)?,
        );
        let bytes: [u8; 32] = decoded
            .as_slice()
            .try_into()
            .map_err(|_| ConfigBuildError::InvalidPrivateKey)?;
        if bytes.iter().all(|byte| *byte == 0) || URL_SAFE_NO_PAD.encode(bytes.as_slice()) != value
        {
            return Err(ConfigBuildError::InvalidPrivateKey);
        }
        Ok(Self(Zeroizing::new(bytes)))
    }

    fn encoded(&self) -> Zeroizing<String> {
        Zeroizing::new(URL_SAFE_NO_PAD.encode(self.0.as_ref()))
    }
}

impl Clone for RealityPrivateKey {
    fn clone(&self) -> Self {
        Self(Zeroizing::new(*self.0))
    }
}

impl fmt::Debug for RealityPrivateKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RealityPrivateKey([redacted])")
    }
}

/// A validated REALITY short ID encoded as canonical lowercase hexadecimal.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ShortId(String);

impl ShortId {
    /// Parses a short ID with four to eight bytes of entropy.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigBuildError::InvalidShortId`] for empty, odd-length,
    /// non-hexadecimal, or out-of-range values.
    pub fn parse(value: &str) -> Result<Self, ConfigBuildError> {
        if value.len() < MIN_SHORT_ID_HEX_LENGTH
            || value.len() > MAX_SHORT_ID_HEX_LENGTH
            || value.len() % 2 != 0
            || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(ConfigBuildError::InvalidShortId);
        }
        Ok(Self(value.to_ascii_lowercase()))
    }

    /// Returns the canonical hexadecimal short ID.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ShortId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("ShortId").field(&self.0).finish()
    }
}

/// A validated Xray client email/label.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UserEmail(String);

impl UserEmail {
    /// Parses a conservative ASCII Xray email/label.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigBuildError::InvalidUserEmail`] when the value is empty,
    /// too long, surrounded by whitespace, or contains unsafe characters.
    pub fn parse(value: &str) -> Result<Self, ConfigBuildError> {
        let valid_character = |byte: u8| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'@' | b'+' | b'-')
        };
        let bytes = value.as_bytes();
        if value.is_empty()
            || value.len() > 128
            || value.trim() != value
            || !value.is_ascii()
            || !bytes.iter().copied().all(valid_character)
            || !bytes.first().is_some_and(u8::is_ascii_alphanumeric)
            || !bytes.last().is_some_and(u8::is_ascii_alphanumeric)
        {
            return Err(ConfigBuildError::InvalidUserEmail);
        }
        Ok(Self(value.to_owned()))
    }

    /// Returns the validated label.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn duplicate_key(&self) -> String {
        self.0.to_ascii_lowercase()
    }
}

impl fmt::Debug for UserEmail {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("UserEmail").field(&self.0).finish()
    }
}

/// One VLESS client included in the generated inbound when enabled.
#[derive(Clone)]
pub struct VlessUser {
    id: Uuid,
    email: UserEmail,
    enabled: bool,
}

/// A loopback-only Xray Stats API listener.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StatsApiConfig {
    address: SocketAddrV4,
}

impl StatsApiConfig {
    /// Creates an API listener fixed to IPv4 loopback.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigBuildError::InvalidStatsApiPort`] when `port` is zero.
    pub fn loopback(port: u16) -> Result<Self, ConfigBuildError> {
        if port == 0 {
            return Err(ConfigBuildError::InvalidStatsApiPort);
        }
        Ok(Self {
            address: SocketAddrV4::new(Ipv4Addr::LOCALHOST, port),
        })
    }

    /// Returns the private API endpoint.
    #[must_use]
    pub const fn address(self) -> SocketAddrV4 {
        self.address
    }
}

impl VlessUser {
    /// Creates a validated VLESS user.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigBuildError::NilUserId`] for the nil UUID.
    pub fn new(id: Uuid, email: UserEmail, enabled: bool) -> Result<Self, ConfigBuildError> {
        if id.is_nil() {
            return Err(ConfigBuildError::NilUserId);
        }
        Ok(Self { id, email, enabled })
    }

    /// Returns the VLESS UUID.
    #[must_use]
    pub const fn id(&self) -> Uuid {
        self.id
    }

    /// Returns the Xray email/label.
    #[must_use]
    pub fn email(&self) -> &UserEmail {
        &self.email
    }

    /// Returns whether this client will be emitted into the Xray config.
    #[must_use]
    pub const fn enabled(&self) -> bool {
        self.enabled
    }
}

impl fmt::Debug for VlessUser {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VlessUser")
            .field("id", &"[redacted]")
            .field("email", &self.email)
            .field("enabled", &self.enabled)
            .finish()
    }
}

/// Builder for one deterministic VLESS + REALITY server configuration.
#[derive(Clone, Debug)]
pub struct VlessRealityConfigBuilder {
    listen_address: IpAddr,
    listen_port: u16,
    target: RealityTarget,
    private_key: RealityPrivateKey,
    server_names: Vec<ServerName>,
    short_ids: Vec<ShortId>,
    users: Vec<VlessUser>,
    stats_api: Option<StatsApiConfig>,
}

impl VlessRealityConfigBuilder {
    /// Creates an empty builder with explicit network and key inputs.
    ///
    /// # Errors
    ///
    /// Returns an error for port zero, multicast, or IPv4 broadcast listen
    /// addresses.
    pub fn new(
        listen_address: IpAddr,
        listen_port: u16,
        target: RealityTarget,
        private_key: RealityPrivateKey,
    ) -> Result<Self, ConfigBuildError> {
        if listen_port == 0 {
            return Err(ConfigBuildError::InvalidListenPort);
        }
        if listen_address.is_multicast() || listen_address == IpAddr::V4(Ipv4Addr::BROADCAST) {
            return Err(ConfigBuildError::InvalidListenAddress);
        }
        Ok(Self {
            listen_address,
            listen_port,
            target,
            private_key,
            server_names: Vec::new(),
            short_ids: Vec::new(),
            users: Vec::new(),
            stats_api: None,
        })
    }

    /// Adds an allowed REALITY server name.
    #[must_use]
    pub fn server_name(mut self, server_name: ServerName) -> Self {
        self.server_names.push(server_name);
        self
    }

    /// Adds an allowed REALITY short ID.
    #[must_use]
    pub fn short_id(mut self, short_id: ShortId) -> Self {
        self.short_ids.push(short_id);
        self
    }

    /// Adds a VLESS user, including disabled users used for deterministic
    /// duplicate detection.
    #[must_use]
    pub fn user(mut self, user: VlessUser) -> Self {
        self.users.push(user);
        self
    }

    /// Enables per-user cumulative traffic counters through a loopback-only API.
    #[must_use]
    pub fn stats_api(mut self, stats_api: StatsApiConfig) -> Self {
        self.stats_api = Some(stats_api);
        self
    }

    /// Validates all cross-field constraints and renders deterministic JSON.
    ///
    /// Disabled users are validated for duplicate identities but are omitted
    /// from the rendered Xray `settings.clients` list. No enabled users produces
    /// an empty list that revokes all VLESS identities.
    ///
    /// # Errors
    ///
    /// Returns an error for missing REALITY names/short IDs or excessive and
    /// duplicate collections.
    pub fn build(mut self) -> Result<RenderedXrayConfig, ConfigBuildError> {
        validate_collection_sizes(&self)?;

        self.server_names.sort();
        self.short_ids.sort();
        self.users.sort_by(|left, right| {
            left.email
                .duplicate_key()
                .cmp(&right.email.duplicate_key())
                .then_with(|| left.id.cmp(&right.id))
        });
        validate_duplicates(&self)?;

        let enabled_users: Vec<_> = self.users.iter().filter(|user| user.enabled).collect();

        let target = self.target.authority();
        let encoded_private_key = self.private_key.encoded();
        if self.stats_api.is_some_and(|stats| {
            self.listen_address == IpAddr::V4(Ipv4Addr::LOCALHOST)
                && self.listen_port == stats.address().port()
        }) {
            return Err(ConfigBuildError::StatsApiPortConflict);
        }
        let stats_api = self.stats_api.map(|_| ApiSettings {
            tag: "stats-api",
            services: ["StatsService"],
        });
        let routing = self.stats_api.map(|_| RoutingSettings {
            rules: [RoutingRule {
                rule_type: "field",
                inbound_tag: ["stats-api"],
                outbound_tag: "stats-api",
            }],
        });
        let mut inbounds = vec![Inbound::Vless(VlessInbound {
            tag: "vless-reality-in",
            listen: self.listen_address,
            port: self.listen_port,
            protocol: "vless",
            settings: VlessInboundSettings {
                clients: enabled_users
                    .into_iter()
                    .map(|user| Client {
                        id: user.id,
                        email: user.email.as_str(),
                        level: 0,
                        flow: "xtls-rprx-vision",
                    })
                    .collect(),
                decryption: "none",
            },
            stream_settings: StreamSettings {
                network: "raw",
                security: "reality",
                reality_settings: RealitySettings {
                    show: false,
                    target: &target,
                    xver: 0,
                    server_names: self.server_names.iter().map(ServerName::as_str).collect(),
                    private_key: encoded_private_key.as_str(),
                    short_ids: self.short_ids.iter().map(ShortId::as_str).collect(),
                },
            },
        })];
        if let Some(stats) = self.stats_api {
            inbounds.push(Inbound::Api(ApiInbound {
                tag: "stats-api",
                listen: *stats.address().ip(),
                port: stats.address().port(),
                protocol: "dokodemo-door",
                settings: ApiInboundSettings {
                    address: Ipv4Addr::LOCALHOST,
                },
            }));
        }
        let config = XrayConfig {
            log: LogSettings {
                access: "none",
                dns_log: false,
                log_level: "warning",
            },
            api: stats_api,
            routing,
            stats: self.stats_api.map(|_| EmptySettings {}),
            policy: self.stats_api.map(|_| PolicySettings {
                levels: PolicyLevels {
                    default: UserLevelPolicy {
                        stats_user_uplink: true,
                        stats_user_downlink: true,
                    },
                },
                system: SystemPolicy {},
            }),
            inbounds,
            outbounds: vec![Outbound {
                tag: "direct",
                protocol: "freedom",
            }],
        };

        let mut json = serde_json::to_string_pretty(&config)
            .map_err(|_| ConfigBuildError::SerializationFailed)?;
        json.push('\n');
        Ok(RenderedXrayConfig(Zeroizing::new(json)))
    }
}

/// Rendered Xray JSON containing sensitive key and user material.
pub struct RenderedXrayConfig(Zeroizing<String>);

impl RenderedXrayConfig {
    /// Exposes the complete JSON for writing to a protected file.
    ///
    /// Callers should not log this value because it contains the REALITY private
    /// key and VLESS UUIDs.
    #[must_use]
    pub fn expose_json(&self) -> &str {
        &self.0
    }

    /// Returns the serialized size without exposing the contents.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns whether the rendered document is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for RenderedXrayConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RenderedXrayConfig")
            .field("contents", &"[redacted]")
            .field("bytes", &self.0.len())
            .finish()
    }
}

/// Safe validation failures from the pure configuration builder.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ConfigBuildError {
    /// The listen port was zero.
    #[error("Xray listen port must be non-zero")]
    InvalidListenPort,
    /// The listen address cannot be used as a local socket address.
    #[error("Xray listen address must not be multicast or broadcast")]
    InvalidListenAddress,
    /// The Stats API listen port was zero.
    #[error("Xray Stats API port must be non-zero")]
    InvalidStatsApiPort,
    /// The data and API listeners would bind the same loopback socket.
    #[error("Xray Stats API port conflicts with the VLESS listen port")]
    StatsApiPortConflict,
    /// The REALITY target port was zero.
    #[error("REALITY target port must be non-zero")]
    InvalidTargetPort,
    /// A REALITY DNS name failed conservative validation.
    #[error("REALITY server name is invalid")]
    InvalidServerName,
    /// The REALITY private key was malformed or unsafe.
    #[error("REALITY private key is invalid")]
    InvalidPrivateKey,
    /// A REALITY short ID was malformed or outside the safe length range.
    #[error("REALITY short ID is invalid")]
    InvalidShortId,
    /// A VLESS email/label failed conservative validation.
    #[error("VLESS user email is invalid")]
    InvalidUserEmail,
    /// A VLESS user had the nil UUID.
    #[error("VLESS user UUID must not be nil")]
    NilUserId,
    /// No server name was supplied.
    #[error("at least one REALITY server name is required")]
    NoServerNames,
    /// Too many server names were supplied.
    #[error("too many REALITY server names")]
    TooManyServerNames,
    /// The canonical server-name list contained a duplicate.
    #[error("REALITY server names must be unique")]
    DuplicateServerName,
    /// No short ID was supplied.
    #[error("at least one REALITY short ID is required")]
    NoShortIds,
    /// Too many short IDs were supplied.
    #[error("too many REALITY short IDs")]
    TooManyShortIds,
    /// The canonical short-ID list contained a duplicate.
    #[error("REALITY short IDs must be unique")]
    DuplicateShortId,
    /// Too many users were supplied.
    #[error("too many VLESS users")]
    TooManyUsers,
    /// Multiple users had the same UUID.
    #[error("VLESS user UUIDs must be unique")]
    DuplicateUserId,
    /// Multiple users had the same case-insensitive email/label.
    #[error("VLESS user emails must be unique")]
    DuplicateUserEmail,
    /// Serialization failed unexpectedly.
    #[error("Xray configuration could not be serialized")]
    SerializationFailed,
}

fn validate_dns_name(value: &str) -> Result<String, ConfigBuildError> {
    if value.is_empty()
        || value.len() > 253
        || value.trim() != value
        || !value.is_ascii()
        || value.ends_with('.')
        || value.contains('*')
        || value.parse::<IpAddr>().is_ok()
    {
        return Err(ConfigBuildError::InvalidServerName);
    }

    let canonical = value.to_ascii_lowercase();
    let labels: Vec<_> = canonical.split('.').collect();
    if labels.len() < 2
        || labels.iter().any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
        || labels.last().is_some_and(|label| {
            matches!(
                *label,
                "example" | "invalid" | "local" | "localhost" | "onion" | "test"
            ) || !label.bytes().any(|byte| byte.is_ascii_alphabetic())
        })
    {
        return Err(ConfigBuildError::InvalidServerName);
    }
    Ok(canonical)
}

fn validate_collection_sizes(builder: &VlessRealityConfigBuilder) -> Result<(), ConfigBuildError> {
    match builder.server_names.len() {
        0 => return Err(ConfigBuildError::NoServerNames),
        length if length > MAX_SERVER_NAMES => return Err(ConfigBuildError::TooManyServerNames),
        _ => {}
    }
    match builder.short_ids.len() {
        0 => return Err(ConfigBuildError::NoShortIds),
        length if length > MAX_SHORT_IDS => return Err(ConfigBuildError::TooManyShortIds),
        _ => {}
    }
    if builder.users.len() > MAX_USERS {
        return Err(ConfigBuildError::TooManyUsers);
    }
    Ok(())
}

fn validate_duplicates(builder: &VlessRealityConfigBuilder) -> Result<(), ConfigBuildError> {
    if builder
        .server_names
        .windows(2)
        .any(|pair| pair[0] == pair[1])
    {
        return Err(ConfigBuildError::DuplicateServerName);
    }
    if builder.short_ids.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(ConfigBuildError::DuplicateShortId);
    }

    let mut ids = HashSet::with_capacity(builder.users.len());
    let mut emails = HashSet::with_capacity(builder.users.len());
    for user in &builder.users {
        if !ids.insert(user.id) {
            return Err(ConfigBuildError::DuplicateUserId);
        }
        if !emails.insert(user.email.duplicate_key()) {
            return Err(ConfigBuildError::DuplicateUserEmail);
        }
    }
    Ok(())
}

#[derive(Serialize)]
struct XrayConfig<'a> {
    log: LogSettings<'a>,
    #[serde(skip_serializing_if = "Option::is_none")]
    api: Option<ApiSettings<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    routing: Option<RoutingSettings<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    stats: Option<EmptySettings>,
    #[serde(skip_serializing_if = "Option::is_none")]
    policy: Option<PolicySettings>,
    inbounds: Vec<Inbound<'a>>,
    outbounds: Vec<Outbound<'a>>,
}

#[derive(Serialize)]
struct ApiSettings<'a> {
    tag: &'a str,
    services: [&'a str; 1],
}

#[derive(Serialize)]
struct RoutingSettings<'a> {
    rules: [RoutingRule<'a>; 1],
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RoutingRule<'a> {
    #[serde(rename = "type")]
    rule_type: &'a str,
    inbound_tag: [&'a str; 1],
    outbound_tag: &'a str,
}

#[derive(Serialize)]
struct EmptySettings {}

#[derive(Serialize)]
struct PolicySettings {
    levels: PolicyLevels,
    system: SystemPolicy,
}

#[derive(Serialize)]
struct PolicyLevels {
    #[serde(rename = "0")]
    default: UserLevelPolicy,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UserLevelPolicy {
    stats_user_uplink: bool,
    stats_user_downlink: bool,
}

#[derive(Serialize)]
struct SystemPolicy {}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct LogSettings<'a> {
    access: &'a str,
    dns_log: bool,
    #[serde(rename = "loglevel")]
    log_level: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
#[serde(untagged)]
enum Inbound<'a> {
    Vless(VlessInbound<'a>),
    Api(ApiInbound<'a>),
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct VlessInbound<'a> {
    tag: &'a str,
    listen: IpAddr,
    port: u16,
    protocol: &'a str,
    settings: VlessInboundSettings<'a>,
    stream_settings: StreamSettings<'a>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ApiInbound<'a> {
    tag: &'a str,
    listen: Ipv4Addr,
    port: u16,
    protocol: &'a str,
    settings: ApiInboundSettings,
}

#[derive(Serialize)]
struct ApiInboundSettings {
    address: Ipv4Addr,
}

#[derive(Serialize)]
struct VlessInboundSettings<'a> {
    // Xray 26.3.27 predates the inbound `clients` -> `users` rename.
    clients: Vec<Client<'a>>,
    decryption: &'a str,
}

#[derive(Serialize)]
struct Client<'a> {
    id: Uuid,
    email: &'a str,
    level: u8,
    flow: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct StreamSettings<'a> {
    network: &'a str,
    security: &'a str,
    reality_settings: RealitySettings<'a>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RealitySettings<'a> {
    show: bool,
    target: &'a str,
    xver: u8,
    server_names: Vec<&'a str>,
    private_key: &'a str,
    short_ids: Vec<&'a str>,
}

#[derive(Serialize)]
struct Outbound<'a> {
    tag: &'a str,
    protocol: &'a str,
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use serde_json::Value;
    use uuid::Uuid;

    use super::{
        ConfigBuildError, RealityPrivateKey, RealityTarget, ServerName, ShortId, StatsApiConfig,
        UserEmail, VlessRealityConfigBuilder, VlessUser,
    };

    fn private_key() -> RealityPrivateKey {
        RealityPrivateKey::parse(&URL_SAFE_NO_PAD.encode([7_u8; 32])).expect("valid test key")
    }

    fn user(id: &str, email: &str, enabled: bool) -> VlessUser {
        VlessUser::new(
            Uuid::parse_str(id).expect("valid test UUID"),
            UserEmail::parse(email).expect("valid test email"),
            enabled,
        )
        .expect("valid test user")
    }

    fn builder() -> VlessRealityConfigBuilder {
        VlessRealityConfigBuilder::new(
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            443,
            RealityTarget::new("www.example.com", 443).expect("valid target"),
            private_key(),
        )
        .expect("valid builder")
    }

    #[test]
    fn renders_deterministic_safe_json_independent_of_input_order() {
        let first = builder()
            .server_name(ServerName::parse("cdn.example.com").expect("valid name"))
            .server_name(ServerName::parse("www.example.com").expect("valid name"))
            .short_id(ShortId::parse("AABBCCDD").expect("valid short ID"))
            .short_id(ShortId::parse("0011223344556677").expect("valid short ID"))
            .user(user(
                "22222222-2222-4222-8222-222222222222",
                "friend-b@example.com",
                true,
            ))
            .user(user(
                "11111111-1111-4111-8111-111111111111",
                "friend-a@example.com",
                true,
            ))
            .user(user(
                "33333333-3333-4333-8333-333333333333",
                "friend-c@example.com",
                false,
            ))
            .build()
            .expect("first config");

        let second = builder()
            .server_name(ServerName::parse("WWW.EXAMPLE.COM").expect("valid name"))
            .server_name(ServerName::parse("CDN.EXAMPLE.COM").expect("valid name"))
            .short_id(ShortId::parse("0011223344556677").expect("valid short ID"))
            .short_id(ShortId::parse("aabbccdd").expect("valid short ID"))
            .user(user(
                "33333333-3333-4333-8333-333333333333",
                "friend-c@example.com",
                false,
            ))
            .user(user(
                "11111111-1111-4111-8111-111111111111",
                "friend-a@example.com",
                true,
            ))
            .user(user(
                "22222222-2222-4222-8222-222222222222",
                "friend-b@example.com",
                true,
            ))
            .build()
            .expect("second config");

        assert_eq!(first.expose_json(), second.expose_json());
        let json: Value = serde_json::from_str(first.expose_json()).expect("valid JSON");
        assert_eq!(json.pointer("/log/access"), Some(&Value::from("none")));
        assert_eq!(json.pointer("/log/dnsLog"), Some(&Value::from(false)));
        assert_eq!(json.pointer("/log/loglevel"), Some(&Value::from("warning")));
        assert!(json.pointer("/log/logLevel").is_none());
        assert_eq!(
            json.pointer("/inbounds/0/streamSettings/network"),
            Some(&Value::from("raw"))
        );
        assert_eq!(
            json.pointer("/inbounds/0/streamSettings/realitySettings/target"),
            Some(&Value::from("www.example.com:443"))
        );
        assert_eq!(
            json.pointer("/inbounds/0/settings/clients/0/email"),
            Some(&Value::from("friend-a@example.com"))
        );
        assert_eq!(
            json.pointer("/inbounds/0/settings/clients")
                .and_then(Value::as_array)
                .map(Vec::len),
            Some(2)
        );
    }

    #[test]
    fn renders_minimal_loopback_stats_api_and_per_user_policy() {
        let rendered = builder()
            .server_name(ServerName::parse("www.example.com").unwrap())
            .short_id(ShortId::parse("aabbccdd").unwrap())
            .user(user(
                "11111111-1111-4111-8111-111111111111",
                "friend@example.com",
                true,
            ))
            .stats_api(StatsApiConfig::loopback(31_337).unwrap())
            .build()
            .unwrap();
        let json: Value = serde_json::from_str(rendered.expose_json()).unwrap();

        assert!(json.pointer("/api/listen").is_none());
        assert_eq!(
            json.pointer("/api/services"),
            Some(&serde_json::json!(["StatsService"]))
        );
        assert_eq!(json.pointer("/stats"), Some(&serde_json::json!({})));
        assert_eq!(json.pointer("/policy/system"), Some(&serde_json::json!({})));
        assert_eq!(
            json.pointer("/policy/levels/0/statsUserUplink"),
            Some(&Value::Bool(true))
        );
        assert_eq!(
            json.pointer("/inbounds/0/settings/clients/0/level"),
            Some(&Value::from(0))
        );
        assert_eq!(
            json.pointer("/inbounds/1/listen"),
            Some(&Value::from("127.0.0.1"))
        );
        assert_eq!(json.pointer("/inbounds/1/port"), Some(&Value::from(31_337)));
        assert_eq!(
            json.pointer("/inbounds/1/protocol"),
            Some(&Value::from("dokodemo-door"))
        );
        assert_eq!(
            json.pointer("/inbounds/1/settings/address"),
            Some(&Value::from("127.0.0.1"))
        );
        assert!(json.pointer("/inbounds/1/settings/clients").is_none());
        assert!(json.pointer("/inbounds/1/streamSettings").is_none());
        assert_eq!(
            json.pointer("/routing/rules/0/inboundTag"),
            Some(&serde_json::json!(["stats-api"]))
        );
        assert_eq!(
            json.pointer("/routing/rules/0/outboundTag"),
            Some(&Value::from("stats-api"))
        );
        assert_eq!(json["inbounds"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn rejects_a_loopback_stats_api_port_collision() {
        let error = VlessRealityConfigBuilder::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            31_337,
            RealityTarget::new("www.example.com", 443).unwrap(),
            private_key(),
        )
        .unwrap()
        .server_name(ServerName::parse("www.example.com").unwrap())
        .short_id(ShortId::parse("aabbccdd").unwrap())
        .stats_api(StatsApiConfig::loopback(31_337).unwrap())
        .build()
        .unwrap_err();

        assert_eq!(error, ConfigBuildError::StatsApiPortConflict);
    }

    #[test]
    fn permits_empty_access_and_rejects_duplicate_users() {
        let empty = builder()
            .server_name(ServerName::parse("www.example.com").expect("valid name"))
            .short_id(ShortId::parse("aabbccdd").expect("valid short ID"))
            .build()
            .expect("empty access list must revoke every VLESS identity");
        let empty_json: Value = serde_json::from_str(empty.expose_json()).unwrap();
        assert_eq!(
            empty_json
                .pointer("/inbounds/0/settings/clients")
                .and_then(Value::as_array)
                .map(Vec::len),
            Some(0)
        );

        let id = "11111111-1111-4111-8111-111111111111";
        let duplicate = builder()
            .server_name(ServerName::parse("www.example.com").expect("valid name"))
            .short_id(ShortId::parse("aabbccdd").expect("valid short ID"))
            .user(user(id, "friend-a@example.com", true))
            .user(user(id, "friend-b@example.com", false))
            .build()
            .expect_err("duplicate UUID must fail");
        assert_eq!(duplicate, ConfigBuildError::DuplicateUserId);

        let duplicate_server_name = builder()
            .server_name(ServerName::parse("www.example.com").expect("valid name"))
            .server_name(ServerName::parse("WWW.EXAMPLE.COM").expect("valid name"))
            .short_id(ShortId::parse("aabbccdd").expect("valid short ID"))
            .user(user(
                "11111111-1111-4111-8111-111111111111",
                "friend@example.com",
                true,
            ))
            .build()
            .expect_err("duplicate server name must fail");
        assert_eq!(duplicate_server_name, ConfigBuildError::DuplicateServerName);

        let duplicate_short_id = builder()
            .server_name(ServerName::parse("www.example.com").expect("valid name"))
            .short_id(ShortId::parse("AABBCCDD").expect("valid short ID"))
            .short_id(ShortId::parse("aabbccdd").expect("valid short ID"))
            .user(user(
                "11111111-1111-4111-8111-111111111111",
                "friend@example.com",
                true,
            ))
            .build()
            .expect_err("duplicate short ID must fail");
        assert_eq!(duplicate_short_id, ConfigBuildError::DuplicateShortId);

        let duplicate_email = builder()
            .server_name(ServerName::parse("www.example.com").expect("valid name"))
            .short_id(ShortId::parse("aabbccdd").expect("valid short ID"))
            .user(user(
                "11111111-1111-4111-8111-111111111111",
                "Friend@example.com",
                true,
            ))
            .user(user(
                "22222222-2222-4222-8222-222222222222",
                "friend@example.com",
                false,
            ))
            .build()
            .expect_err("case-insensitive duplicate email must fail");
        assert_eq!(duplicate_email, ConfigBuildError::DuplicateUserEmail);

        let all_disabled = builder()
            .server_name(ServerName::parse("www.example.com").expect("valid name"))
            .short_id(ShortId::parse("aabbccdd").expect("valid short ID"))
            .user(user(
                "11111111-1111-4111-8111-111111111111",
                "friend@example.com",
                false,
            ))
            .build()
            .expect("all-disabled access list must render");
        let disabled_json: Value = serde_json::from_str(all_disabled.expose_json()).unwrap();
        assert_eq!(
            disabled_json
                .pointer("/inbounds/0/settings/clients")
                .and_then(Value::as_array)
                .map(Vec::len),
            Some(0)
        );
    }

    #[test]
    fn rejects_dangerous_scalar_inputs() {
        assert_eq!(
            RealityTarget::new("www.example.com", 0).expect_err("zero target port"),
            ConfigBuildError::InvalidTargetPort
        );
        assert_eq!(
            VlessRealityConfigBuilder::new(
                IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                0,
                RealityTarget::new("www.example.com", 443).expect("valid target"),
                private_key(),
            )
            .expect_err("zero listen port"),
            ConfigBuildError::InvalidListenPort
        );
        assert_eq!(
            ServerName::parse("localhost").expect_err("single-label host"),
            ConfigBuildError::InvalidServerName
        );
        assert_eq!(
            ServerName::parse("127.0.0.1").expect_err("IP host"),
            ConfigBuildError::InvalidServerName
        );
        assert_eq!(
            ServerName::parse("node.invalid").expect_err("reserved DNS suffix"),
            ConfigBuildError::InvalidServerName
        );
        assert_eq!(
            ShortId::parse("").expect_err("empty short ID"),
            ConfigBuildError::InvalidShortId
        );
        assert_eq!(
            UserEmail::parse("friend 1").expect_err("whitespace"),
            ConfigBuildError::InvalidUserEmail
        );
        assert_eq!(
            RealityPrivateKey::parse("not-a-key").expect_err("invalid key"),
            ConfigBuildError::InvalidPrivateKey
        );
    }

    #[test]
    fn debug_output_redacts_private_material() {
        let key_text = URL_SAFE_NO_PAD.encode([7_u8; 32]);
        let key = RealityPrivateKey::parse(&key_text).expect("valid key");
        assert!(!format!("{key:?}").contains(&key_text));

        let rendered = builder()
            .server_name(ServerName::parse("www.example.com").expect("valid name"))
            .short_id(ShortId::parse("aabbccdd").expect("valid short ID"))
            .user(user(
                "11111111-1111-4111-8111-111111111111",
                "friend@example.com",
                true,
            ))
            .build()
            .expect("valid config");
        assert!(!format!("{rendered:?}").contains(&key_text));
    }
}
