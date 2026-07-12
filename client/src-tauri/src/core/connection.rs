//! Secret-bearing connection model shared by account bundles and compatibility imports.

use crate::error::ClientError;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use control_protocol::account::NodeProfile;
use control_protocol::id::NodeId;
use control_protocol::node::EndpointMode;
use std::fmt;
use uuid::Uuid;

const SUPPORTED_FLOWS: &[&str] = &["xtls-rprx-vision", "xtls-rprx-vision-udp443"];
const SUPPORTED_FINGERPRINTS: &[&str] = &[
    "chrome",
    "firefox",
    "safari",
    "ios",
    "android",
    "edge",
    "360",
    "qq",
    "random",
    "randomized",
];

/// Origin of a normalized connection profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionSource {
    /// Controller-signed account bundle.
    AccountBundle { node_id: NodeId, mode: EndpointMode },
    /// Locally imported legacy URI.
    CompatibilityImport,
}

/// Complete internal Xray connection input.
///
/// This type deliberately does not implement `Serialize`; Tauri commands expose only safe views.
#[derive(Clone)]
pub struct ConnectionProfile {
    /// Profile origin and stable account-node identity, when available.
    pub source: ConnectionSource,
    /// Safe presentation label.
    pub name: String,
    /// Verified endpoint address.
    pub server_address: String,
    /// Verified endpoint port.
    pub server_port: u16,
    /// Secret VLESS credential.
    pub user_id: Uuid,
    /// Supported XTLS flow.
    pub flow: String,
    /// REALITY server name.
    pub server_name: String,
    /// uTLS fingerprint.
    pub fingerprint: String,
    /// Node REALITY public key, secret-bearing in client diagnostics.
    pub reality_password: String,
    /// Node REALITY short ID.
    pub short_id: String,
    /// REALITY spider path.
    pub spider_x: String,
}

impl fmt::Debug for ConnectionProfile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConnectionProfile")
            .field("source", &self.source)
            .field("name", &self.name)
            .field("server_address", &self.server_address)
            .field("server_port", &self.server_port)
            .field("user_id", &"[redacted]")
            .field("flow", &self.flow)
            .field("server_name", &self.server_name)
            .field("fingerprint", &self.fingerprint)
            .field("reality_password", &"[redacted]")
            .field("short_id", &"[redacted]")
            .field("spider_x", &"[redacted]")
            .finish()
    }
}

impl TryFrom<&NodeProfile> for ConnectionProfile {
    type Error = ClientError;

    fn try_from(profile: &NodeProfile) -> Result<Self, Self::Error> {
        let connection = &profile.connection;
        let normalized = Self {
            source: ConnectionSource::AccountBundle {
                node_id: profile.node_id,
                mode: profile.endpoint.mode,
            },
            name: profile.display_name.clone(),
            server_address: profile.endpoint.address.clone(),
            server_port: profile.endpoint.port,
            user_id: Uuid::parse_str(connection.vless_uuid.expose_secret()).map_err(|_| {
                invalid_profile(
                    "bundle_profile_invalid_uuid",
                    "The VLESS credential is invalid.",
                )
            })?,
            flow: connection.flow.clone(),
            server_name: connection.server_name.clone(),
            fingerprint: connection.fingerprint.clone(),
            reality_password: connection.reality_public_key.expose_secret().clone(),
            short_id: connection.short_id.expose_secret().clone(),
            spider_x: connection.spider_x.expose_secret().clone(),
        };
        normalized.validate()?;
        Ok(normalized)
    }
}

impl ConnectionProfile {
    /// Validates fields that affect generated Xray behavior.
    pub fn validate(&self) -> Result<(), ClientError> {
        if self.server_address.is_empty()
            || self.server_address.len() > 253
            || self.server_address.contains('/')
            || self.server_address.chars().any(char::is_whitespace)
            || self.server_port == 0
        {
            return Err(invalid_profile(
                "connection_profile_invalid_endpoint",
                "The connection endpoint is invalid.",
            ));
        }
        if !SUPPORTED_FLOWS.contains(&self.flow.as_str()) {
            return Err(invalid_profile(
                "connection_profile_unsupported_flow",
                "The connection flow is unsupported.",
            ));
        }
        if !SUPPORTED_FINGERPRINTS.contains(&self.fingerprint.as_str()) {
            return Err(invalid_profile(
                "connection_profile_unsupported_fingerprint",
                "The TLS fingerprint is unsupported.",
            ));
        }
        validate_server_name(&self.server_name)?;
        validate_reality_key(&self.reality_password)?;
        validate_short_id(&self.short_id)?;
        if self.spider_x.is_empty() || !self.spider_x.starts_with('/') {
            return Err(invalid_profile(
                "connection_profile_invalid_spider_path",
                "The REALITY spider path is invalid.",
            ));
        }
        Ok(())
    }
}

pub(crate) fn validate_server_name(value: &str) -> Result<(), ClientError> {
    if value.is_empty()
        || value.len() > 253
        || value.chars().any(char::is_whitespace)
        || value.contains('/')
        || value.contains(':')
    {
        return Err(invalid_profile(
            "connection_profile_invalid_server_name",
            "The REALITY server name is invalid.",
        ));
    }
    Ok(())
}

pub(crate) fn validate_reality_key(value: &str) -> Result<(), ClientError> {
    let decoded = URL_SAFE_NO_PAD.decode(value).map_err(|_| {
        invalid_profile(
            "connection_profile_invalid_reality_key",
            "The REALITY public key is invalid.",
        )
    })?;
    if decoded.len() != 32 {
        return Err(invalid_profile(
            "connection_profile_invalid_reality_key",
            "The REALITY public key is invalid.",
        ));
    }
    Ok(())
}

pub(crate) fn validate_short_id(value: &str) -> Result<(), ClientError> {
    if value.len() > 16
        || !value.len().is_multiple_of(2)
        || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(invalid_profile(
            "connection_profile_invalid_short_id",
            "The REALITY short ID is invalid.",
        ));
    }
    Ok(())
}

fn invalid_profile(code: &str, message: &str) -> ClientError {
    ClientError::internal(code, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_redacts_connection_credentials() {
        let profile = ConnectionProfile {
            source: ConnectionSource::CompatibilityImport,
            name: "test".to_string(),
            server_address: "example.test".to_string(),
            server_port: 443,
            user_id: Uuid::parse_str("11111111-1111-4111-8111-111111111111").unwrap(),
            flow: "xtls-rprx-vision".to_string(),
            server_name: "example.test".to_string(),
            fingerprint: "chrome".to_string(),
            reality_password: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
            short_id: "aabb".to_string(),
            spider_x: "/".to_string(),
        };

        let output = format!("{profile:?}");
        assert!(!output.contains("11111111-1111-4111-8111-111111111111"));
        assert!(!output.contains("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"));
        assert!(!output.contains("aabb"));
    }
}
