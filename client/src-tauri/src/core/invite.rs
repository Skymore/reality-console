use crate::error::ClientError;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use percent_encoding::percent_decode_str;
use serde::Serialize;
use std::collections::HashMap;
use std::fmt;
use url::Url;
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
const SINGLE_VALUE_PARAMETERS: &[&str] = &[
    "encryption",
    "flow",
    "security",
    "sni",
    "fp",
    "pbk",
    "sid",
    "type",
    "headerType",
    "spx",
];

#[derive(Clone)]
pub struct RealityProfile {
    pub name: String,
    pub server_address: String,
    pub server_port: u16,
    pub user_id: Uuid,
    pub flow: String,
    pub server_name: String,
    pub fingerprint: String,
    pub reality_password: String,
    pub short_id: String,
    pub spider_x: String,
}

impl fmt::Debug for RealityProfile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RealityProfile")
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

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InvitationPreview {
    pub name: String,
    pub server_address: String,
    pub server_port: u16,
    pub transport: String,
    pub security: String,
    pub flow: String,
    pub server_name: String,
    pub fingerprint: String,
}

impl From<&RealityProfile> for InvitationPreview {
    fn from(profile: &RealityProfile) -> Self {
        Self {
            name: profile.name.clone(),
            server_address: profile.server_address.clone(),
            server_port: profile.server_port,
            transport: "raw".to_string(),
            security: "reality".to_string(),
            flow: profile.flow.clone(),
            server_name: profile.server_name.clone(),
            fingerprint: profile.fingerprint.clone(),
        }
    }
}

pub fn parse_invitation(invitation: &str) -> Result<RealityProfile, ClientError> {
    let invitation = invitation.trim();
    let url = Url::parse(invitation).map_err(|_| {
        invalid(
            "invitation_invalid_url",
            "invitation",
            "The invitation is not a valid URL.",
        )
    })?;

    if url.scheme() != "vless" {
        return Err(invalid(
            "invitation_unsupported_scheme",
            "scheme",
            "Only vless:// invitations are supported.",
        ));
    }

    if !url.password().unwrap_or_default().is_empty() {
        return Err(invalid(
            "invitation_invalid_authority",
            "userId",
            "The VLESS authority must contain a UUID without a password.",
        ));
    }

    let user_id = Uuid::parse_str(url.username()).map_err(|_| {
        invalid(
            "invitation_invalid_uuid",
            "userId",
            "The invitation must contain a valid VLESS UUID.",
        )
    })?;

    let server_address = url
        .host_str()
        .filter(|host| !host.trim().is_empty())
        .ok_or_else(|| {
            invalid(
                "invitation_missing_host",
                "serverAddress",
                "The invitation is missing a server address.",
            )
        })?
        .to_string();

    let server_port = url.port().ok_or_else(|| {
        invalid(
            "invitation_missing_port",
            "serverPort",
            "The invitation is missing a server port.",
        )
    })?;
    if server_port == 0 {
        return Err(invalid(
            "invitation_invalid_port",
            "serverPort",
            "The server port must be between 1 and 65535.",
        ));
    }

    let parameters = collect_parameters(&url)?;
    require_value(&parameters, "encryption", "encryption")?
        .eq("none")
        .then_some(())
        .ok_or_else(|| {
            invalid(
                "invitation_unsupported_encryption",
                "encryption",
                "VLESS encryption must be set to none.",
            )
        })?;

    let security = require_value(&parameters, "security", "security")?;
    if security != "reality" {
        return Err(invalid(
            "invitation_unsupported_security",
            "security",
            "The invitation must use REALITY security.",
        ));
    }

    let transport = require_value(&parameters, "type", "transport")?;
    if transport != "tcp" && transport != "raw" {
        return Err(invalid(
            "invitation_unsupported_transport",
            "transport",
            "Only TCP/RAW transport is supported.",
        ));
    }

    if let Some(header_type) = parameters.get("headerType") {
        if header_type != "none" {
            return Err(invalid(
                "invitation_unsupported_header",
                "headerType",
                "TCP header type must be none.",
            ));
        }
    }

    let flow = require_value(&parameters, "flow", "flow")?;
    if !SUPPORTED_FLOWS.contains(&flow) {
        return Err(invalid(
            "invitation_unsupported_flow",
            "flow",
            "The invitation uses an unsupported XTLS flow.",
        ));
    }

    let server_name = require_value(&parameters, "sni", "serverName")?;
    validate_server_name(server_name)?;

    let fingerprint = require_value(&parameters, "fp", "fingerprint")?;
    if !SUPPORTED_FINGERPRINTS.contains(&fingerprint) {
        return Err(invalid(
            "invitation_unsupported_fingerprint",
            "fingerprint",
            "The invitation uses an unsupported TLS fingerprint.",
        ));
    }

    let reality_password = require_value(&parameters, "pbk", "realityPassword")?;
    validate_reality_password(reality_password)?;

    let short_id = parameters.get("sid").cloned().unwrap_or_default();
    validate_short_id(&short_id)?;

    let spider_x = parameters
        .get("spx")
        .cloned()
        .unwrap_or_else(|| "/".to_string());

    let name = url
        .fragment()
        .and_then(|value| percent_decode_str(value).decode_utf8().ok())
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| server_address.clone());

    Ok(RealityProfile {
        name,
        server_address,
        server_port,
        user_id,
        flow: flow.to_string(),
        server_name: server_name.to_string(),
        fingerprint: fingerprint.to_string(),
        reality_password: reality_password.to_string(),
        short_id,
        spider_x,
    })
}

fn collect_parameters(url: &Url) -> Result<HashMap<String, String>, ClientError> {
    let mut parameters = HashMap::new();

    for (key, value) in url.query_pairs() {
        if SINGLE_VALUE_PARAMETERS.contains(&key.as_ref()) && parameters.contains_key(key.as_ref())
        {
            return Err(invalid(
                "invitation_duplicate_parameter",
                key.as_ref(),
                format!("The invitation contains duplicate {key} parameters."),
            ));
        }
        parameters.insert(key.into_owned(), value.into_owned());
    }

    Ok(parameters)
}

fn require_value<'a>(
    parameters: &'a HashMap<String, String>,
    key: &str,
    field: &str,
) -> Result<&'a str, ClientError> {
    parameters
        .get(key)
        .map(String::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            invalid(
                "invitation_missing_parameter",
                field,
                format!("The invitation is missing {key}."),
            )
        })
}

fn validate_server_name(value: &str) -> Result<(), ClientError> {
    if value.len() > 253
        || value.chars().any(char::is_whitespace)
        || value.contains('/')
        || value.contains(':')
    {
        return Err(invalid(
            "invitation_invalid_server_name",
            "serverName",
            "The REALITY server name is invalid.",
        ));
    }
    Ok(())
}

fn validate_reality_password(value: &str) -> Result<(), ClientError> {
    let bytes = URL_SAFE_NO_PAD.decode(value).map_err(|_| {
        invalid(
            "invitation_invalid_reality_password",
            "realityPassword",
            "The REALITY password/public key is not valid base64url.",
        )
    })?;

    if bytes.len() != 32 {
        return Err(invalid(
            "invitation_invalid_reality_password",
            "realityPassword",
            "The REALITY password/public key must decode to 32 bytes.",
        ));
    }
    Ok(())
}

fn validate_short_id(value: &str) -> Result<(), ClientError> {
    if value.len() > 16
        || !value.len().is_multiple_of(2)
        || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(invalid(
            "invitation_invalid_short_id",
            "shortId",
            "The REALITY short ID must be an even-length hexadecimal value up to 16 characters.",
        ));
    }
    Ok(())
}

fn invalid(code: &str, field: &str, message: impl Into<String>) -> ClientError {
    ClientError::invalid_invitation(code, field, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_INVITATION: &str = "vless://11111111-1111-4111-8111-111111111111@203.0.113.10:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.example.com&fp=chrome&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sid=753bd0a1&type=tcp&headerType=none#Friend%20One";

    #[test]
    fn parses_supported_reality_invitation() {
        let profile = parse_invitation(VALID_INVITATION).expect("valid invitation");

        assert_eq!(profile.name, "Friend One");
        assert_eq!(profile.server_address, "203.0.113.10");
        assert_eq!(profile.server_port, 443);
        assert_eq!(profile.flow, "xtls-rprx-vision");
        assert_eq!(profile.server_name, "www.example.com");
        assert_eq!(profile.short_id, "753bd0a1");
    }

    #[test]
    fn rejects_duplicate_security_parameter() {
        let invitation =
            VALID_INVITATION.replace("security=reality", "security=reality&security=none");
        let error = parse_invitation(&invitation).expect_err("duplicate must fail");

        assert_eq!(error.code, "invitation_duplicate_parameter");
        assert_eq!(error.field.as_deref(), Some("security"));
    }

    #[test]
    fn rejects_odd_short_id() {
        let invitation = VALID_INVITATION.replace("sid=753bd0a1", "sid=123");
        let error = parse_invitation(&invitation).expect_err("odd short id must fail");

        assert_eq!(error.code, "invitation_invalid_short_id");
    }

    #[test]
    fn rejects_zero_port() {
        let invitation = VALID_INVITATION.replace(":443", ":0");
        let error = parse_invitation(&invitation).expect_err("zero port must fail");

        assert_eq!(error.code, "invitation_invalid_port");
    }

    #[test]
    fn rejects_invalid_reality_password() {
        let invitation =
            VALID_INVITATION.replace("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "not-a-key");
        let error = parse_invitation(&invitation).expect_err("invalid password must fail");

        assert_eq!(error.code, "invitation_invalid_reality_password");
    }

    #[test]
    fn debug_output_redacts_credentials() {
        let profile = parse_invitation(VALID_INVITATION).expect("valid invitation");
        let output = format!("{profile:?}");

        assert!(!output.contains("11111111-1111-4111-8111-111111111111"));
        assert!(!output.contains("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"));
        assert!(!output.contains("753bd0a1"));
        assert!(output.contains("[redacted]"));
    }
}
