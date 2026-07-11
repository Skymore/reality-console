//! Stable API error envelope and forward-compatible error codes.

use crate::id::RequestId;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fmt;

/// Stable API error codes understood by protocol version 1.
///
/// Unknown values are retained so an older client can report a newer server
/// code while presenting its generic localized fallback.
#[derive(Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ErrorCode {
    /// Authentication failed without revealing which credential field failed.
    AuthenticationFailed,
    /// The caller is authenticated but lacks the required scope.
    Forbidden,
    /// A one-time invitation is invalid.
    InvitationInvalid,
    /// A one-time invitation has expired.
    InvitationExpired,
    /// A one-time invitation was already consumed.
    InvitationConsumed,
    /// A one-time invitation was cancelled.
    InvitationCancelled,
    /// An account is disabled or deleted.
    AccountDisabled,
    /// A member device has been revoked.
    DeviceRevoked,
    /// A node or node key has been revoked.
    NodeRevoked,
    /// A rotated refresh credential was reused.
    RefreshCredentialReuse,
    /// A request signature or signed artifact is invalid.
    SignatureInvalid,
    /// The request nonce was already used.
    NonceReplayed,
    /// The request timestamp is outside the accepted skew window.
    ClockSkew,
    /// The participant cannot safely interpret the schema.
    SchemaUnsupported,
    /// A stale revision or bundle generation was supplied.
    StateStale,
    /// State conflicts with a newer unresolved local result.
    StateConflict,
    /// A state transition is not monotonic.
    InvalidStateTransition,
    /// Structured input failed validation.
    ValidationFailed,
    /// A validated Xray candidate could not be started.
    XrayStartFailed,
    /// A started Xray candidate failed bounded local health checks.
    XrayUnhealthy,
    /// The previously applied Xray revision could not be restored safely.
    RollbackFailed,
    /// An ordered telemetry batch contains a gap.
    TelemetrySequenceGap,
    /// A request conflicts with current resource state.
    Conflict,
    /// The caller exceeded a configured request rate.
    RateLimited,
    /// No resource exists at the requested path or identity.
    NotFound,
    /// The HTTP method is not supported by the matched resource.
    MethodNotAllowed,
    /// The request body exceeds the service's configured bound.
    RequestTooLarge,
    /// A transient dependency or service is unavailable.
    ServiceUnavailable,
    /// An unexpected internal failure occurred.
    Internal,
    /// A newer stable code not known to this crate version.
    Unknown(String),
}

impl ErrorCode {
    /// Returns the stable snake-case wire code.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::AuthenticationFailed => "authentication_failed",
            Self::Forbidden => "forbidden",
            Self::InvitationInvalid => "invitation_invalid",
            Self::InvitationExpired => "invitation_expired",
            Self::InvitationConsumed => "invitation_consumed",
            Self::InvitationCancelled => "invitation_cancelled",
            Self::AccountDisabled => "account_disabled",
            Self::DeviceRevoked => "device_revoked",
            Self::NodeRevoked => "node_revoked",
            Self::RefreshCredentialReuse => "refresh_credential_reuse",
            Self::SignatureInvalid => "signature_invalid",
            Self::NonceReplayed => "nonce_replayed",
            Self::ClockSkew => "clock_skew",
            Self::SchemaUnsupported => "schema_unsupported",
            Self::StateStale => "state_stale",
            Self::StateConflict => "state_conflict",
            Self::InvalidStateTransition => "invalid_state_transition",
            Self::ValidationFailed => "validation_failed",
            Self::XrayStartFailed => "xray_start_failed",
            Self::XrayUnhealthy => "xray_unhealthy",
            Self::RollbackFailed => "rollback_failed",
            Self::TelemetrySequenceGap => "telemetry_sequence_gap",
            Self::Conflict => "conflict",
            Self::RateLimited => "rate_limited",
            Self::NotFound => "not_found",
            Self::MethodNotAllowed => "method_not_allowed",
            Self::RequestTooLarge => "request_too_large",
            Self::ServiceUnavailable => "service_unavailable",
            Self::Internal => "internal",
            Self::Unknown(code) => code,
        }
    }

    fn from_wire(code: String) -> Self {
        match code.as_str() {
            "authentication_failed" => Self::AuthenticationFailed,
            "forbidden" => Self::Forbidden,
            "invitation_invalid" => Self::InvitationInvalid,
            "invitation_expired" => Self::InvitationExpired,
            "invitation_consumed" => Self::InvitationConsumed,
            "invitation_cancelled" => Self::InvitationCancelled,
            "account_disabled" => Self::AccountDisabled,
            "device_revoked" => Self::DeviceRevoked,
            "node_revoked" => Self::NodeRevoked,
            "refresh_credential_reuse" => Self::RefreshCredentialReuse,
            "signature_invalid" => Self::SignatureInvalid,
            "nonce_replayed" => Self::NonceReplayed,
            "clock_skew" => Self::ClockSkew,
            "schema_unsupported" => Self::SchemaUnsupported,
            "state_stale" => Self::StateStale,
            "state_conflict" => Self::StateConflict,
            "invalid_state_transition" => Self::InvalidStateTransition,
            "validation_failed" => Self::ValidationFailed,
            "xray_start_failed" => Self::XrayStartFailed,
            "xray_unhealthy" => Self::XrayUnhealthy,
            "rollback_failed" => Self::RollbackFailed,
            "telemetry_sequence_gap" => Self::TelemetrySequenceGap,
            "conflict" => Self::Conflict,
            "rate_limited" => Self::RateLimited,
            "not_found" => Self::NotFound,
            "method_not_allowed" => Self::MethodNotAllowed,
            "request_too_large" => Self::RequestTooLarge,
            "service_unavailable" => Self::ServiceUnavailable,
            "internal" => Self::Internal,
            _ => Self::Unknown(code),
        }
    }
}

impl fmt::Debug for ErrorCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl Serialize for ErrorCode {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for ErrorCode {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Ok(Self::from_wire(String::deserialize(deserializer)?))
    }
}

/// The stable top-level API error response.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ErrorEnvelope {
    /// Error details.
    pub error: ApiError,
}

/// Safe diagnostics returned for a failed API request.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApiError {
    /// Stable machine-readable code.
    pub code: ErrorCode,
    /// Non-secret diagnostic suitable for support output.
    pub message: String,
    /// Request correlation identifier.
    pub request_id: RequestId,
    /// Whether retrying after bounded backoff can succeed unchanged.
    pub retryable: bool,
    /// Bounded, non-secret structured context.
    #[serde(default)]
    pub details: BTreeMap<String, Value>,
}

#[cfg(test)]
mod tests {
    use super::{ApiError, ErrorCode, ErrorEnvelope};
    use crate::id::RequestId;
    use std::collections::BTreeMap;

    #[test]
    fn error_envelope_has_stable_camel_case_shape() {
        let envelope = ErrorEnvelope {
            error: ApiError {
                code: ErrorCode::InvitationExpired,
                message: "The invitation has expired.".to_string(),
                request_id: RequestId::new(),
                retryable: false,
                details: BTreeMap::new(),
            },
        };
        let value = serde_json::to_value(envelope).unwrap();

        assert_eq!(value["error"]["code"], "invitation_expired");
        assert!(value["error"].get("requestId").is_some());
        assert_eq!(value["error"]["details"], serde_json::json!({}));
    }

    #[test]
    fn unknown_codes_survive_round_trip() {
        let code: ErrorCode = serde_json::from_str("\"future_failure\"").unwrap();

        assert_eq!(code, ErrorCode::Unknown("future_failure".to_string()));
        assert_eq!(serde_json::to_string(&code).unwrap(), "\"future_failure\"");
    }

    #[test]
    fn xray_lifecycle_codes_have_stable_wire_values() {
        for (code, expected) in [
            (ErrorCode::XrayStartFailed, "xray_start_failed"),
            (ErrorCode::XrayUnhealthy, "xray_unhealthy"),
            (ErrorCode::RollbackFailed, "rollback_failed"),
        ] {
            assert_eq!(
                serde_json::to_string(&code).unwrap(),
                format!("\"{expected}\"")
            );
            assert_eq!(
                serde_json::from_str::<ErrorCode>(&format!("\"{expected}\"")).unwrap(),
                code
            );
        }
    }
}
