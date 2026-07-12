use std::io;

use thiserror::Error;

/// Stable, payload-safe relay error codes.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ErrorCode {
    #[error("relay_protocol_invalid")]
    ProtocolInvalid,
    #[error("relay_frame_too_large")]
    FrameTooLarge,
    #[error("relay_auth_failed")]
    AuthFailed,
    #[error("relay_route_unknown")]
    RouteUnknown,
    #[error("relay_grant_expired")]
    GrantExpired,
    #[error("relay_route_unavailable")]
    RouteUnavailable,
    #[error("relay_limit_reached")]
    LimitReached,
    #[error("relay_open_timeout")]
    OpenTimeout,
    #[error("relay_idle_timeout")]
    IdleTimeout,
    #[error("relay_tunnel_lost")]
    TunnelLost,
    #[error("relay_route_revoked")]
    RouteRevoked,
    #[error("relay_internal")]
    Internal,
}

impl ErrorCode {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ProtocolInvalid => "relay_protocol_invalid",
            Self::FrameTooLarge => "relay_frame_too_large",
            Self::AuthFailed => "relay_auth_failed",
            Self::RouteUnknown => "relay_route_unknown",
            Self::GrantExpired => "relay_grant_expired",
            Self::RouteUnavailable => "relay_route_unavailable",
            Self::LimitReached => "relay_limit_reached",
            Self::OpenTimeout => "relay_open_timeout",
            Self::IdleTimeout => "relay_idle_timeout",
            Self::TunnelLost => "relay_tunnel_lost",
            Self::RouteRevoked => "relay_route_revoked",
            Self::Internal => "relay_internal",
        }
    }

    #[must_use]
    pub fn from_wire(value: &[u8]) -> Option<Self> {
        match value {
            b"relay_protocol_invalid" => Some(Self::ProtocolInvalid),
            b"relay_frame_too_large" => Some(Self::FrameTooLarge),
            b"relay_auth_failed" => Some(Self::AuthFailed),
            b"relay_route_unknown" => Some(Self::RouteUnknown),
            b"relay_grant_expired" => Some(Self::GrantExpired),
            b"relay_route_unavailable" => Some(Self::RouteUnavailable),
            b"relay_limit_reached" => Some(Self::LimitReached),
            b"relay_open_timeout" => Some(Self::OpenTimeout),
            b"relay_idle_timeout" => Some(Self::IdleTimeout),
            b"relay_tunnel_lost" => Some(Self::TunnelLost),
            b"relay_route_revoked" => Some(Self::RouteRevoked),
            b"relay_internal" => Some(Self::Internal),
            _ => None,
        }
    }
}

/// Internal relay failure with a stable externally reportable code.
#[derive(Debug, Error)]
pub enum RelayError {
    #[error("{code}: {message}")]
    Stable {
        code: ErrorCode,
        message: &'static str,
    },
    #[error("relay_io: {0}")]
    Io(#[from] io::Error),
    #[error("relay_tls: {0}")]
    Tls(String),
    #[error("relay_config: {0}")]
    Config(String),
}

impl RelayError {
    #[must_use]
    pub const fn stable(code: ErrorCode, message: &'static str) -> Self {
        Self::Stable { code, message }
    }

    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        match self {
            Self::Stable { code, .. } => *code,
            Self::Io(_) | Self::Tls(_) | Self::Config(_) => ErrorCode::Internal,
        }
    }

    #[must_use]
    pub fn operational_code(&self) -> &str {
        match self {
            Self::Config(message) if message.starts_with("managed_route") => message,
            _ => self.code().as_str(),
        }
    }
}

pub type Result<T> = std::result::Result<T, RelayError>;
