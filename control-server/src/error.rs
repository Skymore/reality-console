use crate::protocol::RequestId;
use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use control_protocol::error::{ApiError as ErrorBody, ErrorCode, ErrorEnvelope};
use std::collections::BTreeMap;

pub const REQUEST_ID_HEADER: &str = "x-request-id";

#[derive(Debug)]
pub struct ApiError {
    status: StatusCode,
    body: ErrorEnvelope,
}

impl ApiError {
    #[must_use]
    pub fn authentication_failed(request_id: RequestId) -> Self {
        Self::new(
            StatusCode::UNAUTHORIZED,
            ErrorCode::AuthenticationFailed,
            "Authentication failed.",
            request_id,
            false,
        )
    }

    #[must_use]
    pub fn not_found(request_id: RequestId) -> Self {
        Self::new(
            StatusCode::NOT_FOUND,
            ErrorCode::NotFound,
            "The requested resource was not found.",
            request_id,
            false,
        )
    }

    #[must_use]
    pub fn method_not_allowed(request_id: RequestId) -> Self {
        Self::new(
            StatusCode::METHOD_NOT_ALLOWED,
            ErrorCode::MethodNotAllowed,
            "The request method is not allowed for this resource.",
            request_id,
            false,
        )
    }

    #[must_use]
    pub fn body_too_large(request_id: RequestId) -> Self {
        Self::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            ErrorCode::RequestTooLarge,
            "The request body exceeds the service limit.",
            request_id,
            false,
        )
    }

    #[must_use]
    pub fn validation_failed(request_id: RequestId) -> Self {
        Self::new(
            StatusCode::BAD_REQUEST,
            ErrorCode::ValidationFailed,
            "The request body is invalid.",
            request_id,
            false,
        )
    }

    #[must_use]
    pub fn invitation_invalid(request_id: RequestId) -> Self {
        Self::new(
            StatusCode::NOT_FOUND,
            ErrorCode::InvitationInvalid,
            "The invitation is invalid.",
            request_id,
            false,
        )
    }

    #[must_use]
    pub fn invitation_expired(request_id: RequestId) -> Self {
        Self::new(
            StatusCode::GONE,
            ErrorCode::InvitationExpired,
            "The invitation has expired.",
            request_id,
            false,
        )
    }

    #[must_use]
    pub fn invitation_consumed(request_id: RequestId) -> Self {
        Self::new(
            StatusCode::CONFLICT,
            ErrorCode::InvitationConsumed,
            "The invitation was already consumed.",
            request_id,
            false,
        )
    }

    #[must_use]
    pub fn invitation_cancelled(request_id: RequestId) -> Self {
        Self::new(
            StatusCode::GONE,
            ErrorCode::InvitationCancelled,
            "The invitation was cancelled.",
            request_id,
            false,
        )
    }

    #[must_use]
    pub fn activation_invalid(request_id: RequestId) -> Self {
        Self::new(
            StatusCode::NOT_FOUND,
            ErrorCode::ActivationInvalid,
            "The device activation is invalid.",
            request_id,
            false,
        )
    }

    #[must_use]
    pub fn activation_expired(request_id: RequestId) -> Self {
        Self::new(
            StatusCode::GONE,
            ErrorCode::ActivationExpired,
            "The device activation has expired.",
            request_id,
            false,
        )
    }

    #[must_use]
    pub fn activation_consumed(request_id: RequestId) -> Self {
        Self::new(
            StatusCode::CONFLICT,
            ErrorCode::ActivationConsumed,
            "The device activation was already consumed.",
            request_id,
            false,
        )
    }

    #[must_use]
    pub fn account_reset_invalid(request_id: RequestId) -> Self {
        Self::new(
            StatusCode::NOT_FOUND,
            ErrorCode::Unknown("account_reset_invalid".to_string()),
            "The account reset token is invalid.",
            request_id,
            false,
        )
    }

    #[must_use]
    pub fn account_reset_expired(request_id: RequestId) -> Self {
        Self::new(
            StatusCode::GONE,
            ErrorCode::Unknown("account_reset_expired".to_string()),
            "The account reset token has expired.",
            request_id,
            false,
        )
    }

    #[must_use]
    pub fn account_reset_consumed(request_id: RequestId) -> Self {
        Self::new(
            StatusCode::CONFLICT,
            ErrorCode::Unknown("account_reset_consumed".to_string()),
            "The account reset token was already consumed.",
            request_id,
            false,
        )
    }

    #[must_use]
    pub fn rollback_target_invalid(request_id: RequestId) -> Self {
        Self::new(
            StatusCode::CONFLICT,
            ErrorCode::Unknown("rollback_target_invalid".to_string()),
            "The rollback source or failed revision is not eligible.",
            request_id,
            false,
        )
    }

    #[must_use]
    pub fn rollback_target_incompatible(request_id: RequestId) -> Self {
        Self::new(
            StatusCode::CONFLICT,
            ErrorCode::Unknown("rollback_target_incompatible".to_string()),
            "The rollback source is incompatible with the current node.",
            request_id,
            false,
        )
    }

    #[must_use]
    pub fn account_disabled(request_id: RequestId) -> Self {
        Self::new(
            StatusCode::FORBIDDEN,
            ErrorCode::AccountDisabled,
            "The account is disabled.",
            request_id,
            false,
        )
    }

    #[must_use]
    pub fn refresh_reuse(request_id: RequestId) -> Self {
        Self::new(
            StatusCode::UNAUTHORIZED,
            ErrorCode::RefreshCredentialReuse,
            "The refresh credential was reused and its session was revoked.",
            request_id,
            false,
        )
    }

    #[must_use]
    pub fn signature_invalid(request_id: RequestId) -> Self {
        Self::new(
            StatusCode::UNAUTHORIZED,
            ErrorCode::SignatureInvalid,
            "The request signature or proof is invalid.",
            request_id,
            false,
        )
    }

    #[must_use]
    pub fn node_revoked(request_id: RequestId) -> Self {
        Self::new(
            StatusCode::FORBIDDEN,
            ErrorCode::NodeRevoked,
            "The node or node credential is revoked.",
            request_id,
            false,
        )
    }

    #[must_use]
    pub fn nonce_replayed(request_id: RequestId) -> Self {
        Self::new(
            StatusCode::CONFLICT,
            ErrorCode::NonceReplayed,
            "The request nonce was already used.",
            request_id,
            false,
        )
    }

    #[must_use]
    pub fn clock_skew(request_id: RequestId) -> Self {
        Self::new(
            StatusCode::UNAUTHORIZED,
            ErrorCode::ClockSkew,
            "The request timestamp is outside the accepted clock window.",
            request_id,
            true,
        )
    }

    #[must_use]
    pub fn state_stale(request_id: RequestId) -> Self {
        Self::new(
            StatusCode::CONFLICT,
            ErrorCode::StateStale,
            "The node reported progress older than its durable state.",
            request_id,
            false,
        )
    }

    #[must_use]
    pub fn state_conflict(request_id: RequestId) -> Self {
        Self::new(
            StatusCode::CONFLICT,
            ErrorCode::StateConflict,
            "The reported state conflicts with authoritative server state.",
            request_id,
            false,
        )
    }

    #[must_use]
    pub fn invalid_state_transition(request_id: RequestId) -> Self {
        Self::new(
            StatusCode::CONFLICT,
            ErrorCode::InvalidStateTransition,
            "The requested state transition is not monotonic.",
            request_id,
            false,
        )
    }

    #[must_use]
    pub fn telemetry_sequence_gap(request_id: RequestId) -> Self {
        Self::new(
            StatusCode::CONFLICT,
            ErrorCode::TelemetrySequenceGap,
            "The telemetry sequence does not match the durable controller cursor.",
            request_id,
            true,
        )
    }

    #[must_use]
    pub fn conflict(request_id: RequestId) -> Self {
        Self::new(
            StatusCode::CONFLICT,
            ErrorCode::Conflict,
            "The requested operation conflicts with the current resource state.",
            request_id,
            false,
        )
    }

    #[must_use]
    pub fn idempotency_key_conflict(request_id: RequestId) -> Self {
        Self::new(
            StatusCode::CONFLICT,
            ErrorCode::IdempotencyKeyConflict,
            "The idempotency key was already used for a different request.",
            request_id,
            false,
        )
    }

    #[must_use]
    pub fn timeout(request_id: RequestId) -> Self {
        Self::new(
            StatusCode::GATEWAY_TIMEOUT,
            ErrorCode::ServiceUnavailable,
            "The request exceeded the service time limit.",
            request_id,
            true,
        )
    }

    #[must_use]
    pub fn internal(request_id: RequestId) -> Self {
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            ErrorCode::Internal,
            "The service could not complete the request.",
            request_id,
            false,
        )
    }

    fn new(
        status: StatusCode,
        code: ErrorCode,
        message: &'static str,
        request_id: RequestId,
        retryable: bool,
    ) -> Self {
        Self {
            status,
            body: ErrorEnvelope {
                error: ErrorBody {
                    code,
                    message: message.to_string(),
                    request_id,
                    retryable,
                    details: BTreeMap::new(),
                },
            },
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let request_id = self.body.error.request_id.to_string();
        let mut response = (self.status, Json(self.body)).into_response();
        if let Ok(value) = HeaderValue::from_str(&request_id) {
            response.headers_mut().insert(REQUEST_ID_HEADER, value);
        }
        response
    }
}
