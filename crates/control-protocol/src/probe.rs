//! Minimal contract for an untrusted external TCP preflight executor.

use crate::id::RequestId;
use crate::validation::{ProtocolValidationError, ValidationCode};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::Ipv4Addr;

/// Current external TCP executor request/response schema.
pub const TCP_PROBE_EXECUTOR_SCHEMA_VERSION: u16 = 1;
/// Cloudflare Workers currently allow six simultaneous outgoing connections.
pub const MAX_TCP_PROBE_TARGETS: usize = 6;
/// Smallest useful TCP connect timeout accepted by the executor contract.
pub const MIN_TCP_PROBE_TIMEOUT_MILLIS: u32 = 100;
/// Largest TCP connect timeout accepted by the executor contract.
pub const MAX_TCP_PROBE_TIMEOUT_MILLIS: u32 = 10_000;
const MAX_REPORTED_LATENCY_SLOP_MILLIS: u32 = 1_000;

/// One controller-resolved, privacy-minimized external TCP preflight request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TcpProbeExecutorRequest {
    /// Closed request schema version.
    pub schema_version: u16,
    /// Per-call correlation identity with no node or member meaning.
    pub request_id: RequestId,
    /// Controller-resolved globally publishable IPv4 addresses.
    pub targets: Vec<Ipv4Addr>,
    /// Public TCP port from the node's signed applied revision.
    pub port: u16,
    /// End-to-end connection deadline for this call.
    pub timeout_millis: u32,
}

impl TcpProbeExecutorRequest {
    /// Validates the closed executor request before any network operation.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolValidationError`] for an unsupported schema, unsafe or
    /// duplicate address, invalid port, or timeout outside the bounded policy.
    pub fn validate(&self) -> Result<(), ProtocolValidationError> {
        if self.schema_version != TCP_PROBE_EXECUTOR_SCHEMA_VERSION {
            return Err(ProtocolValidationError::new(
                ValidationCode::UnsupportedSchema,
                "schemaVersion",
                "TCP probe executor schema is not supported",
            ));
        }
        if self.targets.is_empty() || self.targets.len() > MAX_TCP_PROBE_TARGETS {
            return Err(ProtocolValidationError::new(
                ValidationCode::OutOfRange,
                "targets",
                "TCP probe targets must contain between one and six addresses",
            ));
        }
        if self
            .targets
            .iter()
            .any(|target| !is_public_probe_ipv4(*target))
        {
            return Err(ProtocolValidationError::new(
                ValidationCode::InvalidFormat,
                "targets",
                "TCP probe targets must be globally publishable IPv4 addresses",
            ));
        }
        if self.targets.iter().collect::<HashSet<_>>().len() != self.targets.len() {
            return Err(ProtocolValidationError::new(
                ValidationCode::DuplicateIdentity,
                "targets",
                "TCP probe targets must be unique",
            ));
        }
        if self.port == 0 || self.port == 25 {
            return Err(ProtocolValidationError::new(
                ValidationCode::OutOfRange,
                "port",
                "TCP probe port must be non-zero and supported by the executor",
            ));
        }
        if !(MIN_TCP_PROBE_TIMEOUT_MILLIS..=MAX_TCP_PROBE_TIMEOUT_MILLIS)
            .contains(&self.timeout_millis)
        {
            return Err(ProtocolValidationError::new(
                ValidationCode::OutOfRange,
                "timeoutMillis",
                "TCP probe timeout is outside the supported range",
            ));
        }
        Ok(())
    }
}

/// Secret-free result produced by an external TCP executor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "status",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum TcpProbeExecutorResult {
    /// At least one pinned target accepted a TCP connection.
    Connected {
        /// Exact pinned address that accepted the connection.
        resolved_address: Ipv4Addr,
        /// Executor-observed connection latency.
        latency_millis: u32,
    },
    /// Every pinned target rejected or failed the connection attempt.
    Unreachable {
        /// Time until all attempts reached a terminal failure.
        latency_millis: u32,
    },
    /// The executor closed all attempts at the request deadline.
    TimedOut {
        /// Executor-observed time at deadline handling.
        latency_millis: u32,
    },
    /// The executor could not perform a trustworthy attempt.
    ExecutorFailed,
}

/// One bounded external TCP executor response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TcpProbeExecutorResponse {
    /// Closed response schema version.
    pub schema_version: u16,
    /// Must exactly echo the request correlation identity.
    pub request_id: RequestId,
    /// Secret-free connection outcome.
    pub result: TcpProbeExecutorResult,
}

impl TcpProbeExecutorResponse {
    /// Validates that this response is bounded and belongs to `request`.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolValidationError`] when the schema or request identity
    /// differs, the connected address was not pinned by the request, or the
    /// reported latency exceeds the bounded deadline allowance.
    pub fn validate_for(
        &self,
        request: &TcpProbeExecutorRequest,
    ) -> Result<(), ProtocolValidationError> {
        request.validate()?;
        if self.schema_version != TCP_PROBE_EXECUTOR_SCHEMA_VERSION {
            return Err(ProtocolValidationError::new(
                ValidationCode::UnsupportedSchema,
                "schemaVersion",
                "TCP probe executor response schema is not supported",
            ));
        }
        if self.request_id != request.request_id {
            return Err(ProtocolValidationError::new(
                ValidationCode::IdentityMismatch,
                "requestId",
                "TCP probe executor response belongs to another request",
            ));
        }
        if let TcpProbeExecutorResult::Connected {
            resolved_address, ..
        } = self.result
        {
            if !request.targets.contains(&resolved_address) {
                return Err(ProtocolValidationError::new(
                    ValidationCode::IdentityMismatch,
                    "result.resolvedAddress",
                    "TCP probe executor connected to an unrequested address",
                ));
            }
        }
        let latency = match self.result {
            TcpProbeExecutorResult::Connected { latency_millis, .. }
            | TcpProbeExecutorResult::Unreachable { latency_millis }
            | TcpProbeExecutorResult::TimedOut { latency_millis } => Some(latency_millis),
            TcpProbeExecutorResult::ExecutorFailed => None,
        };
        if latency.is_some_and(|latency| {
            latency
                > request
                    .timeout_millis
                    .saturating_add(MAX_REPORTED_LATENCY_SLOP_MILLIS)
        }) {
            return Err(ProtocolValidationError::new(
                ValidationCode::OutOfRange,
                "result.latencyMillis",
                "TCP probe executor latency exceeds the request deadline allowance",
            ));
        }
        Ok(())
    }
}

/// Returns whether an IPv4 address is safe for a public TCP preflight target.
#[must_use]
pub fn is_public_probe_ipv4(address: Ipv4Addr) -> bool {
    let octets = address.octets();
    !address.is_private()
        && !address.is_loopback()
        && !address.is_link_local()
        && !address.is_unspecified()
        && !address.is_multicast()
        && !address.is_broadcast()
        && !address.is_documentation()
        && !(octets[0] == 100 && (64..=127).contains(&octets[1]))
        && !(octets[0] == 192 && octets[1] == 0 && octets[2] == 0)
        && !(octets[0] == 198 && (octets[1] == 18 || octets[1] == 19))
        && octets[0] != 0
        && octets[0] < 240
}

#[cfg(test)]
mod tests {
    use super::{
        is_public_probe_ipv4, TcpProbeExecutorRequest, TcpProbeExecutorResponse,
        TcpProbeExecutorResult, TCP_PROBE_EXECUTOR_SCHEMA_VERSION,
    };
    use crate::id::RequestId;
    use std::net::Ipv4Addr;

    fn request() -> TcpProbeExecutorRequest {
        TcpProbeExecutorRequest {
            schema_version: TCP_PROBE_EXECUTOR_SCHEMA_VERSION,
            request_id: RequestId::new(),
            targets: vec![Ipv4Addr::new(8, 8, 8, 8), Ipv4Addr::new(1, 1, 1, 1)],
            port: 443,
            timeout_millis: 5_000,
        }
    }

    #[test]
    fn request_rejects_unsafe_duplicate_and_provider_blocked_targets() {
        let mut value = request();
        value.targets = vec![Ipv4Addr::LOCALHOST];
        assert!(value.validate().is_err());

        let mut value = request();
        value.targets = vec![Ipv4Addr::new(8, 8, 8, 8); 2];
        assert!(value.validate().is_err());

        let mut value = request();
        value.port = 25;
        assert!(value.validate().is_err());
        assert!(is_public_probe_ipv4(Ipv4Addr::new(8, 8, 4, 4)));
        assert!(!is_public_probe_ipv4(Ipv4Addr::new(100, 64, 0, 1)));
    }

    #[test]
    fn response_is_bound_to_the_request_and_pinned_address_set() {
        let request = request();
        let response = TcpProbeExecutorResponse {
            schema_version: TCP_PROBE_EXECUTOR_SCHEMA_VERSION,
            request_id: request.request_id,
            result: TcpProbeExecutorResult::Connected {
                resolved_address: request.targets[0],
                latency_millis: 12,
            },
        };
        assert!(response.validate_for(&request).is_ok());

        let mut wrong_request = response;
        wrong_request.request_id = RequestId::new();
        assert!(wrong_request.validate_for(&request).is_err());

        let mut wrong_target = response;
        wrong_target.result = TcpProbeExecutorResult::Connected {
            resolved_address: Ipv4Addr::new(9, 9, 9, 9),
            latency_millis: 12,
        };
        assert!(wrong_target.validate_for(&request).is_err());
    }

    #[test]
    fn wire_shape_is_closed_and_camel_case() {
        let request = request();
        let json = serde_json::to_value(&request).unwrap();
        assert_eq!(json["schemaVersion"], 1);
        assert_eq!(json["targets"][0], "8.8.8.8");
        assert!(json.get("request_id").is_none());

        let mut with_unknown = json;
        with_unknown["nodeId"] = serde_json::json!(RequestId::new());
        assert!(serde_json::from_value::<TcpProbeExecutorRequest>(with_unknown).is_err());

        let response = TcpProbeExecutorResponse {
            schema_version: TCP_PROBE_EXECUTOR_SCHEMA_VERSION,
            request_id: request.request_id,
            result: TcpProbeExecutorResult::Connected {
                resolved_address: request.targets[0],
                latency_millis: 9,
            },
        };
        let json = serde_json::to_value(response).unwrap();
        assert_eq!(json["result"]["status"], "connected");
        assert_eq!(json["result"]["resolvedAddress"], "8.8.8.8");
        assert_eq!(json["result"]["latencyMillis"], 9);
        assert!(json["result"].get("resolved_address").is_none());
    }
}
