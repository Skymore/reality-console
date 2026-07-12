//! Ordered, idempotent node telemetry batch contracts.

use crate::id::{Count, NodeId, SequenceNumber, Timestamp, UserId};
use crate::validation::{ProtocolValidationError, ValidationCode};
use serde::{Deserialize, Serialize};

/// Maximum number of telemetry events accepted in one protocol batch.
pub const MAX_TELEMETRY_BATCH_EVENTS: usize = 1_000;
/// Maximum accepted serialized telemetry request size.
pub const MAX_TELEMETRY_BATCH_BYTES: usize = 256 * 1024;
/// Current telemetry upload schema.
pub const TELEMETRY_SCHEMA_VERSION: u16 = 1;

/// Network protocol retained by opt-in detailed connection analytics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum NetworkProtocol {
    /// Transmission Control Protocol.
    Tcp,
    /// User Datagram Protocol.
    Udp,
}

/// Safe quota state reported with essential telemetry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum QuotaStatus {
    /// Usage is below warning thresholds.
    Normal,
    /// Usage is approaching a configured cap.
    NearingLimit,
    /// Usage reached or exceeded a configured cap.
    Exceeded,
}

/// One normalized telemetry event payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "type",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum TelemetryEventKind {
    /// Aggregate per-member deltas, never cumulative counters.
    TrafficDelta {
        /// Stable logical member identity.
        user_id: UserId,
        /// Bytes uploaded since the prior normalized sample.
        bytes_up: Count,
        /// Bytes downloaded since the prior normalized sample.
        bytes_down: Count,
        /// New connection count in the sample window.
        connection_count: Count,
    },
    /// Optional detailed connection metadata with no payloads or full URLs.
    Connection {
        /// Stable logical member identity.
        user_id: UserId,
        /// Network protocol observed.
        protocol: NetworkProtocol,
        /// Destination hostname or IP only, without path or query.
        destination_host: String,
        /// Destination transport port.
        destination_port: u16,
        /// Optional keyed pseudonym or truncated client prefix.
        client_identifier: Option<String>,
    },
    /// Data-quality condition such as counter reset or collection failure.
    CollectionStatus {
        /// Stable bounded diagnostic code.
        code: String,
        /// Whether later samples restored healthy collection.
        recovered: bool,
    },
    /// Current member quota state for the reporting node.
    QuotaState {
        /// Stable logical member identity.
        user_id: UserId,
        /// Current threshold state.
        status: QuotaStatus,
        /// Remaining transfer, when a transfer cap exists.
        remaining_bytes: Option<Count>,
    },
}

impl TelemetryEventKind {
    fn validate(&self) -> Result<(), ProtocolValidationError> {
        match self {
            Self::Connection {
                destination_host,
                destination_port,
                client_identifier,
                ..
            } => {
                validate_text(destination_host, 253, "events.destinationHost")?;
                if destination_host.contains('/')
                    || destination_host.contains('?')
                    || destination_host.contains('#')
                    || destination_host.contains(char::is_whitespace)
                {
                    return Err(ProtocolValidationError::new(
                        ValidationCode::InvalidFormat,
                        "events.destinationHost",
                        "connection telemetry may contain a host only, never a full URL",
                    ));
                }
                if *destination_port == 0 {
                    return Err(ProtocolValidationError::new(
                        ValidationCode::OutOfRange,
                        "events.destinationPort",
                        "destination port must be non-zero",
                    ));
                }
                if let Some(identifier) = client_identifier {
                    validate_text(identifier, 128, "events.clientIdentifier")?;
                }
            }
            Self::CollectionStatus { code, .. } => {
                validate_text(code, 64, "events.code")?;
                if !code
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
                {
                    return Err(ProtocolValidationError::new(
                        ValidationCode::InvalidFormat,
                        "events.code",
                        "collection status code must use lowercase snake case",
                    ));
                }
            }
            Self::TrafficDelta { .. } | Self::QuotaState { .. } => {}
        }
        Ok(())
    }
}

/// One durably sequenced node telemetry event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TelemetryEvent {
    /// Node-local monotonic sequence number.
    pub sequence: SequenceNumber,
    /// Node-observed event time; controller receipt time is stored separately.
    pub occurred_at: Timestamp,
    /// Closed telemetry payload schema.
    #[serde(flatten)]
    pub kind: TelemetryEventKind,
}

/// Bounded contiguous telemetry upload from one authenticated node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TelemetryBatch {
    /// Telemetry schema version.
    pub schema_version: u16,
    /// Authenticated reporting node.
    pub node_id: NodeId,
    /// First sequence included in the batch.
    pub first_sequence: SequenceNumber,
    /// Last sequence included in the batch.
    pub last_sequence: SequenceNumber,
    /// Ordered contiguous event list.
    pub events: Vec<TelemetryEvent>,
}

impl TelemetryBatch {
    /// Validates schema support, bounds, and exact contiguous sequencing.
    ///
    /// # Errors
    ///
    /// Returns an error for unsupported schema, an empty or oversized batch,
    /// mismatched sequence bounds, sequence gaps or overflow, or an invalid
    /// event payload.
    pub fn validate(
        &self,
        supported_schema_versions: &[u16],
    ) -> Result<(), ProtocolValidationError> {
        if !supported_schema_versions.contains(&self.schema_version) {
            return Err(ProtocolValidationError::new(
                ValidationCode::UnsupportedSchema,
                "schemaVersion",
                "telemetry schema version is not supported",
            ));
        }
        if self.events.is_empty() || self.events.len() > MAX_TELEMETRY_BATCH_EVENTS {
            return Err(ProtocolValidationError::new(
                ValidationCode::OutOfRange,
                "events",
                "telemetry batch must contain between 1 and 1000 events",
            ));
        }
        if self.first_sequence.get() == 0 {
            return Err(ProtocolValidationError::new(
                ValidationCode::OutOfRange,
                "firstSequence",
                "telemetry event sequences begin at one",
            ));
        }
        if self.events.first().map(|event| event.sequence) != Some(self.first_sequence)
            || self.events.last().map(|event| event.sequence) != Some(self.last_sequence)
        {
            return Err(ProtocolValidationError::new(
                ValidationCode::SequenceGap,
                "firstSequence",
                "batch sequence bounds must match the first and last events",
            ));
        }

        let mut expected = self.first_sequence;
        for (index, event) in self.events.iter().enumerate() {
            if event.sequence != expected {
                return Err(ProtocolValidationError::new(
                    ValidationCode::SequenceGap,
                    "events.sequence",
                    "telemetry events must be ordered and contiguous",
                ));
            }
            event.kind.validate()?;
            if index + 1 < self.events.len() {
                expected = expected.checked_next().ok_or_else(|| {
                    ProtocolValidationError::new(
                        ValidationCode::OutOfRange,
                        "events.sequence",
                        "telemetry sequence overflowed the protocol range",
                    )
                })?;
            }
        }
        Ok(())
    }
}

/// Durable ingestion acknowledgement for an ordered telemetry upload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TelemetryBatchAcknowledgement {
    /// Highest sequence durably committed for the node.
    pub acknowledged_sequence: SequenceNumber,
    /// Next sequence expected by the controller.
    pub expected_sequence: SequenceNumber,
}

/// Controller-owned durable cursor used to resume or replay a node spool.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TelemetryCursor {
    /// Highest sequence durably committed, or zero before the first event.
    pub acknowledged_sequence: SequenceNumber,
    /// Exact next sequence accepted for a new event.
    pub expected_sequence: SequenceNumber,
}

impl TelemetryCursor {
    /// Validates the adjacent durable cursor pair.
    ///
    /// # Errors
    ///
    /// Returns an error if the expected sequence does not immediately follow
    /// the acknowledgement.
    pub fn validate(self) -> Result<(), ProtocolValidationError> {
        TelemetryBatchAcknowledgement {
            acknowledged_sequence: self.acknowledged_sequence,
            expected_sequence: self.expected_sequence,
        }
        .validate()
    }
}

/// One privacy-bounded aggregate returned to an operator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TrafficAggregate {
    /// Stable logical member identity.
    pub user_id: UserId,
    /// Stable reporting node identity.
    pub node_id: NodeId,
    /// UTC Unix bucket start in seconds.
    pub bucket_start: i64,
    /// Bucket width in seconds.
    pub bucket_seconds: u32,
    /// Sum of normalized upload deltas.
    pub bytes_up: Count,
    /// Sum of normalized download deltas.
    pub bytes_down: Count,
    /// Sum of normalized connection deltas.
    pub connection_count: Count,
}

impl TrafficAggregate {
    /// Validates one aggregate without claiming destination-level accuracy.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsupported bucket width or misaligned bucket.
    pub fn validate(&self) -> Result<(), ProtocolValidationError> {
        if !matches!(self.bucket_seconds, 3_600 | 86_400)
            || self.bucket_start < 0
            || self.bucket_start % i64::from(self.bucket_seconds) != 0
        {
            return Err(ProtocolValidationError::new(
                ValidationCode::OutOfRange,
                "bucketStart",
                "traffic aggregate bucket is invalid",
            ));
        }
        Ok(())
    }
}

/// Result of one age-based telemetry retention pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TelemetryRetentionResult {
    /// Raw traffic delta rows removed after hourly aggregation retention.
    pub traffic_events_deleted: u64,
    /// Detailed connection rows removed.
    pub detailed_events_deleted: u64,
    /// Transient health and quality rows removed.
    pub health_events_deleted: u64,
    /// Hourly aggregate rows removed.
    pub hourly_aggregates_deleted: u64,
    /// Daily aggregate rows removed.
    pub daily_aggregates_deleted: u64,
}

impl TelemetryBatchAcknowledgement {
    /// Validates that the expected cursor immediately follows the acknowledgement.
    ///
    /// # Errors
    ///
    /// Returns an error when `expected_sequence` is not exactly one greater
    /// than `acknowledged_sequence`, including overflow at the numeric limit.
    pub fn validate(self) -> Result<(), ProtocolValidationError> {
        if self.acknowledged_sequence.checked_next() != Some(self.expected_sequence) {
            return Err(ProtocolValidationError::new(
                ValidationCode::SequenceGap,
                "expectedSequence",
                "expected sequence must immediately follow the durable acknowledgement",
            ));
        }
        Ok(())
    }
}

fn validate_text(
    value: &str,
    maximum_length: usize,
    field: &'static str,
) -> Result<(), ProtocolValidationError> {
    if value.is_empty() {
        return Err(ProtocolValidationError::new(
            ValidationCode::MissingField,
            field,
            "value is required",
        ));
    }
    if value.len() > maximum_length || value.chars().any(char::is_control) {
        return Err(ProtocolValidationError::new(
            ValidationCode::OutOfRange,
            field,
            "value exceeds its length or character bound",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{TelemetryBatch, TelemetryEvent, TelemetryEventKind};
    use crate::id::{Count, NodeId, SequenceNumber, Timestamp, UserId};

    fn event(sequence: i64) -> TelemetryEvent {
        TelemetryEvent {
            sequence: SequenceNumber::new(sequence).unwrap(),
            occurred_at: "2026-07-11T20:00:00Z".parse::<Timestamp>().unwrap(),
            kind: TelemetryEventKind::TrafficDelta {
                user_id: UserId::new(),
                bytes_up: Count::new(10).unwrap(),
                bytes_down: Count::new(20).unwrap(),
                connection_count: Count::new(1).unwrap(),
            },
        }
    }

    #[test]
    fn telemetry_batch_requires_exact_contiguous_sequences() {
        let batch = TelemetryBatch {
            schema_version: 1,
            node_id: NodeId::new(),
            first_sequence: SequenceNumber::new(7).unwrap(),
            last_sequence: SequenceNumber::new(8).unwrap(),
            events: vec![event(7), event(8)],
        };
        assert!(batch.validate(&[1]).is_ok());

        let mut gap = batch.clone();
        gap.events[1].sequence = SequenceNumber::new(9).unwrap();
        gap.last_sequence = SequenceNumber::new(9).unwrap();
        assert!(gap.validate(&[1]).is_err());
    }

    #[test]
    fn telemetry_event_serialization_is_tagged_and_camel_case() {
        let value = serde_json::to_value(event(4)).unwrap();

        assert_eq!(value["sequence"], 4);
        assert_eq!(value["type"], "trafficDelta");
        assert_eq!(value["bytesUp"], 10);
        assert!(value.get("occurredAt").is_some());
    }

    #[test]
    fn detailed_events_reject_full_urls() {
        let kind = TelemetryEventKind::Connection {
            user_id: UserId::new(),
            protocol: super::NetworkProtocol::Tcp,
            destination_host: "https://example.test/path".to_string(),
            destination_port: 443,
            client_identifier: None,
        };

        assert!(kind.validate().is_err());
    }
}
