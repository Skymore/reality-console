//! Canonical signing and verification for controller-owned node self-status.

use crate::crypto::{Ed25519PublicKey, Ed25519Signature};
use crate::node::NodeHeartbeatStatus;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
use thiserror::Error;

const NODE_STATUS_V1_DOMAIN: &[u8] = b"control/node-heartbeat-status/v1";

/// Returns the canonical transcript covered by a node self-status signature.
///
/// Endpoints must already be sorted by endpoint identity. Their order is part
/// of the signature so the same evidence has one canonical representation.
///
/// # Errors
///
/// Returns an error for an unsupported or inconsistent document, or if a
/// transcript field cannot fit its explicit length prefix.
pub fn node_heartbeat_status_transcript(
    document: &NodeHeartbeatStatus,
) -> Result<Vec<u8>, NodeStatusCryptoError> {
    document
        .validate_for(
            document.node_id,
            document.heartbeat_generation,
            document.controller_instance_id,
        )
        .map_err(|_| NodeStatusCryptoError::InvalidDocument)?;
    let mut transcript = Transcript::new(NODE_STATUS_V1_DOMAIN)?;
    transcript.bytes("schema-version", &document.schema_version.to_be_bytes())?;
    transcript.text("node-id", &document.node_id.to_string())?;
    transcript.bytes(
        "heartbeat-generation",
        &document.heartbeat_generation.get().to_be_bytes(),
    )?;
    transcript.text("observed-at", &document.observed_at.to_string())?;
    transcript.text("lifecycle", document.lifecycle.as_str())?;
    transcript.text("signing-key-id", &document.signing_key_id.to_string())?;
    transcript.text(
        "controller-instance-id",
        &document.controller_instance_id.to_string(),
    )?;
    transcript.count("endpoint-count", document.endpoints.len())?;
    for endpoint in &document.endpoints {
        transcript.text("endpoint-id", &endpoint.endpoint_id.to_string())?;
        transcript.text("readiness", endpoint.readiness.as_str())?;
        let checked_at = endpoint.last_checked_at.as_ref().map(ToString::to_string);
        transcript.optional_text("last-checked-at", checked_at.as_deref())?;
        transcript.optional_text("error-code", endpoint.error_code.as_deref())?;
    }
    Ok(transcript.finish())
}

/// Verifies the signature over a controller-owned node self-status.
///
/// # Errors
///
/// Returns an error for malformed key material, an invalid document, or a
/// signature that does not match the exact canonical transcript.
pub fn verify_node_heartbeat_status_signature(
    document: &NodeHeartbeatStatus,
    signature: &Ed25519Signature,
    public_key: &Ed25519PublicKey,
) -> Result<(), NodeStatusCryptoError> {
    let public_bytes = decode_exact::<32>(public_key.as_str())?;
    let signature_bytes = decode_exact::<64>(signature.as_str())?;
    let verifying_key = VerifyingKey::from_bytes(&public_bytes)
        .map_err(|_| NodeStatusCryptoError::InvalidSignature)?;
    let signature = Signature::from_bytes(&signature_bytes);
    let transcript = node_heartbeat_status_transcript(document)?;
    verifying_key
        .verify(&transcript, &signature)
        .map_err(|_| NodeStatusCryptoError::InvalidSignature)
}

fn decode_exact<const N: usize>(value: &str) -> Result<[u8; N], NodeStatusCryptoError> {
    URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| NodeStatusCryptoError::InvalidSignature)?
        .try_into()
        .map_err(|_| NodeStatusCryptoError::InvalidSignature)
}

struct Transcript {
    bytes: Vec<u8>,
}

impl Transcript {
    fn new(domain: &[u8]) -> Result<Self, NodeStatusCryptoError> {
        let mut transcript = Self { bytes: Vec::new() };
        transcript.bytes("domain", domain)?;
        Ok(transcript)
    }

    fn count(&mut self, label: &str, value: usize) -> Result<(), NodeStatusCryptoError> {
        let value = u32::try_from(value).map_err(|_| NodeStatusCryptoError::FieldTooLarge)?;
        self.bytes(label, &value.to_be_bytes())
    }

    fn optional_text(
        &mut self,
        label: &str,
        value: Option<&str>,
    ) -> Result<(), NodeStatusCryptoError> {
        let presence_label = format!("{label}-present");
        self.bytes(&presence_label, &[u8::from(value.is_some())])?;
        if let Some(value) = value {
            self.text(label, value)?;
        }
        Ok(())
    }

    fn text(&mut self, label: &str, value: &str) -> Result<(), NodeStatusCryptoError> {
        self.bytes(label, value.as_bytes())
    }

    fn bytes(&mut self, label: &str, value: &[u8]) -> Result<(), NodeStatusCryptoError> {
        let label_length =
            u16::try_from(label.len()).map_err(|_| NodeStatusCryptoError::FieldTooLarge)?;
        let value_length =
            u32::try_from(value.len()).map_err(|_| NodeStatusCryptoError::FieldTooLarge)?;
        self.bytes.extend_from_slice(&label_length.to_be_bytes());
        self.bytes.extend_from_slice(label.as_bytes());
        self.bytes.extend_from_slice(&value_length.to_be_bytes());
        self.bytes.extend_from_slice(value);
        Ok(())
    }

    fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

/// Canonical node self-status signature failure.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum NodeStatusCryptoError {
    /// Public key, signature bytes, or signature verification is invalid.
    #[error("the node heartbeat status signature is invalid")]
    InvalidSignature,
    /// A transcript field exceeded its explicit encoding bound.
    #[error("a node heartbeat status transcript field is too large")]
    FieldTooLarge,
    /// The status document failed its closed consistency rules.
    #[error("the node heartbeat status document is invalid")]
    InvalidDocument,
}

#[cfg(test)]
mod tests {
    use super::{node_heartbeat_status_transcript, verify_node_heartbeat_status_signature};
    use crate::crypto::{Ed25519PublicKey, Ed25519Signature};
    use crate::id::{
        ControllerInstanceId, EndpointId, NodeId, SequenceNumber, SigningKeyId, Timestamp,
    };
    use crate::node::{
        EndpointReadiness, NodeEndpointStatus, NodeHeartbeatStatus, NodeLifecycleState,
    };
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    use ed25519_dalek::{Signer as _, SigningKey};
    use time::OffsetDateTime;

    fn document() -> NodeHeartbeatStatus {
        NodeHeartbeatStatus {
            schema_version: 1,
            node_id: NodeId::new(),
            heartbeat_generation: SequenceNumber::new(7).unwrap(),
            observed_at: Timestamp::from_datetime(OffsetDateTime::UNIX_EPOCH),
            lifecycle: NodeLifecycleState::Active,
            endpoints: vec![NodeEndpointStatus {
                endpoint_id: EndpointId::new(),
                readiness: EndpointReadiness::TcpReachable,
                last_checked_at: Some(Timestamp::from_datetime(OffsetDateTime::UNIX_EPOCH)),
                error_code: None,
            }],
            signing_key_id: SigningKeyId::new(),
            controller_instance_id: ControllerInstanceId::new(),
        }
    }

    #[test]
    fn exact_status_transcript_verifies_and_mutation_fails() {
        let signing_key = SigningKey::from_bytes(&[9_u8; 32]);
        let public_key: Ed25519PublicKey = URL_SAFE_NO_PAD
            .encode(signing_key.verifying_key().to_bytes())
            .parse()
            .unwrap();
        let mut document = document();
        let transcript = node_heartbeat_status_transcript(&document).unwrap();
        let signature: Ed25519Signature = URL_SAFE_NO_PAD
            .encode(signing_key.sign(&transcript).to_bytes())
            .parse()
            .unwrap();
        verify_node_heartbeat_status_signature(&document, &signature, &public_key).unwrap();

        document.lifecycle = NodeLifecycleState::Pending;
        assert!(
            verify_node_heartbeat_status_signature(&document, &signature, &public_key).is_err()
        );
    }

    #[test]
    fn transcript_rejects_inconsistent_endpoint_evidence() {
        let mut document = document();
        document.endpoints[0].error_code = Some("direct_tcp_unreachable".to_string());
        assert!(node_heartbeat_status_transcript(&document).is_err());
    }
}
