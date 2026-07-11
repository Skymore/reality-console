use crate::crypto::Sha256Digest;
use crate::id::{NodeInvitationId, Timestamp};
use crate::node::{
    EnrollNodeRequest, EnrollNodeResponse, NodeAuthenticationMode, NodeCapability, PairingPurpose,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use thiserror::Error;

const REQUEST_DOMAIN: &[u8] = b"control/node-enrollment/request/v1";
const RESPONSE_DOMAIN: &[u8] = b"control/node-enrollment/response/v1";

/// Invitation metadata pinned into a node's enrollment proof.
pub struct EnrollmentInvitation<'a> {
    pub invitation_id: NodeInvitationId,
    pub purpose: PairingPurpose,
    pub expires_at: Timestamp,
    pub controller_origin: &'a str,
    pub controller_fingerprint: &'a Sha256Digest,
}

/// Returns the canonical request transcript signed by the node identity key.
///
/// The encoding is a domain byte string followed by labeled fields. Each label
/// is encoded as a big-endian `u16` length plus UTF-8 bytes; each value is a
/// big-endian `u32` length plus raw bytes. Capabilities are sorted by wire name.
///
/// # Errors
///
/// Returns [`EnrollmentCryptoError::FieldTooLarge`] if a field cannot be
/// represented by the version 1 length-prefix format.
pub fn enrollment_request_transcript(
    invitation: &EnrollmentInvitation<'_>,
    request: &EnrollNodeRequest,
) -> Result<Vec<u8>, EnrollmentCryptoError> {
    let mut transcript = Transcript::new(REQUEST_DOMAIN)?;
    transcript.text("purpose", purpose_name(invitation.purpose))?;
    transcript.text("controller-origin", invitation.controller_origin)?;
    transcript.text(
        "controller-fingerprint",
        invitation.controller_fingerprint.as_str(),
    )?;
    transcript.text("invitation-id", &invitation.invitation_id.to_string())?;
    transcript.text("invitation-expires-at", &invitation.expires_at.to_string())?;
    transcript.text("identity-public-key", request.identity_public_key.as_str())?;
    transcript.text(
        "encryption-public-key",
        request.encryption_public_key.as_str(),
    )?;
    transcript.text("nonce", request.nonce.as_str())?;
    transcript.text("agent-version", &request.agent_version)?;
    transcript.text("platform", &request.platform)?;
    transcript.text("display-name", &request.display_name)?;

    let mut capabilities: Vec<_> = request
        .capabilities
        .iter()
        .copied()
        .map(capability_name)
        .collect();
    capabilities.sort_unstable();
    let capability_count =
        u32::try_from(capabilities.len()).map_err(|_| EnrollmentCryptoError::FieldTooLarge)?;
    transcript.bytes("capability-count", &capability_count.to_be_bytes())?;
    for capability in capabilities {
        transcript.text("capability", capability)?;
    }

    transcript.text(
        "consent-policy-version",
        &request.provider_consent.policy_version,
    )?;
    transcript.bytes(
        "consent-host-owner",
        &[u8::from(request.provider_consent.host_owner_consented)],
    )?;
    transcript.bytes(
        "consent-exit-ip-disclosure",
        &[u8::from(
            request.provider_consent.exit_ip_disclosure_accepted,
        )],
    )?;
    transcript.bytes(
        "consent-router-mapping",
        &[u8::from(request.provider_consent.router_mapping_accepted)],
    )?;
    transcript.text(
        "consent-accepted-at",
        &request.provider_consent.accepted_at.to_string(),
    )?;
    Ok(transcript.finish())
}

/// Returns the canonical controller response transcript.
///
/// # Errors
///
/// Returns [`EnrollmentCryptoError::FieldTooLarge`] if a field cannot be
/// represented by the version 1 length-prefix format.
pub fn enrollment_response_transcript(
    request_transcript: &[u8],
    response: &EnrollNodeResponse,
) -> Result<Vec<u8>, EnrollmentCryptoError> {
    let mut transcript = Transcript::new(RESPONSE_DOMAIN)?;
    transcript.bytes(
        "request-transcript-sha256",
        &Sha256::digest(request_transcript),
    )?;
    transcript.text("network-id", &response.network_id.to_string())?;
    transcript.text("node-id", &response.node_id.to_string())?;
    transcript.text(
        "controller-instance-id",
        &response.controller_instance_id.to_string(),
    )?;
    transcript.text("credential-key-id", &response.credential.key_id.to_string())?;
    transcript.text(
        "credential-mode",
        authentication_mode_name(response.credential.mode),
    )?;
    transcript.text(
        "credential-expires-at",
        &response.credential.expires_at.to_string(),
    )?;
    transcript.text(
        "controller-signing-public-key",
        response.desired_state_signing_public_key.as_str(),
    )?;
    transcript.text("controller-nonce", response.controller_nonce.as_str())?;
    Ok(transcript.finish())
}

/// Verifies a node proof against the canonical request transcript.
///
/// # Errors
///
/// Returns [`EnrollmentCryptoError`] for malformed or invalid key material.
pub fn verify_enrollment_proof(
    request: &EnrollNodeRequest,
    transcript: &[u8],
) -> Result<(), EnrollmentCryptoError> {
    let public_bytes = decode_exact::<32>(request.identity_public_key.as_str())?;
    let signature_bytes = decode_exact::<64>(request.proof.as_str())?;
    let public_key =
        VerifyingKey::from_bytes(&public_bytes).map_err(|_| EnrollmentCryptoError::InvalidProof)?;
    let signature = Signature::from_bytes(&signature_bytes);
    public_key
        .verify(transcript, &signature)
        .map_err(|_| EnrollmentCryptoError::InvalidProof)
}

fn decode_exact<const N: usize>(value: &str) -> Result<[u8; N], EnrollmentCryptoError> {
    URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| EnrollmentCryptoError::InvalidProof)?
        .try_into()
        .map_err(|_| EnrollmentCryptoError::InvalidProof)
}

fn purpose_name(value: PairingPurpose) -> &'static str {
    match value {
        PairingPurpose::NodeEnrollment => "node-enrollment",
        PairingPurpose::DeviceActivation => "device-activation",
        PairingPurpose::AdminDeviceEnrollment => "admin-device-enrollment",
    }
}

fn capability_name(value: NodeCapability) -> &'static str {
    match value {
        NodeCapability::Xray => "xray",
        NodeCapability::DirectTcp => "direct-tcp",
        NodeCapability::Upnp => "upnp",
        NodeCapability::NatPmp => "nat-pmp",
        NodeCapability::Pcp => "pcp",
        NodeCapability::RelayTcp => "relay-tcp",
    }
}

fn authentication_mode_name(value: NodeAuthenticationMode) -> &'static str {
    match value {
        NodeAuthenticationMode::MutualTls => "mutualTls",
        NodeAuthenticationMode::SignedRequest => "signedRequest",
    }
}

struct Transcript {
    bytes: Vec<u8>,
}

impl Transcript {
    fn new(domain: &[u8]) -> Result<Self, EnrollmentCryptoError> {
        let mut value = Self { bytes: Vec::new() };
        value.bytes("domain", domain)?;
        Ok(value)
    }

    fn text(&mut self, label: &str, value: &str) -> Result<(), EnrollmentCryptoError> {
        self.bytes(label, value.as_bytes())
    }

    fn bytes(&mut self, label: &str, value: &[u8]) -> Result<(), EnrollmentCryptoError> {
        let label_length =
            u16::try_from(label.len()).map_err(|_| EnrollmentCryptoError::FieldTooLarge)?;
        let value_length =
            u32::try_from(value.len()).map_err(|_| EnrollmentCryptoError::FieldTooLarge)?;
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

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum EnrollmentCryptoError {
    #[error("the node enrollment proof is invalid")]
    InvalidProof,
    #[error("an enrollment transcript field is too large")]
    FieldTooLarge,
}
