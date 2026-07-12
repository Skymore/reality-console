//! Controller-issued relay grants and node-encrypted assignment material.

use crate::crypto::{
    ed25519_signing_key_id, Ed25519PublicKey, Ed25519Signature, Nonce, Sha256Digest,
    X25519PublicKey,
};
use crate::id::{
    EndpointId, NetworkId, NodeId, RelayGeneration, RelayGrantId, RelayId, RelayRouteId,
    SigningKeyId, Timestamp,
};
use crate::secret::Secret;
use crate::validation::{ProtocolValidationError, ValidationCode};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
use hpke::aead::ChaCha20Poly1305;
use hpke::kdf::HkdfSha256;
use hpke::kem::X25519HkdfSha256;
use hpke::{Deserializable, OpModeR, OpModeS, Serializable};
use rand_core::{OsRng, TryRngCore as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::fmt;
use std::net::IpAddr;
use time::Duration;

/// Current relay assignment and managed-route schema.
pub const RELAY_SCHEMA_VERSION: u16 = 1;
/// Maximum controller-issued relay grant lifetime.
pub const MAX_RELAY_GRANT_LIFETIME_SECONDS: i64 = 86_400;

const RELAY_HPKE_INFO: &[u8] = b"control/relay/assignment-hpke/v1";
const RELAY_ASSIGNMENT_DOMAIN: &[u8] = b"control/relay/signed-assignment/v1";
const RELAY_ROUTE_DOMAIN: &[u8] = b"control/relay/signed-route/v1";
const MAX_HOST_LENGTH: usize = 253;
const MAX_PEM_LENGTH: usize = 65_536;
const MAX_CIPHERTEXT_BYTES: usize = 196_608;
const MIN_BYTES_PER_SECOND: u64 = 1_024;
const MAX_BYTES_PER_SECOND: u64 = 10_000_000_000;
const MIN_BYTE_LIMIT: u64 = 1_048_576;
const MAX_BYTE_LIMIT: u64 = 10 * 1_024 * 1_024 * 1_024 * 1_024 * 1_024;

/// Closed relay assignment lifecycle visible without secret material.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RelayGrantState {
    /// Durable grant exists but its route document is not confirmed on disk.
    Pending,
    /// Exact signed route document is available to the relay.
    Published,
    /// Route removal is durably requested.
    Revoking,
    /// Route is absent and the assignment is no longer usable.
    Revoked,
    /// Grant lifetime ended and it cannot be renewed by the node.
    Expired,
}

/// Controller and relay ceilings for one route generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RelayLimits {
    /// Maximum simultaneously open logical member streams.
    pub max_concurrent_streams: u16,
    /// Aggregate byte rate across both directions.
    pub max_bytes_per_second: u64,
    /// Maximum total bytes copied by one member connection.
    pub max_bytes_per_connection: u64,
    /// Maximum calendar-month route bytes before new streams are refused.
    pub monthly_byte_limit: u64,
}

impl RelayLimits {
    /// Validates finite production bounds.
    ///
    /// # Errors
    ///
    /// Returns a stable validation error for zero or unsafe limits.
    pub fn validate(self) -> Result<(), ProtocolValidationError> {
        if !(1..=4_096).contains(&self.max_concurrent_streams) {
            return Err(validation(
                ValidationCode::OutOfRange,
                "limits.maxConcurrentStreams",
                "relay concurrent streams must be between 1 and 4096",
            ));
        }
        if !(MIN_BYTES_PER_SECOND..=MAX_BYTES_PER_SECOND).contains(&self.max_bytes_per_second) {
            return Err(validation(
                ValidationCode::OutOfRange,
                "limits.maxBytesPerSecond",
                "relay byte rate is outside the supported finite range",
            ));
        }
        for (field, value) in [
            (
                "limits.maxBytesPerConnection",
                self.max_bytes_per_connection,
            ),
            ("limits.monthlyByteLimit", self.monthly_byte_limit),
        ] {
            if !(MIN_BYTE_LIMIT..=MAX_BYTE_LIMIT).contains(&value) {
                return Err(validation(
                    ValidationCode::OutOfRange,
                    field,
                    "relay byte limit is outside the supported finite range",
                ));
            }
        }
        Ok(())
    }
}

/// Provider-selected ceilings carried by a signed node ensure request.
/// Control intersects these values with its static operator ceilings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EnsureRelayAssignmentRequest {
    pub provider_limits: RelayLimits,
}

impl EnsureRelayAssignmentRequest {
    /// Validates all provider-selected finite ceilings before issuance.
    ///
    /// # Errors
    ///
    /// Returns a protocol validation error for an unsafe provider ceiling.
    pub fn validate(&self) -> Result<(), ProtocolValidationError> {
        self.provider_limits.validate()
    }
}

/// Node acknowledgement sent only after a relay generation is durably
/// installed and its connector has registered with the Relay Service.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AcknowledgeRelayAssignmentRequest {
    pub grant_id: RelayGrantId,
    pub generation: RelayGeneration,
}

impl AcknowledgeRelayAssignmentRequest {
    /// Validates the closed generation identity.
    ///
    /// # Errors
    ///
    /// Returns an error when a reserved generation value is supplied.
    pub fn validate(&self) -> Result<(), ProtocolValidationError> {
        if self.generation.get() < 1 {
            return Err(validation(
                ValidationCode::OutOfRange,
                "generation",
                "relay generation must be positive",
            ));
        }
        Ok(())
    }
}

/// Non-secret assignment identity used as HPKE AAD and signature input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RelayAssignmentHeader {
    /// Protocol schema version.
    pub schema_version: u16,
    /// Stable private-network identity.
    pub network_id: NetworkId,
    /// Exact enrolled node receiving the assignment.
    pub node_id: NodeId,
    /// Configured relay service.
    pub relay_id: RelayId,
    /// Logical route retained across rotations.
    pub route_id: RelayRouteId,
    /// Exact grant record.
    pub grant_id: RelayGrantId,
    /// Monotonic credential and endpoint generation.
    pub generation: RelayGeneration,
    /// Endpoint identity reported by Node Host after registration.
    pub endpoint_id: EndpointId,
    /// Public member-facing relay hostname or IP address.
    pub public_host: String,
    /// Public member-facing relay TCP port.
    pub public_port: u16,
    /// Node-tunnel relay hostname or IP address.
    pub tunnel_host: String,
    /// Node-tunnel relay TCP port.
    pub tunnel_port: u16,
    /// Exact TLS server name checked by Node Host.
    pub tls_server_name: String,
    /// Grant creation time.
    pub issued_at: Timestamp,
    /// Earliest accepted installation time.
    pub not_before: Timestamp,
    /// Finite fail-closed expiry.
    pub expires_at: Timestamp,
    /// Controller and relay ceilings.
    pub limits: RelayLimits,
}

impl RelayAssignmentHeader {
    /// Returns the exact generation-scoped ID used by the node/relay registration protocol.
    ///
    /// The logical [`Self::route_id`] remains stable across rotation. Registration uses the grant
    /// ID so predecessor and successor generations can coexist during bounded cutover.
    #[must_use]
    pub fn registration_route_id(&self) -> String {
        self.grant_id.to_string()
    }

    /// Validates identity, endpoint, time, and limit invariants.
    ///
    /// # Errors
    ///
    /// Returns a stable protocol validation error for any invalid field.
    pub fn validate(&self) -> Result<(), ProtocolValidationError> {
        if self.schema_version != RELAY_SCHEMA_VERSION {
            return Err(validation(
                ValidationCode::UnsupportedSchema,
                "schemaVersion",
                "unsupported relay assignment schema",
            ));
        }
        validate_host(&self.public_host, "publicHost")?;
        validate_host(&self.tunnel_host, "tunnelHost")?;
        validate_host(&self.tls_server_name, "tlsServerName")?;
        if self.public_port == 0 || self.tunnel_port == 0 {
            return Err(validation(
                ValidationCode::OutOfRange,
                "port",
                "relay ports must be non-zero",
            ));
        }
        if self.not_before < self.issued_at || self.expires_at <= self.not_before {
            return Err(validation(
                ValidationCode::InconsistentState,
                "expiresAt",
                "relay grant time ordering is invalid",
            ));
        }
        let lifetime = self.expires_at.as_datetime() - self.issued_at.as_datetime();
        if lifetime > Duration::seconds(MAX_RELAY_GRANT_LIFETIME_SECONDS) {
            return Err(validation(
                ValidationCode::OutOfRange,
                "expiresAt",
                "relay grant lifetime exceeds 24 hours",
            ));
        }
        self.limits.validate()
    }
}

/// HPKE ciphertext encrypted to one enrolled Node Host installation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EncryptedRelayMaterial {
    /// Closed encryption algorithm identifier.
    pub algorithm: RelayEncryptionAlgorithm,
    /// Ephemeral X25519 sender public key.
    pub ephemeral_public_key: X25519PublicKey,
    /// Random envelope nonce also bound into AAD.
    pub nonce: Nonce,
    /// Base64url HPKE ciphertext.
    pub ciphertext: Secret<String>,
}

/// Closed relay assignment encryption algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RelayEncryptionAlgorithm {
    /// HPKE base mode with the exact named primitives.
    HpkeBaseX25519HkdfSha256ChaCha20Poly1305,
}

/// Secret material installed into an owner-only Node Host generation.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RelayAssignmentMaterial {
    /// Random route registration bearer.
    pub route_token: Secret<String>,
    /// PEM encoded relay client certificate chain.
    pub client_certificate_pem: Secret<String>,
    /// PEM encoded relay client private key.
    pub client_private_key_pem: Secret<String>,
    /// Public PEM relay CA used for server verification.
    pub relay_ca_certificate_pem: String,
}

impl fmt::Debug for RelayAssignmentMaterial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RelayAssignmentMaterial")
            .field("route_token", &"[redacted]")
            .field("client_certificate_pem", &"[redacted]")
            .field("client_private_key_pem", &"[redacted]")
            .field("relay_ca_certificate_pem", &"[public certificate]")
            .finish()
    }
}

impl RelayAssignmentMaterial {
    /// Validates bounded token and PEM shapes before installation.
    ///
    /// # Errors
    ///
    /// Returns a stable validation error for malformed or oversized material.
    pub fn validate(&self) -> Result<(), ProtocolValidationError> {
        let token = URL_SAFE_NO_PAD
            .decode(self.route_token.expose_secret())
            .map_err(|_| {
                validation(
                    ValidationCode::InvalidFormat,
                    "routeToken",
                    "route token must be unpadded base64url",
                )
            })?;
        if token.len() != 32 {
            return Err(validation(
                ValidationCode::InvalidFormat,
                "routeToken",
                "route token must contain exactly 32 bytes",
            ));
        }
        validate_pem(
            self.client_certificate_pem.expose_secret(),
            "clientCertificatePem",
            "CERTIFICATE",
        )?;
        validate_pem(
            self.client_private_key_pem.expose_secret(),
            "clientPrivateKeyPem",
            "PRIVATE KEY",
        )?;
        validate_pem(
            &self.relay_ca_certificate_pem,
            "relayCaCertificatePem",
            "CERTIFICATE",
        )
    }
}

/// Complete controller-signed encrypted relay assignment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedRelayAssignment {
    /// Non-secret assignment identity.
    pub header: RelayAssignmentHeader,
    /// Node-encrypted credential material.
    pub encrypted_material: EncryptedRelayMaterial,
    /// Controller signing key identity.
    pub signing_key_id: SigningKeyId,
    /// Signature over the complete assignment transcript.
    pub signature: Ed25519Signature,
}

impl SignedRelayAssignment {
    /// Validates all non-cryptographic wire invariants.
    ///
    /// # Errors
    ///
    /// Returns a stable protocol error for invalid metadata or ciphertext size.
    pub fn validate(&self) -> Result<(), ProtocolValidationError> {
        self.header.validate()?;
        let ciphertext = URL_SAFE_NO_PAD
            .decode(self.encrypted_material.ciphertext.expose_secret())
            .map_err(|_| {
                validation(
                    ValidationCode::InvalidFormat,
                    "encryptedMaterial.ciphertext",
                    "relay ciphertext must be unpadded base64url",
                )
            })?;
        if ciphertext.is_empty() || ciphertext.len() > MAX_CIPHERTEXT_BYTES {
            return Err(validation(
                ValidationCode::OutOfRange,
                "encryptedMaterial.ciphertext",
                "relay ciphertext is empty or exceeds its size limit",
            ));
        }
        Ok(())
    }
}

/// Non-secret signed route document consumed by the Relay service.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedRelayRoute {
    /// Assignment identity and endpoint limits.
    pub header: RelayAssignmentHeader,
    /// SHA-256 of the raw route token.
    pub route_token_sha256: Sha256Digest,
    /// SHA-256 of the exact client leaf certificate DER.
    pub client_certificate_sha256: Sha256Digest,
    /// Controller signing key identity.
    pub signing_key_id: SigningKeyId,
    /// Signature over the route transcript.
    pub signature: Ed25519Signature,
}

impl SignedRelayRoute {
    /// Validates non-cryptographic route invariants.
    ///
    /// # Errors
    ///
    /// Returns the assignment header validation error.
    pub fn validate(&self) -> Result<(), ProtocolValidationError> {
        self.header.validate()
    }
}

/// Encrypts one validated relay material object to a Node Host installation.
///
/// # Errors
///
/// Returns an error for invalid metadata/material, recipient encoding, serialization, or HPKE.
pub fn encrypt_relay_material(
    recipient: &X25519PublicKey,
    header: &RelayAssignmentHeader,
    material: &RelayAssignmentMaterial,
) -> Result<EncryptedRelayMaterial, RelayCryptoError> {
    header.validate()?;
    material.validate()?;
    let plaintext = serde_json::to_vec(material)?;
    let mut nonce_bytes = [0_u8; 16];
    OsRng
        .try_fill_bytes(&mut nonce_bytes)
        .map_err(|_| RelayCryptoError::Encryption)?;
    let nonce: Nonce = URL_SAFE_NO_PAD
        .encode(nonce_bytes)
        .parse()
        .map_err(|_| RelayCryptoError::InvalidEncoding)?;
    let aad = assignment_aad(header, nonce.as_str())?;
    let recipient_bytes = decode_exact(recipient.as_str(), 32)?;
    let recipient_key = <X25519HkdfSha256 as hpke::Kem>::PublicKey::from_bytes(&recipient_bytes)
        .map_err(|_| RelayCryptoError::InvalidEncoding)?;
    let mut rng = OsRng.unwrap_err();
    let (encapped, mut context) = hpke::setup_sender::<
        ChaCha20Poly1305,
        HkdfSha256,
        X25519HkdfSha256,
        _,
    >(&OpModeS::Base, &recipient_key, RELAY_HPKE_INFO, &mut rng)
    .map_err(|_| RelayCryptoError::Encryption)?;
    let ciphertext = context
        .seal(&plaintext, &aad)
        .map_err(|_| RelayCryptoError::Encryption)?;
    if ciphertext.len() > MAX_CIPHERTEXT_BYTES {
        return Err(RelayCryptoError::FieldTooLarge);
    }
    Ok(EncryptedRelayMaterial {
        algorithm: RelayEncryptionAlgorithm::HpkeBaseX25519HkdfSha256ChaCha20Poly1305,
        ephemeral_public_key: URL_SAFE_NO_PAD
            .encode(encapped.to_bytes())
            .parse()
            .map_err(|_| RelayCryptoError::InvalidEncoding)?,
        nonce,
        ciphertext: Secret::new(URL_SAFE_NO_PAD.encode(ciphertext)),
    })
}

/// Decrypts and validates one assignment with the exact recipient installation key.
///
/// # Errors
///
/// Returns an error for invalid metadata, encoding, wrong recipient/AAD, or invalid material.
pub fn decrypt_relay_material(
    recipient_private_key: &[u8; 32],
    header: &RelayAssignmentHeader,
    encrypted: &EncryptedRelayMaterial,
) -> Result<RelayAssignmentMaterial, RelayCryptoError> {
    header.validate()?;
    if encrypted.algorithm != RelayEncryptionAlgorithm::HpkeBaseX25519HkdfSha256ChaCha20Poly1305 {
        return Err(RelayCryptoError::UnsupportedAlgorithm);
    }
    let private_key =
        <X25519HkdfSha256 as hpke::Kem>::PrivateKey::from_bytes(recipient_private_key)
            .map_err(|_| RelayCryptoError::InvalidEncoding)?;
    let encapped = <X25519HkdfSha256 as hpke::Kem>::EncappedKey::from_bytes(&decode_exact(
        encrypted.ephemeral_public_key.as_str(),
        32,
    )?)
    .map_err(|_| RelayCryptoError::InvalidEncoding)?;
    let mut context = hpke::setup_receiver::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>(
        &OpModeR::Base,
        &private_key,
        &encapped,
        RELAY_HPKE_INFO,
    )
    .map_err(|_| RelayCryptoError::Encryption)?;
    let ciphertext = URL_SAFE_NO_PAD
        .decode(encrypted.ciphertext.expose_secret())
        .map_err(|_| RelayCryptoError::InvalidEncoding)?;
    if ciphertext.is_empty() || ciphertext.len() > MAX_CIPHERTEXT_BYTES {
        return Err(RelayCryptoError::FieldTooLarge);
    }
    let aad = assignment_aad(header, encrypted.nonce.as_str())?;
    let plaintext = context
        .open(&ciphertext, &aad)
        .map_err(|_| RelayCryptoError::Encryption)?;
    let material: RelayAssignmentMaterial = serde_json::from_slice(&plaintext)?;
    material.validate()?;
    Ok(material)
}

/// Builds the deterministic controller-signature transcript for an assignment.
///
/// # Errors
///
/// Returns an error when a variable field exceeds transcript limits.
pub fn relay_assignment_transcript(
    assignment: &SignedRelayAssignment,
) -> Result<Vec<u8>, RelayCryptoError> {
    assignment.validate()?;
    let mut transcript = Transcript::new(RELAY_ASSIGNMENT_DOMAIN)?;
    encode_header(&mut transcript, &assignment.header)?;
    transcript.text("algorithm", "hpkeBaseX25519HkdfSha256ChaCha20Poly1305")?;
    transcript.text(
        "ephemeralPublicKey",
        assignment.encrypted_material.ephemeral_public_key.as_str(),
    )?;
    transcript.text("nonce", assignment.encrypted_material.nonce.as_str())?;
    transcript.text(
        "ciphertext",
        assignment.encrypted_material.ciphertext.expose_secret(),
    )?;
    transcript.text("signingKeyId", &assignment.signing_key_id.to_string())?;
    Ok(transcript.finish())
}

/// Verifies an assignment signature against the pinned controller key.
///
/// # Errors
///
/// Returns an error for invalid encoding, transcript, or signature.
pub fn verify_relay_assignment_signature(
    assignment: &SignedRelayAssignment,
    controller_public_key: &Ed25519PublicKey,
) -> Result<(), RelayCryptoError> {
    if ed25519_signing_key_id(controller_public_key)
        .map_err(|_| RelayCryptoError::InvalidEncoding)?
        != assignment.signing_key_id
    {
        return Err(RelayCryptoError::SigningKeyMismatch);
    }
    verify_signature(
        controller_public_key,
        &assignment.signature,
        &relay_assignment_transcript(assignment)?,
    )
}

/// Builds the deterministic controller-signature transcript for a route document.
///
/// # Errors
///
/// Returns an error when a variable field exceeds transcript limits.
pub fn relay_route_transcript(route: &SignedRelayRoute) -> Result<Vec<u8>, RelayCryptoError> {
    route.validate()?;
    let mut transcript = Transcript::new(RELAY_ROUTE_DOMAIN)?;
    encode_header(&mut transcript, &route.header)?;
    transcript.text("routeTokenSha256", route.route_token_sha256.as_str())?;
    transcript.text(
        "clientCertificateSha256",
        route.client_certificate_sha256.as_str(),
    )?;
    transcript.text("signingKeyId", &route.signing_key_id.to_string())?;
    Ok(transcript.finish())
}

/// Verifies a managed route signature against the pinned controller key.
///
/// # Errors
///
/// Returns an error for invalid encoding, transcript, or signature.
pub fn verify_relay_route_signature(
    route: &SignedRelayRoute,
    controller_public_key: &Ed25519PublicKey,
) -> Result<(), RelayCryptoError> {
    if ed25519_signing_key_id(controller_public_key)
        .map_err(|_| RelayCryptoError::InvalidEncoding)?
        != route.signing_key_id
    {
        return Err(RelayCryptoError::SigningKeyMismatch);
    }
    verify_signature(
        controller_public_key,
        &route.signature,
        &relay_route_transcript(route)?,
    )
}

fn assignment_aad(
    header: &RelayAssignmentHeader,
    nonce: &str,
) -> Result<Vec<u8>, RelayCryptoError> {
    let mut transcript = Transcript::new(b"control/relay/assignment-aad/v1")?;
    encode_header(&mut transcript, header)?;
    transcript.text("nonce", nonce)?;
    Ok(transcript.finish())
}

fn encode_header(
    transcript: &mut Transcript,
    header: &RelayAssignmentHeader,
) -> Result<(), RelayCryptoError> {
    transcript.number("schemaVersion", u64::from(header.schema_version))?;
    transcript.text("networkId", &header.network_id.to_string())?;
    transcript.text("nodeId", &header.node_id.to_string())?;
    transcript.text("relayId", &header.relay_id.to_string())?;
    transcript.text("routeId", &header.route_id.to_string())?;
    transcript.text("grantId", &header.grant_id.to_string())?;
    transcript.number(
        "generation",
        u64::try_from(header.generation.get()).map_err(|_| RelayCryptoError::InvalidEncoding)?,
    )?;
    transcript.text("endpointId", &header.endpoint_id.to_string())?;
    transcript.text("publicHost", &header.public_host)?;
    transcript.number("publicPort", u64::from(header.public_port))?;
    transcript.text("tunnelHost", &header.tunnel_host)?;
    transcript.number("tunnelPort", u64::from(header.tunnel_port))?;
    transcript.text("tlsServerName", &header.tls_server_name)?;
    transcript.text("issuedAt", &header.issued_at.to_string())?;
    transcript.text("notBefore", &header.not_before.to_string())?;
    transcript.text("expiresAt", &header.expires_at.to_string())?;
    transcript.number(
        "maxConcurrentStreams",
        u64::from(header.limits.max_concurrent_streams),
    )?;
    transcript.number("maxBytesPerSecond", header.limits.max_bytes_per_second)?;
    transcript.number(
        "maxBytesPerConnection",
        header.limits.max_bytes_per_connection,
    )?;
    transcript.number("monthlyByteLimit", header.limits.monthly_byte_limit)
}

fn verify_signature(
    public_key: &Ed25519PublicKey,
    signature: &Ed25519Signature,
    transcript: &[u8],
) -> Result<(), RelayCryptoError> {
    let key_bytes: [u8; 32] = decode_exact(public_key.as_str(), 32)?
        .try_into()
        .map_err(|_| RelayCryptoError::InvalidEncoding)?;
    let signature_bytes: [u8; 64] = decode_exact(signature.as_str(), 64)?
        .try_into()
        .map_err(|_| RelayCryptoError::InvalidEncoding)?;
    let key =
        VerifyingKey::from_bytes(&key_bytes).map_err(|_| RelayCryptoError::InvalidEncoding)?;
    key.verify(transcript, &Signature::from_bytes(&signature_bytes))
        .map_err(|_| RelayCryptoError::SignatureInvalid)
}

fn validate_host(value: &str, field: &'static str) -> Result<(), ProtocolValidationError> {
    let valid_ip = value.parse::<IpAddr>().is_ok();
    let valid_dns = !value.is_empty()
        && value.len() <= MAX_HOST_LENGTH
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        });
    if !valid_ip && !valid_dns {
        return Err(validation(
            ValidationCode::InvalidFormat,
            field,
            "relay host must be a canonical IP literal or bounded DNS name without a port",
        ));
    }
    Ok(())
}

fn validate_pem(
    value: &str,
    field: &'static str,
    label: &str,
) -> Result<(), ProtocolValidationError> {
    if value.is_empty() || value.len() > MAX_PEM_LENGTH || value.contains('\0') {
        return Err(validation(
            ValidationCode::OutOfRange,
            field,
            "PEM material is empty or exceeds its size limit",
        ));
    }
    if !value.starts_with(&format!("-----BEGIN {label}-----\n"))
        || !value.ends_with(&format!("-----END {label}-----\n"))
    {
        return Err(validation(
            ValidationCode::InvalidFormat,
            field,
            "PEM material has an invalid envelope",
        ));
    }
    Ok(())
}

fn decode_exact(value: &str, length: usize) -> Result<Vec<u8>, RelayCryptoError> {
    let decoded = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| RelayCryptoError::InvalidEncoding)?;
    if decoded.len() != length {
        return Err(RelayCryptoError::InvalidEncoding);
    }
    Ok(decoded)
}

fn validation(
    code: ValidationCode,
    field: &'static str,
    message: &'static str,
) -> ProtocolValidationError {
    ProtocolValidationError::new(code, field, message)
}

struct Transcript(Vec<u8>);

impl Transcript {
    fn new(domain: &[u8]) -> Result<Self, RelayCryptoError> {
        let mut value = Self(Vec::new());
        value.bytes("domain", domain)?;
        Ok(value)
    }

    fn text(&mut self, label: &str, value: &str) -> Result<(), RelayCryptoError> {
        self.bytes(label, value.as_bytes())
    }

    fn number(&mut self, label: &str, value: u64) -> Result<(), RelayCryptoError> {
        self.bytes(label, &value.to_be_bytes())
    }

    fn bytes(&mut self, label: &str, value: &[u8]) -> Result<(), RelayCryptoError> {
        let label_length =
            u16::try_from(label.len()).map_err(|_| RelayCryptoError::FieldTooLarge)?;
        let value_length =
            u32::try_from(value.len()).map_err(|_| RelayCryptoError::FieldTooLarge)?;
        self.0.extend_from_slice(&label_length.to_be_bytes());
        self.0.extend_from_slice(label.as_bytes());
        self.0.extend_from_slice(&value_length.to_be_bytes());
        self.0.extend_from_slice(value);
        Ok(())
    }

    fn finish(self) -> Vec<u8> {
        self.0
    }
}

/// Relay encryption/signature failure.
#[derive(Debug, thiserror::Error)]
pub enum RelayCryptoError {
    /// Protocol field validation failed.
    #[error(transparent)]
    Validation(#[from] ProtocolValidationError),
    /// Wire serialization failed.
    #[error("relay material serialization failed")]
    Serialization(#[from] serde_json::Error),
    /// A key, nonce, signature, or ciphertext has invalid encoding.
    #[error("relay cryptographic value has invalid encoding")]
    InvalidEncoding,
    /// HPKE could not encrypt or authenticate the material.
    #[error("relay material encryption failed")]
    Encryption,
    /// The encrypted object names an unsupported algorithm.
    #[error("relay material encryption algorithm is unsupported")]
    UnsupportedAlgorithm,
    /// A transcript or encrypted field exceeds its bound.
    #[error("relay cryptographic field exceeds its size limit")]
    FieldTooLarge,
    /// Controller signature verification failed.
    #[error("relay controller signature is invalid")]
    SignatureInvalid,
    /// The envelope names a controller key other than the pinned public key.
    #[error("relay controller signing key identity does not match")]
    SigningKeyMismatch,
}

/// Returns a canonical SHA-256 for route token bytes without retaining the bearer.
#[must_use]
pub fn relay_token_digest(token: &[u8]) -> Sha256Digest {
    Sha256Digest::from_bytes(Sha256::digest(token).into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer as _, SigningKey};
    use hpke::kem::X25519HkdfSha256;
    use hpke::Kem as _;
    use std::str::FromStr as _;
    use time::{Duration, OffsetDateTime};

    fn header() -> RelayAssignmentHeader {
        let issued = OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap();
        RelayAssignmentHeader {
            schema_version: RELAY_SCHEMA_VERSION,
            network_id: NetworkId::new(),
            node_id: NodeId::new(),
            relay_id: RelayId::new(),
            route_id: RelayRouteId::new(),
            grant_id: RelayGrantId::new(),
            generation: RelayGeneration::new(1).unwrap(),
            endpoint_id: EndpointId::new(),
            public_host: "relay.example.test".into(),
            public_port: 20_001,
            tunnel_host: "relay.example.test".into(),
            tunnel_port: 9443,
            tls_server_name: "relay.example.test".into(),
            issued_at: Timestamp::from_datetime(issued),
            not_before: Timestamp::from_datetime(issued),
            expires_at: Timestamp::from_datetime(issued + Duration::hours(12)),
            limits: RelayLimits {
                max_concurrent_streams: 16,
                max_bytes_per_second: 2_500_000,
                max_bytes_per_connection: 10 * 1_024 * 1_024,
                monthly_byte_limit: 100 * 1_024 * 1_024,
            },
        }
    }

    fn material() -> RelayAssignmentMaterial {
        RelayAssignmentMaterial {
            route_token: Secret::new(URL_SAFE_NO_PAD.encode([7_u8; 32])),
            client_certificate_pem: Secret::new(
                "-----BEGIN CERTIFICATE-----\nY2VydA==\n-----END CERTIFICATE-----\n".into(),
            ),
            client_private_key_pem: Secret::new(
                "-----BEGIN PRIVATE KEY-----\na2V5\n-----END PRIVATE KEY-----\n".into(),
            ),
            relay_ca_certificate_pem:
                "-----BEGIN CERTIFICATE-----\nY2E=\n-----END CERTIFICATE-----\n".into(),
        }
    }

    fn recipient() -> ([u8; 32], X25519PublicKey) {
        let mut rng = OsRng.unwrap_err();
        let (private, public) = X25519HkdfSha256::gen_keypair(&mut rng);
        (
            private.to_bytes().into(),
            URL_SAFE_NO_PAD.encode(public.to_bytes()).parse().unwrap(),
        )
    }

    #[test]
    fn assignment_material_round_trips_only_for_exact_header_and_recipient() {
        let (private, public) = recipient();
        let header = header();
        let encrypted = encrypt_relay_material(&public, &header, &material()).unwrap();

        let decrypted = decrypt_relay_material(&private, &header, &encrypted).unwrap();
        assert_eq!(decrypted, material());

        let mut different = header.clone();
        different.endpoint_id = EndpointId::new();
        assert!(decrypt_relay_material(&private, &different, &encrypted).is_err());
        let (wrong_private, _) = recipient();
        assert!(decrypt_relay_material(&wrong_private, &header, &encrypted).is_err());
    }

    #[test]
    fn registration_uses_generation_scoped_grant_id_not_logical_route_id() {
        let first = header();
        let mut successor = first.clone();
        successor.grant_id = RelayGrantId::new();
        successor.generation = RelayGeneration::new(2).unwrap();
        assert_eq!(first.route_id, successor.route_id);
        assert_ne!(
            first.registration_route_id(),
            successor.registration_route_id()
        );
        assert_eq!(first.registration_route_id(), first.grant_id.to_string());
    }

    #[test]
    fn signed_assignment_transcript_verifies_and_detects_tampering() {
        let signing = SigningKey::from_bytes(&[9_u8; 32]);
        let public: Ed25519PublicKey = URL_SAFE_NO_PAD
            .encode(signing.verifying_key().to_bytes())
            .parse()
            .unwrap();
        let (_, recipient) = recipient();
        let mut assignment = SignedRelayAssignment {
            header: header(),
            encrypted_material: encrypt_relay_material(&recipient, &header(), &material()).unwrap(),
            signing_key_id: ed25519_signing_key_id(&public).unwrap(),
            signature: URL_SAFE_NO_PAD.encode([0_u8; 64]).parse().unwrap(),
        };
        // Re-encrypt against the header retained by this exact assignment.
        assignment.encrypted_material =
            encrypt_relay_material(&recipient, &assignment.header, &material()).unwrap();
        let transcript = relay_assignment_transcript(&assignment).unwrap();
        assignment.signature = URL_SAFE_NO_PAD
            .encode(signing.sign(&transcript).to_bytes())
            .parse()
            .unwrap();

        verify_relay_assignment_signature(&assignment, &public).unwrap();
        assignment.header.public_port += 1;
        assert!(verify_relay_assignment_signature(&assignment, &public).is_err());
    }

    #[test]
    fn grant_bounds_and_strict_json_fail_closed() {
        let mut too_long = header();
        too_long.expires_at =
            Timestamp::from_datetime(too_long.issued_at.as_datetime() + Duration::hours(25));
        assert!(too_long.validate().is_err());
        let json = serde_json::to_string(&header()).unwrap();
        let with_unknown = json.replacen('{', "{\"unexpected\":true,", 1);
        assert!(serde_json::from_str::<RelayAssignmentHeader>(&with_unknown).is_err());
    }

    #[test]
    fn acknowledgement_is_exact_and_rejects_extensions() {
        let acknowledgement = AcknowledgeRelayAssignmentRequest {
            grant_id: RelayGrantId::new(),
            generation: RelayGeneration::new(2).unwrap(),
        };
        acknowledgement.validate().unwrap();
        let json = serde_json::to_string(&acknowledgement).unwrap();
        let round_trip: AcknowledgeRelayAssignmentRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(round_trip, acknowledgement);
        let with_unknown = json.replacen('{', "{\"registered\":true,", 1);
        assert!(serde_json::from_str::<AcknowledgeRelayAssignmentRequest>(&with_unknown).is_err());
    }

    #[test]
    fn relay_hosts_accept_ipv6_and_reject_noncanonical_dns() {
        let mut ipv6 = header();
        ipv6.public_host = "2001:db8::10".into();
        ipv6.tunnel_host = "::1".into();
        assert!(ipv6.validate().is_ok());

        for invalid in [
            "UPPER.example",
            "-relay.example",
            "relay_.example",
            "host:443",
        ] {
            let mut header = header();
            header.public_host = invalid.into();
            assert!(
                header.validate().is_err(),
                "accepted invalid host {invalid}"
            );
        }
    }

    #[test]
    fn material_debug_never_exposes_credentials() {
        let debug = format!("{:?}", material());
        assert!(!debug.contains("Y2VydA"));
        assert!(!debug.contains("a2V5"));
        assert!(!debug.contains(&URL_SAFE_NO_PAD.encode([7_u8; 32])));
    }

    #[test]
    fn route_signature_binds_hashes_and_header() {
        let signing = SigningKey::from_bytes(&[4_u8; 32]);
        let public =
            Ed25519PublicKey::from_str(&URL_SAFE_NO_PAD.encode(signing.verifying_key().to_bytes()))
                .unwrap();
        let mut route = SignedRelayRoute {
            header: header(),
            route_token_sha256: relay_token_digest(b"token"),
            client_certificate_sha256: relay_token_digest(b"certificate"),
            signing_key_id: ed25519_signing_key_id(&public).unwrap(),
            signature: URL_SAFE_NO_PAD.encode([0_u8; 64]).parse().unwrap(),
        };
        route.signature = URL_SAFE_NO_PAD
            .encode(
                signing
                    .sign(&relay_route_transcript(&route).unwrap())
                    .to_bytes(),
            )
            .parse()
            .unwrap();
        verify_relay_route_signature(&route, &public).unwrap();
        route.route_token_sha256 = relay_token_digest(b"other");
        assert!(verify_relay_route_signature(&route, &public).is_err());
    }
}
