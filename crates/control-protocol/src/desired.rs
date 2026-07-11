//! Canonical signing and verification for immutable desired state.

use crate::crypto::{Ed25519PublicKey, Ed25519Signature};
use crate::node::DesiredStateDocument;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
use thiserror::Error;

const DESIRED_STATE_DOMAIN: &[u8] = b"control/desired-state/v1";

/// Returns the canonical transcript covered by a desired-state signature.
///
/// Array order is significant. Publishers must therefore emit deterministic
/// user and server-name ordering; any in-transit reordering invalidates the
/// signature rather than creating a second representation of the artifact.
///
/// # Errors
///
/// Returns [`DesiredStateCryptoError::FieldTooLarge`] if a field cannot fit
/// the version 1 length-prefix encoding.
pub fn desired_state_transcript(
    document: &DesiredStateDocument,
) -> Result<Vec<u8>, DesiredStateCryptoError> {
    let mut transcript = Transcript::new(DESIRED_STATE_DOMAIN)?;
    transcript.bytes("schema-version", &document.schema_version.to_be_bytes())?;
    transcript.text("network-id", &document.network_id.to_string())?;
    transcript.text("node-id", &document.node_id.to_string())?;
    transcript.bytes("revision", &document.revision.get().to_be_bytes())?;
    transcript.text("created-at", &document.created_at.to_string())?;
    transcript.text("min-agent-version", &document.min_agent_version)?;
    transcript.text("signing-key-id", &document.signing_key_id.to_string())?;
    transcript.text(
        "controller-instance-id",
        &document.controller_instance_id.to_string(),
    )?;

    transcript.count("user-count", document.users.len())?;
    for user in &document.users {
        transcript.text("user-id", &user.user_id.to_string())?;
        transcript.text("credential-id", &user.credential_id.to_string())?;
        transcript.text("vless-uuid", user.vless_uuid.expose_secret())?;
        transcript.bytes("enabled", &[u8::from(user.enabled)])?;
    }

    transcript.bytes("listen-port", &document.xray.listen_port.to_be_bytes())?;
    transcript.count("server-name-count", document.xray.server_names.len())?;
    for server_name in &document.xray.server_names {
        transcript.text("server-name", server_name)?;
    }
    transcript.text("target", &document.xray.target)?;
    Ok(transcript.finish())
}

/// Verifies an Ed25519 signature over a desired-state transcript.
///
/// # Errors
///
/// Returns an error for malformed key material, an oversized transcript
/// field, or a signature that does not match the exact document.
pub fn verify_desired_state_signature(
    document: &DesiredStateDocument,
    signature: &Ed25519Signature,
    public_key: &Ed25519PublicKey,
) -> Result<(), DesiredStateCryptoError> {
    let public_bytes = decode_exact::<32>(public_key.as_str())?;
    let signature_bytes = decode_exact::<64>(signature.as_str())?;
    let verifying_key = VerifyingKey::from_bytes(&public_bytes)
        .map_err(|_| DesiredStateCryptoError::InvalidSignature)?;
    let signature = Signature::from_bytes(&signature_bytes);
    let transcript = desired_state_transcript(document)?;
    verifying_key
        .verify(&transcript, &signature)
        .map_err(|_| DesiredStateCryptoError::InvalidSignature)
}

fn decode_exact<const N: usize>(value: &str) -> Result<[u8; N], DesiredStateCryptoError> {
    URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| DesiredStateCryptoError::InvalidSignature)?
        .try_into()
        .map_err(|_| DesiredStateCryptoError::InvalidSignature)
}

struct Transcript {
    bytes: Vec<u8>,
}

impl Transcript {
    fn new(domain: &[u8]) -> Result<Self, DesiredStateCryptoError> {
        let mut transcript = Self { bytes: Vec::new() };
        transcript.bytes("domain", domain)?;
        Ok(transcript)
    }

    fn count(&mut self, label: &str, value: usize) -> Result<(), DesiredStateCryptoError> {
        let value = u32::try_from(value).map_err(|_| DesiredStateCryptoError::FieldTooLarge)?;
        self.bytes(label, &value.to_be_bytes())
    }

    fn text(&mut self, label: &str, value: &str) -> Result<(), DesiredStateCryptoError> {
        self.bytes(label, value.as_bytes())
    }

    fn bytes(&mut self, label: &str, value: &[u8]) -> Result<(), DesiredStateCryptoError> {
        let label_length =
            u16::try_from(label.len()).map_err(|_| DesiredStateCryptoError::FieldTooLarge)?;
        let value_length =
            u32::try_from(value.len()).map_err(|_| DesiredStateCryptoError::FieldTooLarge)?;
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
pub enum DesiredStateCryptoError {
    #[error("the desired-state signature is invalid")]
    InvalidSignature,
    #[error("a desired-state transcript field is too large")]
    FieldTooLarge,
}

#[cfg(test)]
mod tests {
    use super::{desired_state_transcript, verify_desired_state_signature};
    use crate::crypto::{Ed25519PublicKey, Ed25519Signature};
    use crate::id::{
        ControllerInstanceId, CredentialId, NetworkId, NodeId, Revision, SigningKeyId, Timestamp,
        UserId,
    };
    use crate::node::{DesiredStateDocument, DesiredUser, DesiredXrayState};
    use crate::secret::Secret;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    use ed25519_dalek::{Signer as _, SigningKey};

    fn document() -> DesiredStateDocument {
        DesiredStateDocument {
            schema_version: 1,
            network_id: NetworkId::new(),
            node_id: NodeId::new(),
            revision: Revision::new(7).unwrap(),
            created_at: "2026-07-11T20:00:00Z".parse::<Timestamp>().unwrap(),
            min_agent_version: "0.1.0".to_string(),
            users: vec![DesiredUser {
                user_id: UserId::new(),
                credential_id: CredentialId::new(),
                vless_uuid: Secret::new("2f55c837-7be6-4752-b58a-a7f51401bd89".to_string()),
                enabled: true,
            }],
            xray: DesiredXrayState {
                listen_port: 443,
                server_names: vec!["www.microsoft.com".to_string()],
                target: "www.microsoft.com:443".to_string(),
            },
            signing_key_id: SigningKeyId::new(),
            controller_instance_id: ControllerInstanceId::new(),
        }
    }

    #[test]
    fn exact_document_verifies_and_mutation_fails() {
        let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
        let public_key: Ed25519PublicKey = URL_SAFE_NO_PAD
            .encode(signing_key.verifying_key().to_bytes())
            .parse()
            .unwrap();
        let document = document();
        let transcript = desired_state_transcript(&document).unwrap();
        let signature: Ed25519Signature = URL_SAFE_NO_PAD
            .encode(signing_key.sign(&transcript).to_bytes())
            .parse()
            .unwrap();

        verify_desired_state_signature(&document, &signature, &public_key).unwrap();

        let mut changed = document;
        changed.xray.listen_port = 8443;
        assert!(verify_desired_state_signature(&changed, &signature, &public_key).is_err());
    }

    #[test]
    fn array_order_is_covered_by_the_transcript() {
        let mut document = document();
        document.xray.server_names = vec!["a.example".to_string(), "b.example".to_string()];
        let first = desired_state_transcript(&document).unwrap();
        document.xray.server_names.reverse();
        let second = desired_state_transcript(&document).unwrap();
        assert_ne!(first, second);
    }
}
