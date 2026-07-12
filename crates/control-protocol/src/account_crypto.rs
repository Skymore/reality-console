//! Canonical device-enrollment and encrypted profile-bundle cryptography.

use crate::account::{
    DeviceEnrollment, EncryptedProfilePayload, ProfileBundleManifest, ProfileEncryptionAlgorithm,
};
use crate::crypto::{Ed25519PublicKey, Ed25519Signature, Nonce, Sha256Digest, X25519PublicKey};
use crate::id::{DeviceActivationId, Timestamp};
use crate::secret::Secret;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use hpke::aead::ChaCha20Poly1305;
use hpke::kdf::HkdfSha256;
use hpke::kem::X25519HkdfSha256;
use hpke::{Deserializable, OpModeR, OpModeS, Serializable};
use rand_core::{OsRng, TryRngCore as _};
use sha2::{Digest, Sha256};
use thiserror::Error;

const ACTIVATION_PROOF_DOMAIN: &[u8] = b"control/device-activation/proof/v1";
const LOGIN_PROOF_DOMAIN: &[u8] = b"control/device-login/proof/v1";
const BUNDLE_SIGNATURE_DOMAIN: &[u8] = b"control/profile-bundle/signature/v1";
const PROFILE_HPKE_INFO: &[u8] = b"control/profile-bundle/profile-hpke/v1";

/// Returns the canonical transcript a device signs before consuming an activation.
///
/// # Errors
///
/// Returns [`AccountCryptoError::FieldTooLarge`] if a field exceeds the transcript encoding.
pub fn device_activation_proof_transcript(
    activation_id: DeviceActivationId,
    activation_expires_at: Timestamp,
    controller_origin: &str,
    enrollment: &DeviceEnrollment,
) -> Result<Vec<u8>, AccountCryptoError> {
    let mut transcript = Transcript::new(ACTIVATION_PROOF_DOMAIN)?;
    transcript.text("activation-id", &activation_id.to_string())?;
    transcript.text("activation-expires-at", &activation_expires_at.to_string())?;
    transcript.text("controller-origin", controller_origin)?;
    transcript.text(
        "identity-public-key",
        enrollment.identity_public_key.as_str(),
    )?;
    transcript.text(
        "encryption-public-key",
        enrollment.encryption_public_key.as_str(),
    )?;
    transcript.text("nonce", enrollment.nonce.as_str())?;
    transcript.text("display-name", &enrollment.display_name)?;
    transcript.text("client-version", &enrollment.client_version)?;
    transcript.text("platform", &enrollment.platform)?;
    Ok(transcript.finish())
}

/// Verifies a device activation proof against its submitted Ed25519 key.
///
/// # Errors
///
/// Returns an error for malformed keys/signatures or a failed proof.
pub fn verify_device_activation_proof(
    enrollment: &DeviceEnrollment,
    transcript: &[u8],
) -> Result<(), AccountCryptoError> {
    let key_bytes = decode_exact(enrollment.identity_public_key.as_str(), 32)?;
    let signature_bytes = decode_exact(enrollment.proof.as_str(), 64)?;
    let verifying_key = VerifyingKey::from_bytes(
        &key_bytes
            .try_into()
            .map_err(|_| AccountCryptoError::InvalidEncoding)?,
    )
    .map_err(|_| AccountCryptoError::InvalidEncoding)?;
    let signature = Signature::from_bytes(
        &signature_bytes
            .try_into()
            .map_err(|_| AccountCryptoError::InvalidEncoding)?,
    );
    verifying_key
        .verify(transcript, &signature)
        .map_err(|_| AccountCryptoError::SignatureInvalid)
}

/// Returns the canonical proof transcript for password login device binding.
///
/// The password is deliberately excluded; HTTPS and Argon2id authenticate it,
/// while this signature proves possession of the submitted device identity key.
///
/// # Errors
///
/// Returns [`AccountCryptoError::FieldTooLarge`] if a field exceeds the encoding.
pub fn device_login_proof_transcript(
    account: &str,
    controller_origin: &str,
    enrollment: &DeviceEnrollment,
) -> Result<Vec<u8>, AccountCryptoError> {
    let mut transcript = Transcript::new(LOGIN_PROOF_DOMAIN)?;
    transcript.text("account", account)?;
    transcript.text("controller-origin", controller_origin)?;
    transcript.text(
        "identity-public-key",
        enrollment.identity_public_key.as_str(),
    )?;
    transcript.text(
        "encryption-public-key",
        enrollment.encryption_public_key.as_str(),
    )?;
    transcript.text("nonce", enrollment.nonce.as_str())?;
    transcript.text("display-name", &enrollment.display_name)?;
    transcript.text("client-version", &enrollment.client_version)?;
    transcript.text("platform", &enrollment.platform)?;
    Ok(transcript.finish())
}

/// Returns the canonical transcript signed by the controller for a profile bundle.
///
/// Payloads are sorted by node identity before their complete encrypted encodings are hashed.
///
/// # Errors
///
/// Returns an error if deterministic serialization fails or a field is too large.
pub fn profile_bundle_signature_transcript(
    manifest: &ProfileBundleManifest,
    encrypted_profiles: &[EncryptedProfilePayload],
) -> Result<Vec<u8>, AccountCryptoError> {
    let mut transcript = Transcript::new(BUNDLE_SIGNATURE_DOMAIN)?;
    let manifest_json = serde_json::to_vec(manifest)?;
    transcript.bytes("manifest-json", &manifest_json)?;
    let count =
        u32::try_from(encrypted_profiles.len()).map_err(|_| AccountCryptoError::FieldTooLarge)?;
    transcript.bytes("encrypted-profile-count", &count.to_be_bytes())?;
    let mut profiles: Vec<_> = encrypted_profiles.iter().collect();
    profiles.sort_by_key(|profile| profile.node_id);
    for profile in profiles {
        transcript.text("node-id", &profile.node_id.to_string())?;
        transcript.bytes("encrypted-profile-json", &serde_json::to_vec(profile)?)?;
    }
    Ok(transcript.finish())
}

/// Verifies a controller signature over a canonical profile bundle transcript.
///
/// # Errors
///
/// Returns an error for malformed keys/signatures or a failed signature.
pub fn verify_profile_bundle_signature(
    public_key: &Ed25519PublicKey,
    signature: &Ed25519Signature,
    transcript: &[u8],
) -> Result<(), AccountCryptoError> {
    let key_bytes = decode_exact(public_key.as_str(), 32)?;
    let signature_bytes = decode_exact(signature.as_str(), 64)?;
    let verifying_key = VerifyingKey::from_bytes(
        &key_bytes
            .try_into()
            .map_err(|_| AccountCryptoError::InvalidEncoding)?,
    )
    .map_err(|_| AccountCryptoError::InvalidEncoding)?;
    let signature = Signature::from_bytes(
        &signature_bytes
            .try_into()
            .map_err(|_| AccountCryptoError::InvalidEncoding)?,
    );
    verifying_key
        .verify(transcript, &signature)
        .map_err(|_| AccountCryptoError::SignatureInvalid)
}

/// Encrypts one canonical node profile to an enrolled device with HPKE base mode.
///
/// The caller supplies bundle/node-bound AAD and a cryptographically secure RNG.
///
/// # Errors
///
/// Returns an error for an invalid recipient key or HPKE failure.
pub fn encrypt_profile(
    recipient: &X25519PublicKey,
    plaintext: &[u8],
    aad: &[u8],
) -> Result<EncryptedProfileCiphertext, AccountCryptoError> {
    let mut envelope_nonce = [0_u8; 16];
    OsRng
        .try_fill_bytes(&mut envelope_nonce)
        .map_err(|_| AccountCryptoError::Encryption)?;
    let nonce = URL_SAFE_NO_PAD
        .encode(envelope_nonce)
        .parse::<Nonce>()
        .map_err(|_| AccountCryptoError::InvalidEncoding)?;
    let bound_aad = envelope_aad(aad, nonce.as_str())?;
    let recipient_bytes = decode_exact(recipient.as_str(), 32)?;
    let recipient_key = <X25519HkdfSha256 as hpke::Kem>::PublicKey::from_bytes(&recipient_bytes)
        .map_err(|_| AccountCryptoError::InvalidEncoding)?;
    let mut hpke_rng = OsRng.unwrap_err();
    let (encapped_key, mut context) =
        hpke::setup_sender::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256, _>(
            &OpModeS::Base,
            &recipient_key,
            PROFILE_HPKE_INFO,
            &mut hpke_rng,
        )
        .map_err(|_| AccountCryptoError::Encryption)?;
    let ciphertext = context
        .seal(plaintext, &bound_aad)
        .map_err(|_| AccountCryptoError::Encryption)?;
    let ephemeral_public_key = URL_SAFE_NO_PAD
        .encode(encapped_key.to_bytes())
        .parse::<X25519PublicKey>()
        .map_err(|_| AccountCryptoError::InvalidEncoding)?;
    Ok(EncryptedProfileCiphertext {
        algorithm: ProfileEncryptionAlgorithm::HpkeBaseX25519HkdfSha256ChaCha20Poly1305,
        ephemeral_public_key,
        nonce,
        ciphertext: Secret::new(URL_SAFE_NO_PAD.encode(ciphertext)),
    })
}

/// Decrypts one HPKE profile ciphertext with the device's X25519 private key.
///
/// # Errors
///
/// Returns an error for malformed input, an unsupported algorithm, or failed authentication.
pub fn decrypt_profile(
    recipient_private_key: &[u8; 32],
    encrypted: &EncryptedProfileCiphertext,
    aad: &[u8],
) -> Result<Vec<u8>, AccountCryptoError> {
    if encrypted.algorithm != ProfileEncryptionAlgorithm::HpkeBaseX25519HkdfSha256ChaCha20Poly1305 {
        return Err(AccountCryptoError::UnsupportedAlgorithm);
    }
    let private_key =
        <X25519HkdfSha256 as hpke::Kem>::PrivateKey::from_bytes(recipient_private_key)
            .map_err(|_| AccountCryptoError::InvalidEncoding)?;
    let encapped_bytes = decode_exact(encrypted.ephemeral_public_key.as_str(), 32)?;
    let encapped_key = <X25519HkdfSha256 as hpke::Kem>::EncappedKey::from_bytes(&encapped_bytes)
        .map_err(|_| AccountCryptoError::InvalidEncoding)?;
    let mut context = hpke::setup_receiver::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>(
        &OpModeR::Base,
        &private_key,
        &encapped_key,
        PROFILE_HPKE_INFO,
    )
    .map_err(|_| AccountCryptoError::Encryption)?;
    let ciphertext = URL_SAFE_NO_PAD
        .decode(encrypted.ciphertext.expose_secret())
        .map_err(|_| AccountCryptoError::InvalidEncoding)?;
    let bound_aad = envelope_aad(aad, encrypted.nonce.as_str())?;
    context
        .open(&ciphertext, &bound_aad)
        .map_err(|_| AccountCryptoError::Encryption)
}

fn envelope_aad(aad: &[u8], nonce: &str) -> Result<Vec<u8>, AccountCryptoError> {
    let aad_length = u32::try_from(aad.len()).map_err(|_| AccountCryptoError::FieldTooLarge)?;
    let mut bound = Vec::with_capacity(4 + aad.len() + nonce.len());
    bound.extend_from_slice(&aad_length.to_be_bytes());
    bound.extend_from_slice(aad);
    bound.extend_from_slice(nonce.as_bytes());
    Ok(bound)
}

/// HPKE fields copied into one [`EncryptedProfilePayload`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedProfileCiphertext {
    pub algorithm: ProfileEncryptionAlgorithm,
    pub ephemeral_public_key: X25519PublicKey,
    pub nonce: Nonce,
    pub ciphertext: Secret<String>,
}

/// Computes the signed manifest digest for a complete encrypted payload object.
///
/// # Errors
///
/// Returns an error if deterministic protocol serialization fails.
pub fn encrypted_profile_digest(
    payload: &EncryptedProfilePayload,
) -> Result<Sha256Digest, AccountCryptoError> {
    let bytes = serde_json::to_vec(payload)?;
    Ok(Sha256Digest::from_bytes(Sha256::digest(bytes).into()))
}

fn decode_exact(value: &str, length: usize) -> Result<Vec<u8>, AccountCryptoError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| AccountCryptoError::InvalidEncoding)?;
    if bytes.len() != length {
        return Err(AccountCryptoError::InvalidEncoding);
    }
    Ok(bytes)
}

struct Transcript(Vec<u8>);

impl Transcript {
    fn new(domain: &[u8]) -> Result<Self, AccountCryptoError> {
        let mut value = Self(Vec::new());
        value.bytes("domain", domain)?;
        Ok(value)
    }

    fn text(&mut self, label: &str, value: &str) -> Result<(), AccountCryptoError> {
        self.bytes(label, value.as_bytes())
    }

    fn bytes(&mut self, label: &str, value: &[u8]) -> Result<(), AccountCryptoError> {
        let label_length =
            u16::try_from(label.len()).map_err(|_| AccountCryptoError::FieldTooLarge)?;
        let value_length =
            u32::try_from(value.len()).map_err(|_| AccountCryptoError::FieldTooLarge)?;
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

#[derive(Debug, Error)]
pub enum AccountCryptoError {
    #[error("a canonical transcript field is too large")]
    FieldTooLarge,
    #[error("a cryptographic value has invalid encoding")]
    InvalidEncoding,
    #[error("signature verification failed")]
    SignatureInvalid,
    #[error("profile encryption or authentication failed")]
    Encryption,
    #[error("profile encryption algorithm is unsupported")]
    UnsupportedAlgorithm,
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

#[cfg(test)]
mod tests {
    use super::{
        decrypt_profile, device_activation_proof_transcript, encrypt_profile,
        verify_device_activation_proof,
    };
    use crate::account::DeviceEnrollment;
    use crate::crypto::{Ed25519PublicKey, Ed25519Signature, Nonce, X25519PublicKey};
    use crate::id::{DeviceActivationId, Timestamp};
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    use ed25519_dalek::{Signer as _, SigningKey};
    use hpke::kem::X25519HkdfSha256;
    use hpke::{Kem as _, Serializable as _};
    use std::str::FromStr as _;

    #[test]
    fn activation_proof_binds_every_device_and_ceremony_field() {
        let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
        let mut enrollment = DeviceEnrollment {
            display_name: "Laptop".to_string(),
            client_version: "0.1.0".to_string(),
            platform: "macos-arm64".to_string(),
            identity_public_key: Ed25519PublicKey::from_str(
                &URL_SAFE_NO_PAD.encode(signing_key.verifying_key().to_bytes()),
            )
            .unwrap(),
            encryption_public_key: X25519PublicKey::from_str(&URL_SAFE_NO_PAD.encode([8_u8; 32]))
                .unwrap(),
            nonce: Nonce::from_str(&URL_SAFE_NO_PAD.encode([9_u8; 32])).unwrap(),
            proof: Ed25519Signature::from_str(&URL_SAFE_NO_PAD.encode([0_u8; 64])).unwrap(),
        };
        let activation_id = DeviceActivationId::new();
        let expires_at = "2026-07-12T00:00:00Z".parse::<Timestamp>().unwrap();
        let transcript = device_activation_proof_transcript(
            activation_id,
            expires_at,
            "https://control.example",
            &enrollment,
        )
        .unwrap();
        enrollment.proof = URL_SAFE_NO_PAD
            .encode(signing_key.sign(&transcript).to_bytes())
            .parse()
            .unwrap();
        assert!(verify_device_activation_proof(&enrollment, &transcript).is_ok());

        enrollment.platform = "windows-x64".to_string();
        let changed = device_activation_proof_transcript(
            activation_id,
            expires_at,
            "https://control.example",
            &enrollment,
        )
        .unwrap();
        assert!(verify_device_activation_proof(&enrollment, &changed).is_err());
    }

    #[test]
    fn hpke_round_trip_authenticates_recipient_ciphertext_and_aad() {
        let (private_key, public_key) = X25519HkdfSha256::derive_keypair(&[11_u8; 32]);
        let public_key =
            X25519PublicKey::from_str(&URL_SAFE_NO_PAD.encode(public_key.to_bytes())).unwrap();
        let private_bytes: [u8; 32] = private_key.to_bytes().as_slice().try_into().unwrap();
        let plaintext = br#"{"vlessUuid":"secret"}"#;
        let encrypted = encrypt_profile(&public_key, plaintext, b"bundle-device-node").unwrap();

        assert_eq!(
            decrypt_profile(&private_bytes, &encrypted, b"bundle-device-node").unwrap(),
            plaintext
        );
        assert!(decrypt_profile(&private_bytes, &encrypted, b"different-node").is_err());

        let mut tampered = encrypted;
        tampered.ciphertext =
            crate::secret::Secret::new(format!("A{}", &tampered.ciphertext.expose_secret()[1..]));
        assert!(decrypt_profile(&private_bytes, &tampered, b"bundle-device-node").is_err());
    }
}
