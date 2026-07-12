//! Strict verification boundary for signed application update manifests.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
use semver::Version;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use thiserror::Error;
use url::Url;
use uuid::Uuid;

/// Only supported release manifest schema.
pub const RELEASE_MANIFEST_SCHEMA_VERSION: u16 = 1;
/// Only supported emergency rollback authorization schema.
pub const ROLLBACK_AUTHORIZATION_SCHEMA_VERSION: u16 = 1;
const RELEASE_DOMAIN: &[u8] = b"private-network-release-manifest-v1\0";
const ROLLBACK_DOMAIN: &[u8] = b"private-network-rollback-authorization-v1\0";
const MAX_ARTIFACTS: usize = 32;
const MAX_RELEASE_NOTES_URL: usize = 2_048;
const MAX_REASON_CODE: usize = 64;
const MAX_KEY_ID: usize = 64;
const ED25519_PUBLIC_KEY_BASE64URL_LENGTH: usize = 43;
const ED25519_SIGNATURE_BASE64URL_LENGTH: usize = 86;
const MAX_CLOCK_SKEW_SECONDS: i64 = 5 * 60;

/// Independently released product.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Product {
    /// Friend-facing network client.
    Connect,
    /// Restricted contributed-node service.
    NodeHost,
    /// Central controller service.
    Control,
    /// Raw TCP relay.
    Relay,
}

/// Supported release operating system.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Platform {
    /// Apple macOS.
    Macos,
    /// Microsoft Windows.
    Windows,
    /// Linux service distribution.
    Linux,
}

/// Supported release architecture.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Architecture {
    /// 64-bit ARM.
    Aarch64,
    /// 64-bit x86.
    X86_64,
}

/// One immutable package described by a release.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReleaseArtifact {
    /// Product contained in the package.
    pub product: Product,
    /// Target operating system.
    pub platform: Platform,
    /// Target CPU architecture.
    pub architecture: Architecture,
    /// Product version.
    pub version: Version,
    /// Exact package length.
    pub size_bytes: u64,
    /// Lowercase SHA-256 of the package.
    pub sha256: String,
    /// Lowercase SHA-256 of the package SBOM.
    pub sbom_sha256: String,
    /// Minimum configuration/protocol schema supported after installation.
    pub minimum_configuration_schema: u16,
    /// Maximum configuration/protocol schema supported after installation.
    pub maximum_configuration_schema: u16,
    /// Bundled Xray version when this product embeds Xray.
    pub xray_version: Option<Version>,
}

impl ReleaseArtifact {
    fn key(&self) -> (Product, Platform, Architecture) {
        (self.product, self.platform, self.architecture)
    }

    fn validate(&self) -> Result<(), ManifestError> {
        if self.size_bytes == 0
            || !valid_sha256(&self.sha256)
            || !valid_sha256(&self.sbom_sha256)
            || self.minimum_configuration_schema == 0
            || self.minimum_configuration_schema > self.maximum_configuration_schema
        {
            return Err(ManifestError::InvalidArtifact);
        }
        let expects_xray = matches!(self.product, Product::Connect | Product::NodeHost);
        if expects_xray != self.xray_version.is_some() {
            return Err(ManifestError::InvalidArtifact);
        }
        Ok(())
    }
}

/// Canonical signed release inventory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReleaseManifest {
    /// Closed manifest schema.
    pub schema_version: u16,
    /// Random immutable release identity.
    pub release_id: Uuid,
    /// Lowercase 40- or 64-character source commit digest.
    pub source_commit: String,
    /// Unix issue time.
    pub issued_at: i64,
    /// Optional HTTPS release notes URL.
    pub release_notes_url: Option<String>,
    /// Sorted unique artifact inventory.
    pub artifacts: Vec<ReleaseArtifact>,
}

impl ReleaseManifest {
    /// Validates closed schema, deterministic ordering, bounds, and artifact invariants.
    pub fn validate(&self) -> Result<(), ManifestError> {
        if self.schema_version != RELEASE_MANIFEST_SCHEMA_VERSION
            || self.issued_at <= 0
            || !valid_source_commit(&self.source_commit)
            || self.artifacts.is_empty()
            || self.artifacts.len() > MAX_ARTIFACTS
            || self
                .release_notes_url
                .as_deref()
                .is_some_and(|url| !valid_https_url(url))
        {
            return Err(ManifestError::InvalidManifest);
        }
        let mut previous = None;
        let mut unique = BTreeSet::new();
        for artifact in &self.artifacts {
            artifact.validate()?;
            let key = artifact.key();
            if previous.is_some_and(|value| value >= key) || !unique.insert(key) {
                return Err(ManifestError::ArtifactOrder);
            }
            previous = Some(key);
        }
        Ok(())
    }

    fn artifact(
        &self,
        product: Product,
        platform: Platform,
        architecture: Architecture,
    ) -> Result<&ReleaseArtifact, ManifestError> {
        self.artifacts
            .iter()
            .find(|artifact| artifact.key() == (product, platform, architecture))
            .ok_or(ManifestError::ArtifactNotFound)
    }
}

/// Signed release wrapper. The key ID is part of the signed transcript.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedReleaseManifest {
    /// Offline release key identity.
    pub key_id: String,
    /// Canonical release payload.
    pub manifest: ReleaseManifest,
    /// Base64url Ed25519 signature.
    pub signature: String,
}

/// Exact emergency downgrade authorization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RollbackAuthorization {
    /// Closed rollback schema.
    pub schema_version: u16,
    /// Random authorization identity.
    pub authorization_id: Uuid,
    /// Exact product.
    pub product: Product,
    /// Exact operating system.
    pub platform: Platform,
    /// Exact architecture.
    pub architecture: Architecture,
    /// Installed version permitted to roll back.
    pub from_version: Version,
    /// Exact approved target version.
    pub to_version: Version,
    /// Exact approved package digest.
    pub artifact_sha256: String,
    /// Stable non-secret incident/change reason code.
    pub reason_code: String,
    /// Unix issue time.
    pub issued_at: i64,
    /// Unix hard expiry.
    pub expires_at: i64,
}

impl RollbackAuthorization {
    fn validate(&self) -> Result<(), ManifestError> {
        if self.schema_version != ROLLBACK_AUTHORIZATION_SCHEMA_VERSION
            || self.issued_at <= 0
            || self.expires_at <= self.issued_at
            || self.to_version >= self.from_version
            || !valid_sha256(&self.artifact_sha256)
            || !valid_reason_code(&self.reason_code)
        {
            return Err(ManifestError::InvalidRollbackAuthorization);
        }
        Ok(())
    }
}

/// Separately signed downgrade grant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedRollbackAuthorization {
    /// Offline rollback key identity.
    pub key_id: String,
    /// Exact downgrade grant.
    pub authorization: RollbackAuthorization,
    /// Base64url Ed25519 signature.
    pub signature: String,
}

/// Installed-target policy supplied by the updater, never by the manifest.
#[derive(Debug, Clone)]
pub struct UpdatePolicy {
    /// Expected product.
    pub product: Product,
    /// Expected platform.
    pub platform: Platform,
    /// Expected architecture.
    pub architecture: Architecture,
    /// Currently installed version.
    pub current_version: Version,
    /// Controller policy floor, including denied vulnerable versions.
    pub minimum_allowed_version: Version,
    /// Current configuration schema that the new binary must understand.
    pub required_configuration_schema: u16,
    /// Current Unix time used for rollback expiry.
    pub now: i64,
}

/// A release package approved for byte-level digest verification and installation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedUpdate {
    /// Immutable release ID.
    pub release_id: Uuid,
    /// Exact approved artifact.
    pub artifact: ReleaseArtifact,
    /// Whether an independent emergency rollback grant was required.
    pub emergency_rollback: bool,
}

/// Pinned offline release and rollback verification roots.
#[derive(Debug, Clone, Default)]
pub struct ReleaseTrustStore {
    release_keys: BTreeMap<String, VerifyingKey>,
    rollback_keys: BTreeMap<String, VerifyingKey>,
}

impl ReleaseTrustStore {
    /// Creates an empty trust store. Production callers must add pinned roots explicitly.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds one release key from an unpadded base64url Ed25519 public key.
    pub fn add_release_key(&mut self, key_id: &str, public_key: &str) -> Result<(), ManifestError> {
        insert_key(&mut self.release_keys, key_id, public_key)
    }

    /// Adds one separately controlled rollback key.
    pub fn add_rollback_key(
        &mut self,
        key_id: &str,
        public_key: &str,
    ) -> Result<(), ManifestError> {
        insert_key(&mut self.rollback_keys, key_id, public_key)
    }

    /// Verifies release authenticity and exact updater policy before any package is opened.
    pub fn verify_update(
        &self,
        signed: &SignedReleaseManifest,
        policy: &UpdatePolicy,
        rollback: Option<&SignedRollbackAuthorization>,
    ) -> Result<VerifiedUpdate, ManifestError> {
        signed.manifest.validate()?;
        if policy.now <= 0
            || signed.manifest.issued_at > policy.now.saturating_add(MAX_CLOCK_SKEW_SECONDS)
        {
            return Err(ManifestError::ManifestNotYetValid);
        }
        verify_signed(
            &self.release_keys,
            &signed.key_id,
            &signed.signature,
            &release_transcript(&signed.key_id, &signed.manifest)?,
        )?;
        let artifact =
            signed
                .manifest
                .artifact(policy.product, policy.platform, policy.architecture)?;
        if artifact.version < policy.minimum_allowed_version {
            return Err(ManifestError::VersionDenied);
        }
        if policy.required_configuration_schema < artifact.minimum_configuration_schema
            || policy.required_configuration_schema > artifact.maximum_configuration_schema
        {
            return Err(ManifestError::ConfigurationIncompatible);
        }
        let downgrade = artifact.version < policy.current_version;
        if downgrade {
            self.verify_rollback(rollback, policy, artifact)?;
        }
        Ok(VerifiedUpdate {
            release_id: signed.manifest.release_id,
            artifact: artifact.clone(),
            emergency_rollback: downgrade,
        })
    }

    fn verify_rollback(
        &self,
        signed: Option<&SignedRollbackAuthorization>,
        policy: &UpdatePolicy,
        artifact: &ReleaseArtifact,
    ) -> Result<(), ManifestError> {
        let signed = signed.ok_or(ManifestError::DowngradeDenied)?;
        signed.authorization.validate()?;
        verify_signed(
            &self.rollback_keys,
            &signed.key_id,
            &signed.signature,
            &rollback_transcript(&signed.key_id, &signed.authorization)?,
        )?;
        let authorization = &signed.authorization;
        if authorization.product != policy.product
            || authorization.platform != policy.platform
            || authorization.architecture != policy.architecture
            || authorization.from_version != policy.current_version
            || authorization.to_version != artifact.version
            || authorization.artifact_sha256 != artifact.sha256
        {
            return Err(ManifestError::RollbackMismatch);
        }
        if policy.now < authorization.issued_at || policy.now >= authorization.expires_at {
            return Err(ManifestError::RollbackExpired);
        }
        Ok(())
    }
}

/// Verifies package length and SHA-256 before installation.
pub fn verify_artifact<R: Read>(
    mut reader: R,
    artifact: &ReleaseArtifact,
) -> Result<(), ManifestError> {
    let mut digest = Sha256::new();
    let mut length = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = reader
            .read(&mut buffer)
            .map_err(|_| ManifestError::ArtifactRead)?;
        if read == 0 {
            break;
        }
        length = length
            .checked_add(u64::try_from(read).map_err(|_| ManifestError::ArtifactTooLarge)?)
            .ok_or(ManifestError::ArtifactTooLarge)?;
        if length > artifact.size_bytes {
            return Err(ManifestError::ArtifactDigestMismatch);
        }
        digest.update(&buffer[..read]);
    }
    let actual = format!("{:x}", digest.finalize());
    if length != artifact.size_bytes || actual != artifact.sha256 {
        return Err(ManifestError::ArtifactDigestMismatch);
    }
    Ok(())
}

/// Returns the exact domain-separated transcript for an offline release signer.
pub fn release_signing_transcript(
    key_id: &str,
    manifest: &ReleaseManifest,
) -> Result<Vec<u8>, ManifestError> {
    manifest.validate()?;
    release_transcript(key_id, manifest)
}

/// Returns the exact domain-separated transcript for an independent rollback signer.
pub fn rollback_signing_transcript(
    key_id: &str,
    authorization: &RollbackAuthorization,
) -> Result<Vec<u8>, ManifestError> {
    authorization.validate()?;
    rollback_transcript(key_id, authorization)
}

fn release_transcript(key_id: &str, manifest: &ReleaseManifest) -> Result<Vec<u8>, ManifestError> {
    transcript(RELEASE_DOMAIN, key_id, manifest)
}

fn rollback_transcript(
    key_id: &str,
    authorization: &RollbackAuthorization,
) -> Result<Vec<u8>, ManifestError> {
    transcript(ROLLBACK_DOMAIN, key_id, authorization)
}

fn transcript<T: Serialize>(
    domain: &[u8],
    key_id: &str,
    value: &T,
) -> Result<Vec<u8>, ManifestError> {
    validate_key_id(key_id)?;
    let encoded = serde_json::to_vec(value).map_err(|_| ManifestError::CanonicalEncoding)?;
    let mut output = Vec::with_capacity(domain.len() + key_id.len() + 1 + encoded.len());
    output.extend_from_slice(domain);
    output.extend_from_slice(key_id.as_bytes());
    output.push(0);
    output.extend_from_slice(&encoded);
    Ok(output)
}

fn verify_signed(
    keys: &BTreeMap<String, VerifyingKey>,
    key_id: &str,
    encoded_signature: &str,
    transcript: &[u8],
) -> Result<(), ManifestError> {
    let key = keys.get(key_id).ok_or(ManifestError::UnknownKey)?;
    if encoded_signature.len() != ED25519_SIGNATURE_BASE64URL_LENGTH {
        return Err(ManifestError::InvalidSignature);
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded_signature)
        .map_err(|_| ManifestError::InvalidSignature)?;
    let signature = Signature::from_slice(&bytes).map_err(|_| ManifestError::InvalidSignature)?;
    key.verify(transcript, &signature)
        .map_err(|_| ManifestError::InvalidSignature)
}

fn insert_key(
    keys: &mut BTreeMap<String, VerifyingKey>,
    key_id: &str,
    public_key: &str,
) -> Result<(), ManifestError> {
    validate_key_id(key_id)?;
    if public_key.len() != ED25519_PUBLIC_KEY_BASE64URL_LENGTH {
        return Err(ManifestError::InvalidPublicKey);
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(public_key)
        .map_err(|_| ManifestError::InvalidPublicKey)?;
    let bytes: [u8; 32] = decoded
        .try_into()
        .map_err(|_| ManifestError::InvalidPublicKey)?;
    let key = VerifyingKey::from_bytes(&bytes).map_err(|_| ManifestError::InvalidPublicKey)?;
    if keys.insert(key_id.to_owned(), key).is_some() {
        return Err(ManifestError::DuplicateKey);
    }
    Ok(())
}

fn validate_key_id(value: &str) -> Result<(), ManifestError> {
    if value.is_empty()
        || value.len() > MAX_KEY_ID
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    {
        return Err(ManifestError::InvalidKeyId);
    }
    Ok(())
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_source_commit(value: &str) -> bool {
    matches!(value.len(), 40 | 64) && valid_hex(value)
}

fn valid_hex(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_reason_code(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_REASON_CODE
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

fn valid_https_url(value: &str) -> bool {
    if value.len() > MAX_RELEASE_NOTES_URL || value.bytes().any(|byte| byte.is_ascii_control()) {
        return false;
    }
    Url::parse(value).is_ok_and(|url| {
        url.scheme() == "https"
            && url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.fragment().is_none()
    })
}

/// Closed stable update verification failures.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum ManifestError {
    /// Manifest-level fields are invalid.
    #[error("release_manifest_invalid")]
    InvalidManifest,
    /// Artifact metadata is invalid.
    #[error("release_artifact_invalid")]
    InvalidArtifact,
    /// Artifacts are not strictly sorted and unique.
    #[error("release_artifact_order_invalid")]
    ArtifactOrder,
    /// Expected product/platform/architecture artifact is absent.
    #[error("release_artifact_not_found")]
    ArtifactNotFound,
    /// Key ID has an invalid shape.
    #[error("release_key_id_invalid")]
    InvalidKeyId,
    /// Pinned public key is malformed.
    #[error("release_public_key_invalid")]
    InvalidPublicKey,
    /// A key ID was added twice.
    #[error("release_key_duplicate")]
    DuplicateKey,
    /// Signature references an untrusted key.
    #[error("release_key_unknown")]
    UnknownKey,
    /// Signature is malformed or does not verify.
    #[error("release_signature_invalid")]
    InvalidSignature,
    /// Deterministic transcript encoding failed.
    #[error("release_manifest_encoding_failed")]
    CanonicalEncoding,
    /// Manifest issue time is implausibly ahead of the updater clock.
    #[error("release_manifest_not_yet_valid")]
    ManifestNotYetValid,
    /// Controller policy denies this version.
    #[error("release_version_denied")]
    VersionDenied,
    /// Installed configuration is outside the new binary's supported range.
    #[error("release_configuration_incompatible")]
    ConfigurationIncompatible,
    /// Downgrade lacks independent authorization.
    #[error("release_downgrade_denied")]
    DowngradeDenied,
    /// Rollback grant is structurally invalid.
    #[error("release_rollback_invalid")]
    InvalidRollbackAuthorization,
    /// Rollback grant does not exactly name this transition and artifact.
    #[error("release_rollback_mismatch")]
    RollbackMismatch,
    /// Rollback grant is not currently valid.
    #[error("release_rollback_expired")]
    RollbackExpired,
    /// Package could not be read.
    #[error("release_artifact_read_failed")]
    ArtifactRead,
    /// Package length counter overflowed.
    #[error("release_artifact_too_large")]
    ArtifactTooLarge,
    /// Package bytes do not match signed length and digest.
    #[error("release_artifact_digest_mismatch")]
    ArtifactDigestMismatch,
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer as _, SigningKey};
    use std::io::Cursor;

    const PACKAGE: &[u8] = b"signed release package";

    fn artifact(version: &str) -> ReleaseArtifact {
        ReleaseArtifact {
            product: Product::Connect,
            platform: Platform::Macos,
            architecture: Architecture::Aarch64,
            version: Version::parse(version).unwrap(),
            size_bytes: u64::try_from(PACKAGE.len()).unwrap(),
            sha256: format!("{:x}", Sha256::digest(PACKAGE)),
            sbom_sha256: "a".repeat(64),
            minimum_configuration_schema: 1,
            maximum_configuration_schema: 2,
            xray_version: Some(Version::parse("26.3.27").unwrap()),
        }
    }

    fn manifest(version: &str) -> ReleaseManifest {
        ReleaseManifest {
            schema_version: RELEASE_MANIFEST_SCHEMA_VERSION,
            release_id: Uuid::new_v4(),
            source_commit: "b".repeat(40),
            issued_at: 1_800_000_000,
            release_notes_url: Some("https://updates.example/releases/1".to_string()),
            artifacts: vec![artifact(version)],
        }
    }

    fn signed_manifest(key_id: &str, key: &SigningKey, version: &str) -> SignedReleaseManifest {
        let manifest = manifest(version);
        let transcript = release_signing_transcript(key_id, &manifest).unwrap();
        SignedReleaseManifest {
            key_id: key_id.to_string(),
            manifest,
            signature: URL_SAFE_NO_PAD.encode(key.sign(&transcript).to_bytes()),
        }
    }

    fn trust(release: &SigningKey, rollback: &SigningKey) -> ReleaseTrustStore {
        let mut trust = ReleaseTrustStore::new();
        trust
            .add_release_key(
                "release_2026",
                &URL_SAFE_NO_PAD.encode(release.verifying_key().to_bytes()),
            )
            .unwrap();
        trust
            .add_rollback_key(
                "rollback_2026",
                &URL_SAFE_NO_PAD.encode(rollback.verifying_key().to_bytes()),
            )
            .unwrap();
        trust
    }

    fn policy(current: &str) -> UpdatePolicy {
        UpdatePolicy {
            product: Product::Connect,
            platform: Platform::Macos,
            architecture: Architecture::Aarch64,
            current_version: Version::parse(current).unwrap(),
            minimum_allowed_version: Version::parse("1.0.0").unwrap(),
            required_configuration_schema: 1,
            now: 1_800_000_100,
        }
    }

    #[test]
    fn verifies_exact_signed_upgrade_and_package_bytes() {
        let release = SigningKey::from_bytes(&[7_u8; 32]);
        let rollback = SigningKey::from_bytes(&[8_u8; 32]);
        let signed = signed_manifest("release_2026", &release, "2.0.0");
        let verified = trust(&release, &rollback)
            .verify_update(&signed, &policy("1.0.0"), None)
            .unwrap();

        assert!(!verified.emergency_rollback);
        verify_artifact(Cursor::new(PACKAGE), &verified.artifact).unwrap();
    }

    #[test]
    fn tampering_platform_or_digest_fails_closed() {
        let release = SigningKey::from_bytes(&[7_u8; 32]);
        let rollback = SigningKey::from_bytes(&[8_u8; 32]);
        let mut signed = signed_manifest("release_2026", &release, "2.0.0");
        signed.manifest.artifacts[0].platform = Platform::Windows;
        assert_eq!(
            trust(&release, &rollback).verify_update(&signed, &policy("1.0.0"), None),
            Err(ManifestError::InvalidSignature)
        );

        let signed = signed_manifest("release_2026", &release, "2.0.0");
        assert_eq!(
            verify_artifact(Cursor::new(b"wrong bytes"), &signed.manifest.artifacts[0]),
            Err(ManifestError::ArtifactDigestMismatch)
        );
    }

    #[test]
    fn downgrade_requires_exact_separately_signed_unexpired_grant() {
        let release = SigningKey::from_bytes(&[7_u8; 32]);
        let rollback = SigningKey::from_bytes(&[8_u8; 32]);
        let signed = signed_manifest("release_2026", &release, "1.5.0");
        let policy = policy("2.0.0");
        let trust = trust(&release, &rollback);
        assert_eq!(
            trust.verify_update(&signed, &policy, None),
            Err(ManifestError::DowngradeDenied)
        );

        let authorization = RollbackAuthorization {
            schema_version: ROLLBACK_AUTHORIZATION_SCHEMA_VERSION,
            authorization_id: Uuid::new_v4(),
            product: Product::Connect,
            platform: Platform::Macos,
            architecture: Architecture::Aarch64,
            from_version: Version::parse("2.0.0").unwrap(),
            to_version: Version::parse("1.5.0").unwrap(),
            artifact_sha256: signed.manifest.artifacts[0].sha256.clone(),
            reason_code: "emergency_regression".to_string(),
            issued_at: 1_800_000_000,
            expires_at: 1_800_000_200,
        };
        let transcript = rollback_signing_transcript("rollback_2026", &authorization).unwrap();
        let grant = SignedRollbackAuthorization {
            key_id: "rollback_2026".to_string(),
            authorization,
            signature: URL_SAFE_NO_PAD.encode(rollback.sign(&transcript).to_bytes()),
        };

        let verified = trust.verify_update(&signed, &policy, Some(&grant)).unwrap();
        assert!(verified.emergency_rollback);
    }

    #[test]
    fn rollback_grant_cannot_be_retargeted_or_replayed_after_expiry() {
        let release = SigningKey::from_bytes(&[7_u8; 32]);
        let rollback = SigningKey::from_bytes(&[8_u8; 32]);
        let signed = signed_manifest("release_2026", &release, "1.5.0");
        let mut authorization = RollbackAuthorization {
            schema_version: ROLLBACK_AUTHORIZATION_SCHEMA_VERSION,
            authorization_id: Uuid::new_v4(),
            product: Product::Connect,
            platform: Platform::Macos,
            architecture: Architecture::Aarch64,
            from_version: Version::parse("2.0.0").unwrap(),
            to_version: Version::parse("1.5.0").unwrap(),
            artifact_sha256: "c".repeat(64),
            reason_code: "emergency_regression".to_string(),
            issued_at: 1_800_000_000,
            expires_at: 1_800_000_050,
        };
        let transcript = rollback_signing_transcript("rollback_2026", &authorization).unwrap();
        let mut grant = SignedRollbackAuthorization {
            key_id: "rollback_2026".to_string(),
            authorization: authorization.clone(),
            signature: URL_SAFE_NO_PAD.encode(rollback.sign(&transcript).to_bytes()),
        };
        let trust = trust(&release, &rollback);
        assert_eq!(
            trust.verify_update(&signed, &policy("2.0.0"), Some(&grant)),
            Err(ManifestError::RollbackMismatch)
        );

        authorization.artifact_sha256 = signed.manifest.artifacts[0].sha256.clone();
        let transcript = rollback_signing_transcript("rollback_2026", &authorization).unwrap();
        grant.authorization = authorization;
        grant.signature = URL_SAFE_NO_PAD.encode(rollback.sign(&transcript).to_bytes());
        assert_eq!(
            trust.verify_update(&signed, &policy("2.0.0"), Some(&grant)),
            Err(ManifestError::RollbackExpired)
        );
    }

    #[test]
    fn artifact_inventory_is_strictly_sorted_and_unique() {
        let mut manifest = manifest("2.0.0");
        manifest.artifacts.push(manifest.artifacts[0].clone());
        assert_eq!(manifest.validate(), Err(ManifestError::ArtifactOrder));
    }

    #[test]
    fn future_manifest_and_credentialed_release_url_are_rejected() {
        let release = SigningKey::from_bytes(&[7_u8; 32]);
        let rollback = SigningKey::from_bytes(&[8_u8; 32]);
        let mut signed = signed_manifest("release_2026", &release, "2.0.0");
        signed.manifest.release_notes_url = Some("https://user@example.test/release".to_string());
        assert_eq!(
            signed.manifest.validate(),
            Err(ManifestError::InvalidManifest)
        );

        let mut signed = signed_manifest("release_2026", &release, "2.0.0");
        signed.manifest.issued_at = 1_900_000_000;
        let transcript = release_signing_transcript("release_2026", &signed.manifest).unwrap();
        signed.signature = URL_SAFE_NO_PAD.encode(release.sign(&transcript).to_bytes());
        assert_eq!(
            trust(&release, &rollback).verify_update(&signed, &policy("1.0.0"), None),
            Err(ManifestError::ManifestNotYetValid)
        );
    }
}
