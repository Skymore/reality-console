//! Verification, decryption, and crash-safe two-generation cache for profile bundles.

use crate::core::connection::ConnectionProfile;
use crate::error::ClientError;
use crate::session::SessionBinding;
use crate::vault::{CredentialVault, VaultScope};
use control_protocol::account::{
    AccountStatus, NodeProfile, ProfileBundlePayload, SignedProfileBundle,
};
use control_protocol::account_crypto::{
    decrypt_profile, encrypted_profile_digest, profile_bundle_signature_transcript,
    verify_profile_bundle_signature, EncryptedProfileCiphertext,
};
use control_protocol::crypto::{ed25519_signing_key_id, Ed25519PublicKey};
use control_protocol::id::{BundleGeneration, BundleId, ControllerInstanceId, NodeId, Timestamp};
use control_protocol::version::{PROFILE_BUNDLE_SCHEMA_VERSION, PROFILE_PAYLOAD_FORMAT_VERSION};
use semver::Version;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;
use std::fs;
#[cfg(unix)]
use std::fs::File;
use std::io::Write as _;
use std::path::{Path, PathBuf};

const CACHE_VERSION: u8 = 1;
const MAXIMUM_CACHED_BUNDLE_BYTES: u64 = 8 * 1024 * 1024;

/// Pinned trust and identity bindings for one enrolled device.
#[derive(Debug, Clone)]
pub struct BundleTrust {
    /// Safe enrolled device identity.
    pub binding: SessionBinding,
    /// Trusted controller epoch; restored controllers cannot replay an old epoch.
    pub controller_instance_id: ControllerInstanceId,
    /// Production-configured profile-bundle signing key.
    pub controller_signing_key: Ed25519PublicKey,
    /// Running Connect semantic version.
    pub client_version: Version,
}

/// Fully authenticated and decrypted bundle. Construction is restricted to [`BundleVerifier`].
pub struct VerifiedBundle {
    signed: SignedProfileBundle,
    profiles: BTreeMap<NodeId, ConnectionProfile>,
    artifact_digest: String,
    etag: Option<String>,
}

impl VerifiedBundle {
    /// Authenticated manifest safe for backend policy decisions.
    #[must_use]
    pub const fn signed(&self) -> &SignedProfileBundle {
        &self.signed
    }

    /// Secret-bearing normalized profiles; this map is never serialized to renderer state.
    #[must_use]
    pub const fn profiles(&self) -> &BTreeMap<NodeId, ConnectionProfile> {
        &self.profiles
    }

    /// Opaque HTTP validator associated with this verified artifact.
    #[must_use]
    pub fn etag(&self) -> Option<&str> {
        self.etag.as_deref()
    }
}

/// Complete bundle authenticator backed by a device key in [`CredentialVault`].
#[derive(Clone)]
pub struct BundleVerifier {
    trust: BundleTrust,
    vault: CredentialVault,
}

impl BundleVerifier {
    /// Creates a verifier for exactly one controller epoch and enrolled device.
    #[must_use]
    pub const fn new(trust: BundleTrust, vault: CredentialVault) -> Self {
        Self { trust, vault }
    }

    /// Verifies, decrypts, and normalizes an untrusted signed envelope.
    pub fn verify(
        &self,
        signed: SignedProfileBundle,
        etag: Option<String>,
        now: Timestamp,
    ) -> Result<VerifiedBundle, ClientError> {
        signed
            .validate_shape(
                &[PROFILE_BUNDLE_SCHEMA_VERSION],
                &[PROFILE_PAYLOAD_FORMAT_VERSION],
            )
            .map_err(|_| bundle_error("bundle_shape_invalid"))?;
        let manifest = &signed.manifest;
        let binding = self.trust.binding;
        if manifest.network_id != binding.network_id
            || manifest.user_id != binding.user_id
            || manifest.device_id != binding.device_id
            || manifest.controller_instance_id != self.trust.controller_instance_id
        {
            return Err(bundle_error("bundle_binding_mismatch"));
        }
        let expected_key_id = ed25519_signing_key_id(&self.trust.controller_signing_key)
            .map_err(|_| bundle_error("bundle_signing_key_invalid"))?;
        if manifest.signing_key_id != expected_key_id {
            return Err(bundle_error("bundle_signing_key_mismatch"));
        }
        if manifest.account_status != AccountStatus::Active {
            return Err(bundle_error("bundle_account_disabled"));
        }
        let now = now.as_datetime();
        if manifest.issued_at.as_datetime() > now
            || manifest.not_before.as_datetime() > now
            || manifest.offline_expires_at.as_datetime() <= now
        {
            return Err(bundle_error("bundle_time_invalid"));
        }
        let minimum_client = Version::parse(&manifest.min_client_version)
            .map_err(|_| bundle_error("bundle_client_version_invalid"))?;
        if self.trust.client_version < minimum_client {
            return Err(bundle_error("bundle_client_upgrade_required"));
        }
        let transcript = profile_bundle_signature_transcript(manifest, &signed.encrypted_profiles)
            .map_err(|_| bundle_error("bundle_signature_transcript_invalid"))?;
        verify_profile_bundle_signature(
            &self.trust.controller_signing_key,
            &signed.signature,
            &transcript,
        )
        .map_err(|_| bundle_error("bundle_signature_invalid"))?;

        for descriptor in &manifest.profiles {
            let encrypted = signed
                .encrypted_profiles
                .iter()
                .find(|payload| payload.node_id == descriptor.node_id)
                .ok_or_else(|| bundle_error("bundle_payload_missing"))?;
            let digest = encrypted_profile_digest(encrypted)
                .map_err(|_| bundle_error("bundle_payload_digest_invalid"))?;
            if digest != descriptor.encrypted_payload_digest {
                return Err(bundle_error("bundle_payload_digest_mismatch"));
            }
        }

        let scope = VaultScope::from(binding);
        let nodes = self
            .vault
            .with_encryption_private_key(scope, |private_key| {
                decrypt_profiles(private_key, &signed)
            })?;
        let payload = ProfileBundlePayload {
            bundle_id: manifest.bundle_id,
            device_id: manifest.device_id,
            generation: manifest.generation,
            profiles: nodes,
        };
        payload
            .validate_against(manifest)
            .map_err(|_| bundle_error("bundle_decrypted_payload_invalid"))?;
        let profiles = payload
            .profiles
            .iter()
            .map(|profile| {
                ConnectionProfile::try_from(profile).map(|normalized| (profile.node_id, normalized))
            })
            .collect::<Result<BTreeMap<_, _>, _>>()?;
        let artifact =
            serde_json::to_vec(&signed).map_err(|_| bundle_error("bundle_serialize_failed"))?;
        let artifact_digest = hex_digest(&artifact);
        Ok(VerifiedBundle {
            signed,
            profiles,
            artifact_digest,
            etag,
        })
    }
}

fn decrypt_profiles(
    private_key: &[u8; 32],
    signed: &SignedProfileBundle,
) -> Result<Vec<NodeProfile>, ClientError> {
    signed
        .encrypted_profiles
        .iter()
        .map(|encrypted| {
            let aad = profile_encryption_aad(
                signed.manifest.network_id,
                signed.manifest.user_id,
                signed.manifest.device_id,
                signed.manifest.bundle_id,
                signed.manifest.generation,
                encrypted.node_id,
            );
            let ciphertext = EncryptedProfileCiphertext {
                algorithm: encrypted.algorithm,
                ephemeral_public_key: encrypted.ephemeral_public_key.clone(),
                nonce: encrypted.nonce.clone(),
                ciphertext: encrypted.ciphertext.clone(),
            };
            let plaintext = decrypt_profile(private_key, &ciphertext, &aad)
                .map_err(|_| bundle_error("bundle_payload_decryption_failed"))?;
            serde_json::from_slice::<NodeProfile>(&plaintext)
                .map_err(|_| bundle_error("bundle_payload_json_invalid"))
        })
        .collect()
}

fn profile_encryption_aad(
    network_id: control_protocol::id::NetworkId,
    user_id: control_protocol::id::UserId,
    device_id: control_protocol::id::DeviceId,
    bundle_id: BundleId,
    generation: BundleGeneration,
    node_id: NodeId,
) -> Vec<u8> {
    format!(
        "control/profile-aad/v1\0{network_id}\0{user_id}\0{device_id}\0{bundle_id}\0{}\0{node_id}",
        generation.get()
    )
    .into_bytes()
}

/// Owner-only cache retaining active and one previous complete signed generation.
#[derive(Clone)]
pub struct BundleCache {
    directory: PathBuf,
    pointer_path: PathBuf,
}

impl BundleCache {
    /// Opens the device-scoped cache directory and enforces owner-only permissions.
    pub fn new(app_data_dir: PathBuf, binding: SessionBinding) -> Result<Self, ClientError> {
        let directory = app_data_dir
            .join("account-bundles-v1")
            .join(binding.network_id.to_string())
            .join(binding.user_id.to_string())
            .join(binding.device_id.to_string());
        fs::create_dir_all(&directory).map_err(|_| cache_error("bundle_cache_create_failed"))?;
        set_owner_directory(&directory)?;
        Ok(Self {
            pointer_path: directory.join("active.json"),
            directory,
        })
    }

    /// Atomically installs a fully verified newer generation and then prunes to two.
    pub fn install(&self, bundle: &VerifiedBundle) -> Result<(), ClientError> {
        let bytes = serde_json::to_vec(&bundle.signed)
            .map_err(|_| cache_error("bundle_cache_serialize_failed"))?;
        if bytes.len() as u64 > MAXIMUM_CACHED_BUNDLE_BYTES {
            return Err(cache_error("bundle_cache_artifact_too_large"));
        }
        let file_name = bundle_file_name(
            bundle.signed.manifest.generation,
            bundle.signed.manifest.bundle_id,
        );
        let pointer = ActivePointer {
            version: CACHE_VERSION,
            generation: bundle.signed.manifest.generation,
            bundle_id: bundle.signed.manifest.bundle_id,
            file: file_name.clone(),
            artifact_digest: bundle.artifact_digest.clone(),
            etag: bundle.etag.clone(),
        };
        if let Some(current) = self.read_pointer()? {
            if pointer.generation < current.generation {
                return Err(cache_error("bundle_cache_generation_rollback"));
            }
            if pointer.generation == current.generation {
                if pointer.bundle_id == current.bundle_id
                    && pointer.artifact_digest == current.artifact_digest
                {
                    return Ok(());
                }
                return Err(cache_error("bundle_cache_generation_conflict"));
            }
        }

        atomic_write(&self.directory.join(&file_name), &bytes)?;
        let pointer_bytes = serde_json::to_vec(&pointer)
            .map_err(|_| cache_error("bundle_cache_serialize_failed"))?;
        atomic_write(&self.pointer_path, &pointer_bytes)?;
        self.prune(&file_name)
    }

    /// Loads the active verified generation, falling back to and repointing the previous one.
    pub fn recover(
        &self,
        verifier: &BundleVerifier,
        now: Timestamp,
    ) -> Result<Option<VerifiedBundle>, ClientError> {
        let pointer = self.read_pointer().ok().flatten();
        let mut candidates = self.bundle_files()?;
        if let Some(active) = &pointer {
            candidates.sort_by_key(|path| {
                if path.file_name().and_then(|name| name.to_str()) == Some(active.file.as_str()) {
                    0
                } else {
                    1
                }
            });
        }
        for path in candidates {
            let Ok(bytes) = read_bounded_file(&path) else {
                continue;
            };
            let file_name = path.file_name().and_then(|value| value.to_str());
            let active = pointer
                .as_ref()
                .filter(|pointer| Some(pointer.file.as_str()) == file_name);
            if active.is_some_and(|pointer| pointer.artifact_digest != hex_digest(&bytes)) {
                continue;
            }
            let Ok(signed) = serde_json::from_slice::<SignedProfileBundle>(&bytes) else {
                continue;
            };
            let etag = active.and_then(|pointer| pointer.etag.clone());
            let Ok(verified) = verifier.verify(signed, etag, now) else {
                continue;
            };
            if active.is_none() {
                self.repoint(&verified, file_name.unwrap_or_default())?;
            }
            self.remove_newer_than(verified.signed.manifest.generation)?;
            self.prune(file_name.unwrap_or_default())?;
            return Ok(Some(verified));
        }
        Ok(None)
    }

    fn repoint(&self, bundle: &VerifiedBundle, file_name: &str) -> Result<(), ClientError> {
        let pointer = ActivePointer {
            version: CACHE_VERSION,
            generation: bundle.signed.manifest.generation,
            bundle_id: bundle.signed.manifest.bundle_id,
            file: file_name.to_string(),
            artifact_digest: bundle.artifact_digest.clone(),
            etag: bundle.etag.clone(),
        };
        let bytes = serde_json::to_vec(&pointer)
            .map_err(|_| cache_error("bundle_cache_serialize_failed"))?;
        atomic_write(&self.pointer_path, &bytes)
    }

    fn read_pointer(&self) -> Result<Option<ActivePointer>, ClientError> {
        if !self.pointer_path.exists() {
            return Ok(None);
        }
        enforce_owner_file(&self.pointer_path)?;
        let bytes = read_bounded_file(&self.pointer_path)?;
        let pointer: ActivePointer = serde_json::from_slice(&bytes)
            .map_err(|_| cache_error("bundle_cache_pointer_invalid"))?;
        if pointer.version != CACHE_VERSION
            || pointer.file != bundle_file_name(pointer.generation, pointer.bundle_id)
        {
            return Err(cache_error("bundle_cache_pointer_invalid"));
        }
        Ok(Some(pointer))
    }

    fn bundle_files(&self) -> Result<Vec<PathBuf>, ClientError> {
        let mut files = fs::read_dir(&self.directory)
            .map_err(|_| cache_error("bundle_cache_read_failed"))?
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with("bundle-") && name.ends_with(".json"))
            })
            .collect::<Vec<_>>();
        files.sort_by(|left, right| right.file_name().cmp(&left.file_name()));
        Ok(files)
    }

    fn prune(&self, active_file: &str) -> Result<(), ClientError> {
        let mut files = self.bundle_files()?;
        files.sort_by_key(|path| {
            std::cmp::Reverse(bundle_generation_from_path(path).unwrap_or_default())
        });
        let mut previous_retained = 0_usize;
        for path in files {
            let is_active = path.file_name().and_then(|name| name.to_str()) == Some(active_file);
            if is_active || previous_retained < 1 {
                previous_retained += usize::from(!is_active);
                continue;
            }
            fs::remove_file(path).map_err(|_| cache_error("bundle_cache_prune_failed"))?;
        }
        sync_directory(&self.directory)
    }

    fn remove_newer_than(&self, active_generation: BundleGeneration) -> Result<(), ClientError> {
        for path in self.bundle_files()? {
            if bundle_generation_from_path(&path)
                .is_some_and(|generation| generation > active_generation.get())
            {
                fs::remove_file(path).map_err(|_| cache_error("bundle_cache_prune_failed"))?;
            }
        }
        Ok(())
    }

    /// Removes all cached encrypted artifacts after explicit account removal.
    pub fn purge(&self) -> Result<(), ClientError> {
        if self.directory.exists() {
            fs::remove_dir_all(&self.directory)
                .map_err(|_| cache_error("bundle_cache_purge_failed"))?;
            if let Some(parent) = self.directory.parent() {
                sync_directory(parent)?;
            }
        }
        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ActivePointer {
    version: u8,
    generation: BundleGeneration,
    bundle_id: BundleId,
    file: String,
    artifact_digest: String,
    etag: Option<String>,
}

fn bundle_file_name(generation: BundleGeneration, bundle_id: BundleId) -> String {
    format!("bundle-{:020}-{bundle_id}.json", generation.get())
}

fn bundle_generation_from_path(path: &Path) -> Option<i64> {
    path.file_name()?
        .to_str()?
        .strip_prefix("bundle-")?
        .split('-')
        .next()?
        .parse()
        .ok()
}

fn read_bounded_file(path: &Path) -> Result<Vec<u8>, ClientError> {
    enforce_owner_file(path)?;
    let metadata = fs::metadata(path).map_err(|_| cache_error("bundle_cache_read_failed"))?;
    if metadata.len() > MAXIMUM_CACHED_BUNDLE_BYTES {
        return Err(cache_error("bundle_cache_artifact_too_large"));
    }
    fs::read(path).map_err(|_| cache_error("bundle_cache_read_failed"))
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), ClientError> {
    let parent = path
        .parent()
        .ok_or_else(|| cache_error("bundle_cache_directory_invalid"))?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)
        .map_err(|_| cache_error("bundle_cache_write_failed"))?;
    temporary
        .write_all(bytes)
        .and_then(|()| temporary.as_file().sync_all())
        .map_err(|_| cache_error("bundle_cache_write_failed"))?;
    set_owner_file(temporary.path())?;
    temporary
        .persist(path)
        .map_err(|_| cache_error("bundle_cache_write_failed"))?;
    sync_directory(parent)
}

fn hex_digest(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(71);
    encoded.push_str("sha256:");
    for byte in digest {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

#[cfg(unix)]
fn set_owner_directory(path: &Path) -> Result<(), ClientError> {
    use std::os::unix::fs::PermissionsExt as _;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|_| cache_error("bundle_cache_permissions_failed"))
}

#[cfg(not(unix))]
fn set_owner_directory(_path: &Path) -> Result<(), ClientError> {
    Ok(())
}

#[cfg(unix)]
fn set_owner_file(path: &Path) -> Result<(), ClientError> {
    use std::os::unix::fs::PermissionsExt as _;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .map_err(|_| cache_error("bundle_cache_permissions_failed"))
}

#[cfg(not(unix))]
fn set_owner_file(_path: &Path) -> Result<(), ClientError> {
    Ok(())
}

#[cfg(unix)]
fn enforce_owner_file(path: &Path) -> Result<(), ClientError> {
    use std::os::unix::fs::PermissionsExt as _;
    let mode = fs::metadata(path)
        .map_err(|_| cache_error("bundle_cache_read_failed"))?
        .permissions()
        .mode();
    if mode & 0o077 != 0 {
        return Err(cache_error("bundle_cache_permissions_invalid"));
    }
    Ok(())
}

#[cfg(not(unix))]
fn enforce_owner_file(_path: &Path) -> Result<(), ClientError> {
    Ok(())
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<(), ClientError> {
    File::open(path)
        .and_then(|file| file.sync_all())
        .map_err(|_| cache_error("bundle_cache_sync_failed"))
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> Result<(), ClientError> {
    Ok(())
}

fn bundle_error(code: &str) -> ClientError {
    ClientError::internal(code, "The signed profile bundle was rejected.")
}

fn cache_error(code: &str) -> ClientError {
    ClientError::internal(code, "The local profile bundle cache operation failed.")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::VaultBackend;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use control_protocol::account::{
        EncryptedProfilePayload, ProfileBundleManifest, ProfileDescriptor,
        ProfileEncryptionAlgorithm, ProfileEndpoint, RealityConnectionParameters, SelectionHints,
    };
    use control_protocol::account_crypto::{encrypt_profile, encrypted_profile_digest};
    use control_protocol::crypto::{ed25519_signing_key_id, Ed25519Signature, X25519PublicKey};
    use control_protocol::id::{CredentialId, NetworkId, UserId};
    use control_protocol::node::EndpointMode;
    use control_protocol::secret::Secret;
    use ed25519_dalek::{Signer as _, SigningKey};
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};
    use tempfile::tempdir;
    use x25519_dalek::{PublicKey as X25519Public, StaticSecret};

    #[derive(Default)]
    struct MemoryBackend(Mutex<HashMap<String, String>>);

    impl VaultBackend for MemoryBackend {
        fn set(&self, key: &str, value: &str) -> Result<(), ClientError> {
            self.0.lock().unwrap().insert(key.into(), value.into());
            Ok(())
        }
        fn get(&self, key: &str) -> Result<Option<String>, ClientError> {
            Ok(self.0.lock().unwrap().get(key).cloned())
        }
        fn delete(&self, key: &str) -> Result<(), ClientError> {
            self.0.lock().unwrap().remove(key);
            Ok(())
        }
    }

    struct Fixture {
        binding: SessionBinding,
        controller_instance_id: ControllerInstanceId,
        controller: SigningKey,
        vault: CredentialVault,
    }

    impl Fixture {
        fn new() -> Self {
            let binding = SessionBinding {
                network_id: NetworkId::new(),
                user_id: UserId::new(),
                device_id: control_protocol::id::DeviceId::new(),
            };
            let vault = CredentialVault::new(Arc::new(MemoryBackend::default()));
            vault
                .store_device_keys(binding.into(), &[3_u8; 32], &[7_u8; 32])
                .unwrap();
            Self {
                binding,
                controller_instance_id: ControllerInstanceId::new(),
                controller: SigningKey::from_bytes(&[9_u8; 32]),
                vault,
            }
        }

        fn verifier(&self) -> BundleVerifier {
            let key: Ed25519PublicKey = URL_SAFE_NO_PAD
                .encode(self.controller.verifying_key().to_bytes())
                .parse()
                .unwrap();
            BundleVerifier::new(
                BundleTrust {
                    binding: self.binding,
                    controller_instance_id: self.controller_instance_id,
                    controller_signing_key: key,
                    client_version: Version::parse("0.1.0").unwrap(),
                },
                self.vault.clone(),
            )
        }

        fn signed(&self, generation: i64) -> SignedProfileBundle {
            let bundle_id = BundleId::new();
            let node_id = NodeId::new();
            let profile = NodeProfile {
                node_id,
                credential_id: CredentialId::new(),
                display_name: "Node".to_string(),
                region: Some("US".to_string()),
                endpoint: ProfileEndpoint {
                    mode: EndpointMode::Direct,
                    address: "node.example".to_string(),
                    port: 443,
                },
                connection: RealityConnectionParameters {
                    vless_uuid: Secret::new("11111111-1111-4111-8111-111111111111".to_string()),
                    flow: "xtls-rprx-vision".to_string(),
                    server_name: "www.example.com".to_string(),
                    fingerprint: "chrome".to_string(),
                    reality_public_key: Secret::new(
                        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
                    ),
                    short_id: Secret::new("aabb".to_string()),
                    spider_x: Secret::new("/".to_string()),
                },
            };
            let generation = BundleGeneration::new(generation).unwrap();
            let aad = profile_encryption_aad(
                self.binding.network_id,
                self.binding.user_id,
                self.binding.device_id,
                bundle_id,
                generation,
                node_id,
            );
            let recipient = X25519Public::from(&StaticSecret::from([7_u8; 32]));
            let recipient: X25519PublicKey = URL_SAFE_NO_PAD
                .encode(recipient.to_bytes())
                .parse()
                .unwrap();
            let ciphertext =
                encrypt_profile(&recipient, &serde_json::to_vec(&profile).unwrap(), &aad).unwrap();
            let encrypted = EncryptedProfilePayload {
                node_id,
                algorithm: ProfileEncryptionAlgorithm::HpkeBaseX25519HkdfSha256ChaCha20Poly1305,
                ephemeral_public_key: ciphertext.ephemeral_public_key,
                nonce: ciphertext.nonce,
                ciphertext: ciphertext.ciphertext,
            };
            let signing_key: Ed25519PublicKey = URL_SAFE_NO_PAD
                .encode(self.controller.verifying_key().to_bytes())
                .parse()
                .unwrap();
            let manifest = ProfileBundleManifest {
                schema_version: PROFILE_BUNDLE_SCHEMA_VERSION,
                format_version: PROFILE_PAYLOAD_FORMAT_VERSION,
                bundle_id,
                network_id: self.binding.network_id,
                user_id: self.binding.user_id,
                device_id: self.binding.device_id,
                signing_key_id: ed25519_signing_key_id(&signing_key).unwrap(),
                controller_instance_id: self.controller_instance_id,
                generation,
                issued_at: "2029-01-01T00:00:00Z".parse().unwrap(),
                not_before: "2029-01-01T00:00:00Z".parse().unwrap(),
                refresh_after: "2029-01-02T00:00:00Z".parse().unwrap(),
                offline_expires_at: "2029-02-01T00:00:00Z".parse().unwrap(),
                min_client_version: "0.1.0".to_string(),
                account_status: AccountStatus::Active,
                profiles: vec![ProfileDescriptor {
                    node_id,
                    display_name: "Node".to_string(),
                    region: Some("US".to_string()),
                    endpoint_mode: EndpointMode::Direct,
                    encrypted_payload_digest: encrypted_profile_digest(&encrypted).unwrap(),
                    priority: 0,
                }],
                selection_hints: SelectionHints {
                    minimum_hold_seconds: 60,
                    latency_tolerance_milliseconds: 20,
                    failure_threshold: 3,
                },
                replacement: None,
            };
            let transcript =
                profile_bundle_signature_transcript(&manifest, std::slice::from_ref(&encrypted))
                    .unwrap();
            let signature: Ed25519Signature = URL_SAFE_NO_PAD
                .encode(self.controller.sign(&transcript).to_bytes())
                .parse()
                .unwrap();
            SignedProfileBundle {
                manifest,
                encrypted_profiles: vec![encrypted],
                signature,
            }
        }
    }

    fn now() -> Timestamp {
        "2029-01-03T00:00:00Z".parse().unwrap()
    }

    #[test]
    fn verifies_signature_digest_binding_and_hpke_before_normalizing() {
        let fixture = Fixture::new();
        let signed = fixture.signed(1);
        let node_id = signed.manifest.profiles[0].node_id;
        let verified = fixture.verifier().verify(signed, None, now()).unwrap();
        assert_eq!(verified.profiles().len(), 1);
        assert!(verified.profiles().contains_key(&node_id));
    }

    #[test]
    fn rejects_tampering_and_wrong_device() {
        let fixture = Fixture::new();
        let mut tampered = fixture.signed(1);
        tampered.encrypted_profiles[0].ciphertext = Secret::new("AAAA".to_string());
        assert!(fixture.verifier().verify(tampered, None, now()).is_err());

        let mut wrong_device = fixture.signed(2);
        wrong_device.manifest.device_id = control_protocol::id::DeviceId::new();
        assert!(fixture
            .verifier()
            .verify(wrong_device, None, now())
            .is_err());
    }

    #[test]
    fn cache_rejects_rollback_and_recovers_previous_after_active_corruption() {
        let fixture = Fixture::new();
        let verifier = fixture.verifier();
        let directory = tempdir().unwrap();
        let cache = BundleCache::new(directory.path().to_path_buf(), fixture.binding).unwrap();
        let first = verifier
            .verify(fixture.signed(1), Some("one".into()), now())
            .unwrap();
        let second = verifier
            .verify(fixture.signed(2), Some("two".into()), now())
            .unwrap();
        cache.install(&first).unwrap();
        cache.install(&second).unwrap();
        assert!(cache.install(&first).is_err());

        let active = cache.read_pointer().unwrap().unwrap();
        fs::write(cache.directory.join(active.file), b"corrupt").unwrap();
        set_owner_file(&cache.directory.join(bundle_file_name(
            second.signed.manifest.generation,
            second.signed.manifest.bundle_id,
        )))
        .unwrap();
        let recovered = cache.recover(&verifier, now()).unwrap().unwrap();
        assert_eq!(recovered.signed.manifest.generation.get(), 1);
        assert_eq!(cache.bundle_files().unwrap().len(), 1);
        assert_eq!(cache.read_pointer().unwrap().unwrap().generation.get(), 1);
    }

    #[test]
    fn interrupted_orphan_does_not_replace_valid_active_pointer() {
        let fixture = Fixture::new();
        let verifier = fixture.verifier();
        let directory = tempdir().unwrap();
        let cache = BundleCache::new(directory.path().to_path_buf(), fixture.binding).unwrap();
        let first = verifier.verify(fixture.signed(1), None, now()).unwrap();
        cache.install(&first).unwrap();
        let orphan = fixture.signed(2);
        let orphan_path = cache.directory.join(bundle_file_name(
            orphan.manifest.generation,
            orphan.manifest.bundle_id,
        ));
        fs::write(&orphan_path, serde_json::to_vec(&orphan).unwrap()).unwrap();
        set_owner_file(&orphan_path).unwrap();

        let recovered = cache.recover(&verifier, now()).unwrap().unwrap();
        assert_eq!(recovered.signed.manifest.generation.get(), 1);
    }
}
