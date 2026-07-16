//! Versioned, device-scoped storage for secrets that must never reach renderer state.

use crate::error::ClientError;
#[cfg(not(target_os = "windows"))]
use crate::local_store::OwnerOnlySecretFile;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use control_protocol::crypto::{Ed25519PublicKey, Ed25519Signature, Nonce, X25519PublicKey};
use control_protocol::id::{
    ControllerInstanceId, DeviceActivationId, DeviceId, NetworkId, Timestamp, UserId,
};
use control_protocol::secret::Secret;
use ed25519_dalek::{Signer as _, SigningKey};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
#[cfg(not(target_os = "windows"))]
use std::path::Path;
use std::sync::{Arc, Mutex};
use uuid::Uuid;
use x25519_dalek::{PublicKey as X25519Public, StaticSecret};
use zeroize::Zeroizing;

const VAULT_VERSION: u8 = 1;
#[cfg(target_os = "windows")]
const KEYRING_SERVICE: &str = "com.sky.realityclient.credentials.v1";
const DEVICE_KEY_SLOT: u8 = 0;
const REFRESH_SLOTS: [u8; 2] = [0, 1];
const INSTALLED_ACCOUNT_VERSION: u8 = 1;
const INSTALLED_ACCOUNT_KEY: &str = "v1:installed-account:singleton";

/// Private device material retained under an activation-scoped key until enrollment commits.
pub(crate) struct PendingDeviceKeys {
    pub(crate) identity: Zeroizing<[u8; 32]>,
    pub(crate) encryption: Zeroizing<[u8; 32]>,
    pub(crate) nonce: Nonce,
}

/// Crash-recoverable material for one exact password-login operation.
pub(crate) struct PendingLoginOperation {
    pub(crate) keys: PendingDeviceKeys,
    pub(crate) idempotency_key: String,
}

/// Complete credential namespace for one enrolled member device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VaultScope {
    /// Bound private network.
    pub network_id: NetworkId,
    /// Bound logical account.
    pub user_id: UserId,
    /// Exact recipient device.
    pub device_id: DeviceId,
}

/// Discoverable account binding and controller trust retained in the selected credential store.
///
/// This record contains no bearer, private key, or encrypted bundle payload.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InstalledAccountRecord {
    version: u8,
    /// Canonical HTTPS or loopback HTTP Control origin.
    pub controller_origin: String,
    /// Installed private network.
    pub network_id: NetworkId,
    /// Installed member account.
    pub user_id: UserId,
    /// Installed independently revocable device.
    pub device_id: DeviceId,
    /// Controller instance pinned by setup.
    pub controller_instance_id: ControllerInstanceId,
    /// Public key pinned for profile-bundle verification.
    pub bundle_signing_public_key: Ed25519PublicKey,
}

impl InstalledAccountRecord {
    /// Builds the current installed-account record schema.
    #[must_use]
    pub fn new(
        controller_origin: String,
        scope: VaultScope,
        controller_instance_id: ControllerInstanceId,
        bundle_signing_public_key: Ed25519PublicKey,
    ) -> Self {
        Self {
            version: INSTALLED_ACCOUNT_VERSION,
            controller_origin,
            network_id: scope.network_id,
            user_id: scope.user_id,
            device_id: scope.device_id,
            controller_instance_id,
            bundle_signing_public_key,
        }
    }

    /// Returns the exact device-scoped vault namespace.
    #[must_use]
    pub const fn scope(&self) -> VaultScope {
        VaultScope {
            network_id: self.network_id,
            user_id: self.user_id,
            device_id: self.device_id,
        }
    }
}

impl std::fmt::Debug for InstalledAccountRecord {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("InstalledAccountRecord")
            .field("version", &self.version)
            .field("controller_origin", &self.controller_origin)
            .field("network_id", &"[redacted]")
            .field("user_id", &"[redacted]")
            .field("device_id", &"[redacted]")
            .field("controller_instance_id", &"[redacted]")
            .field("bundle_signing_public_key", &"[redacted]")
            .finish()
    }
}

/// Public half of locally generated device identity keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DevicePublicKeys {
    /// Ed25519 request-signing identity.
    pub identity: Ed25519PublicKey,
    /// X25519 profile-bundle recipient identity.
    pub encryption: X25519PublicKey,
}

/// Persisted refresh value and monotonic local rotation.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RefreshRecord {
    /// Rotating bearer value.
    pub credential: Secret<String>,
    /// Controller hard expiry.
    pub expires_at: Timestamp,
    /// Local crash-recovery ordering across the two credential slots.
    pub rotation: u64,
    /// Request key persisted before sending this rotation to Control.
    #[serde(default)]
    pub(crate) pending_idempotency_key: Option<String>,
}

impl std::fmt::Debug for RefreshRecord {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RefreshRecord")
            .field("credential", &"[redacted]")
            .field("expires_at", &self.expires_at)
            .field("rotation", &self.rotation)
            .field(
                "has_pending_operation",
                &self.pending_idempotency_key.is_some(),
            )
            .finish()
    }
}

/// Loaded refresh record together with its physical credential slot.
#[derive(Debug, Clone)]
pub struct StoredRefresh {
    /// Credential slot containing `record`.
    pub slot: u8,
    /// Validated stored value.
    pub record: RefreshRecord,
}

/// Minimal credential backend used by the vault.
pub trait VaultBackend: Send + Sync {
    /// Writes one opaque value.
    fn set(&self, account: &str, value: &str) -> Result<(), ClientError>;
    /// Reads one opaque value.
    fn get(&self, account: &str) -> Result<Option<String>, ClientError>;
    /// Deletes one opaque value if present.
    fn delete(&self, account: &str) -> Result<(), ClientError>;
}

/// Windows Credential Manager implementation through `keyring`.
#[cfg(target_os = "windows")]
pub struct NativeVaultBackend;

#[cfg(target_os = "windows")]
impl NativeVaultBackend {
    fn entry(account: &str) -> Result<keyring::Entry, ClientError> {
        keyring::Entry::new(KEYRING_SERVICE, account).map_err(|_| vault_error("vault_unavailable"))
    }
}

#[cfg(not(target_os = "windows"))]
struct LocalVaultBackend {
    store: OwnerOnlySecretFile,
}

#[cfg(not(target_os = "windows"))]
impl LocalVaultBackend {
    fn new(app_data_dir: &Path) -> Result<Self, ClientError> {
        Ok(Self {
            store: OwnerOnlySecretFile::new(app_data_dir, "credentials-v1.json")?,
        })
    }
}

#[cfg(not(target_os = "windows"))]
impl VaultBackend for LocalVaultBackend {
    fn set(&self, account: &str, value: &str) -> Result<(), ClientError> {
        self.store.set(account, value)
    }

    fn get(&self, account: &str) -> Result<Option<String>, ClientError> {
        self.store.get(account)
    }

    fn delete(&self, account: &str) -> Result<(), ClientError> {
        self.store.delete(account)
    }
}

#[cfg(target_os = "windows")]
impl VaultBackend for NativeVaultBackend {
    fn set(&self, account: &str, value: &str) -> Result<(), ClientError> {
        Self::entry(account)?
            .set_password(value)
            .map_err(|_| vault_error("vault_write_failed"))
    }

    fn get(&self, account: &str) -> Result<Option<String>, ClientError> {
        match Self::entry(account)?.get_password() {
            Ok(value) => Ok(Some(value)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(_) => Err(vault_error("vault_read_failed")),
        }
    }

    fn delete(&self, account: &str) -> Result<(), ClientError> {
        match Self::entry(account)?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(_) => Err(vault_error("vault_delete_failed")),
        }
    }
}

/// Versioned credential vault with per-device serialization.
#[derive(Clone)]
pub struct CredentialVault {
    backend: Arc<dyn VaultBackend>,
    gate: Arc<Mutex<()>>,
}

impl CredentialVault {
    /// Uses application-managed owner-only storage on macOS/Linux and Windows Credential Manager
    /// on Windows. The local backend never reads legacy macOS Keychain entries.
    pub fn preferred(app_data_dir: &Path) -> Result<Self, ClientError> {
        #[cfg(not(target_os = "windows"))]
        {
            let backend = Arc::new(LocalVaultBackend::new(app_data_dir)?);
            Ok(Self::new(backend))
        }
        #[cfg(target_os = "windows")]
        {
            let _ = app_data_dir;
            Ok(Self::native())
        }
    }

    /// Creates a vault backed by Windows Credential Manager.
    #[cfg(target_os = "windows")]
    #[must_use]
    pub fn native() -> Self {
        Self::new(Arc::new(NativeVaultBackend))
    }

    /// Creates a vault with an injectable backend.
    #[must_use]
    pub fn new(backend: Arc<dyn VaultBackend>) -> Self {
        Self {
            backend,
            gate: Arc::new(Mutex::new(())),
        }
    }

    /// Loads the single discoverable installed account, if present.
    pub fn load_installed_account(&self) -> Result<Option<InstalledAccountRecord>, ClientError> {
        let _guard = self.gate.lock().map_err(|_| vault_error("vault_busy"))?;
        let Some(encoded) = self.backend.get(INSTALLED_ACCOUNT_KEY)? else {
            return Ok(None);
        };
        let record: InstalledAccountRecord = serde_json::from_str(&encoded)
            .map_err(|_| vault_error("vault_installed_account_invalid"))?;
        validate_installed_account(&record)?;
        Ok(Some(record))
    }

    /// Stores one account record idempotently and rejects replacement by a different binding.
    pub fn store_installed_account(
        &self,
        record: &InstalledAccountRecord,
    ) -> Result<(), ClientError> {
        validate_installed_account(record)?;
        let _guard = self.gate.lock().map_err(|_| vault_error("vault_busy"))?;
        if let Some(encoded) = self.backend.get(INSTALLED_ACCOUNT_KEY)? {
            let existing: InstalledAccountRecord = serde_json::from_str(&encoded)
                .map_err(|_| vault_error("vault_installed_account_invalid"))?;
            if &existing == record {
                return Ok(());
            }
            return Err(vault_error("vault_installed_account_conflict"));
        }
        let encoded = serde_json::to_string(record)
            .map_err(|_| vault_error("vault_installed_account_serialize_failed"))?;
        self.backend.set(INSTALLED_ACCOUNT_KEY, &encoded)
    }

    /// Deletes the installed marker only if it still identifies the expected account.
    pub fn delete_installed_account_if(
        &self,
        expected: &InstalledAccountRecord,
    ) -> Result<bool, ClientError> {
        let _guard = self.gate.lock().map_err(|_| vault_error("vault_busy"))?;
        let Some(encoded) = self.backend.get(INSTALLED_ACCOUNT_KEY)? else {
            return Ok(false);
        };
        let current: InstalledAccountRecord = serde_json::from_str(&encoded)
            .map_err(|_| vault_error("vault_installed_account_invalid"))?;
        if &current != expected {
            return Ok(false);
        }
        self.backend.delete(INSTALLED_ACCOUNT_KEY)?;
        Ok(true)
    }

    /// Loads or creates crash-recoverable keys for one activation attempt.
    pub(crate) fn load_or_create_activation_keys(
        &self,
        activation_id: DeviceActivationId,
    ) -> Result<PendingDeviceKeys, ClientError> {
        let _guard = self.gate.lock().map_err(|_| vault_error("vault_busy"))?;
        let identity_account = pending_activation_account(activation_id, Purpose::Ed25519Private);
        let encryption_account = pending_activation_account(activation_id, Purpose::X25519Private);
        let nonce_account = pending_activation_account(activation_id, Purpose::OperationNonce);
        let identity = self.backend.get(&identity_account)?;
        let encryption = self.backend.get(&encryption_account)?;
        let nonce = self.backend.get(&nonce_account)?;
        match (identity, encryption, nonce) {
            (Some(identity), Some(encryption), Some(nonce)) => Ok(PendingDeviceKeys {
                identity: Zeroizing::new(decode_private_key(&identity)?),
                encryption: Zeroizing::new(decode_private_key(&encryption)?),
                nonce: nonce
                    .parse()
                    .map_err(|_| vault_error("vault_operation_nonce_invalid"))?,
            }),
            (identity, encryption, nonce) => {
                if identity.is_some() || encryption.is_some() || nonce.is_some() {
                    self.backend.delete(&identity_account)?;
                    self.backend.delete(&encryption_account)?;
                    self.backend.delete(&nonce_account)?;
                }
                let identity = Zeroizing::new(SigningKey::generate(&mut OsRng).to_bytes());
                let encryption = Zeroizing::new(StaticSecret::random_from_rng(OsRng).to_bytes());
                let nonce = new_nonce()?;
                self.backend
                    .set(&identity_account, &URL_SAFE_NO_PAD.encode(*identity))?;
                if let Err(error) = self
                    .backend
                    .set(&encryption_account, &URL_SAFE_NO_PAD.encode(*encryption))
                {
                    let _ = self.backend.delete(&identity_account);
                    return Err(error);
                }
                if let Err(error) = self.backend.set(&nonce_account, nonce.as_str()) {
                    let _ = self.backend.delete(&identity_account);
                    let _ = self.backend.delete(&encryption_account);
                    return Err(error);
                }
                Ok(PendingDeviceKeys {
                    identity,
                    encryption,
                    nonce,
                })
            }
        }
    }

    /// Removes activation-scoped keys after device keys and refresh state are durable.
    pub(crate) fn delete_activation_keys(
        &self,
        activation_id: DeviceActivationId,
    ) -> Result<(), ClientError> {
        let _guard = self.gate.lock().map_err(|_| vault_error("vault_busy"))?;
        self.backend.delete(&pending_activation_account(
            activation_id,
            Purpose::Ed25519Private,
        ))?;
        self.backend.delete(&pending_activation_account(
            activation_id,
            Purpose::X25519Private,
        ))?;
        self.backend.delete(&pending_activation_account(
            activation_id,
            Purpose::OperationNonce,
        ))
    }

    /// Loads or creates one exact password-login operation before network I/O.
    pub(crate) fn load_or_create_login_operation(
        &self,
        network_id: NetworkId,
        operation_scope: &str,
        request_fingerprint: &str,
    ) -> Result<PendingLoginOperation, ClientError> {
        let _guard = self.gate.lock().map_err(|_| vault_error("vault_busy"))?;
        let account = pending_login_account(network_id, operation_scope);
        if let Some(encoded) = self.backend.get(&account)? {
            let record: PendingLoginRecord = serde_json::from_str(&encoded)
                .map_err(|_| vault_error("vault_login_operation_invalid"))?;
            if record.request_fingerprint != request_fingerprint {
                return Err(vault_error("vault_login_operation_input_mismatch"));
            }
            return record.into_operation();
        }

        let keys = PendingDeviceKeys {
            identity: Zeroizing::new(SigningKey::generate(&mut OsRng).to_bytes()),
            encryption: Zeroizing::new(StaticSecret::random_from_rng(OsRng).to_bytes()),
            nonce: new_nonce()?,
        };
        let record = PendingLoginRecord::from_operation(
            request_fingerprint.to_string(),
            Uuid::new_v4().to_string(),
            &keys,
        );
        let encoded = serde_json::to_string(&record)
            .map_err(|_| vault_error("vault_login_operation_serialize_failed"))?;
        self.backend.set(&account, &encoded)?;
        record.into_operation()
    }

    /// Removes a completed login operation after device keys and refresh are durable.
    pub(crate) fn delete_login_operation(
        &self,
        network_id: NetworkId,
        operation_scope: &str,
    ) -> Result<(), ClientError> {
        let _guard = self.gate.lock().map_err(|_| vault_error("vault_busy"))?;
        self.backend
            .delete(&pending_login_account(network_id, operation_scope))
    }

    /// Loads or creates both device keys and returns only their public halves.
    pub fn device_public_keys(&self, scope: VaultScope) -> Result<DevicePublicKeys, ClientError> {
        let _guard = self.gate.lock().map_err(|_| vault_error("vault_busy"))?;
        let identity = self.load_or_create_key(scope, Purpose::Ed25519Private)?;
        let encryption = self.load_or_create_key(scope, Purpose::X25519Private)?;

        let signing = SigningKey::from_bytes(&identity);
        let encryption = StaticSecret::from(encryption);
        Ed25519PublicKey::from_base64(signing.verifying_key().to_bytes()).and_then(|identity| {
            X25519PublicKey::from_base64(X25519Public::from(&encryption).to_bytes()).map(
                |encryption| DevicePublicKeys {
                    identity,
                    encryption,
                },
            )
        })
    }

    /// Signs a backend-owned request transcript without exporting the private key.
    pub fn sign_device_transcript(
        &self,
        scope: VaultScope,
        transcript: &[u8],
    ) -> Result<Ed25519Signature, ClientError> {
        let _guard = self.gate.lock().map_err(|_| vault_error("vault_busy"))?;
        let bytes = self.load_existing_key(scope, Purpose::Ed25519Private)?;
        let signature = SigningKey::from_bytes(&bytes).sign(transcript).to_bytes();
        URL_SAFE_NO_PAD
            .encode(signature)
            .parse()
            .map_err(|_| vault_error("vault_signature_invalid"))
    }

    /// Borrows the X25519 private bytes only inside a backend closure.
    pub fn with_encryption_private_key<T>(
        &self,
        scope: VaultScope,
        operation: impl FnOnce(&[u8; 32]) -> Result<T, ClientError>,
    ) -> Result<T, ClientError> {
        let _guard = self.gate.lock().map_err(|_| vault_error("vault_busy"))?;
        let bytes = Zeroizing::new(self.load_existing_key(scope, Purpose::X25519Private)?);
        operation(&bytes)
    }

    /// Loads the highest valid refresh rotation from either crash-recovery slot.
    pub fn load_refresh(&self, scope: VaultScope) -> Result<Option<StoredRefresh>, ClientError> {
        let _guard = self.gate.lock().map_err(|_| vault_error("vault_busy"))?;
        let mut latest: Option<StoredRefresh> = None;
        for slot in REFRESH_SLOTS {
            let account = account_name(scope, Purpose::RefreshToken, slot);
            let Some(encoded) = self.backend.get(&account)? else {
                continue;
            };
            let record: RefreshRecord =
                serde_json::from_str(&encoded).map_err(|_| vault_error("vault_refresh_invalid"))?;
            if record.credential.expose_secret().is_empty() {
                return Err(vault_error("vault_refresh_invalid"));
            }
            if latest
                .as_ref()
                .is_none_or(|current| record.rotation > current.record.rotation)
            {
                latest = Some(StoredRefresh { slot, record });
            }
        }
        Ok(latest)
    }

    /// Persists an idempotency key against the source refresh rotation before network I/O.
    pub(crate) fn prepare_refresh_operation(
        &self,
        scope: VaultScope,
        current: &StoredRefresh,
    ) -> Result<StoredRefresh, ClientError> {
        let _guard = self.gate.lock().map_err(|_| vault_error("vault_busy"))?;
        let mut prepared = current.clone();
        if prepared.record.pending_idempotency_key.is_none() {
            prepared.record.pending_idempotency_key = Some(Uuid::new_v4().to_string());
            let encoded = serde_json::to_string(&prepared.record)
                .map_err(|_| vault_error("vault_refresh_serialize_failed"))?;
            self.backend.set(
                &account_name(scope, Purpose::RefreshToken, prepared.slot),
                &encoded,
            )?;
        }
        Ok(prepared)
    }

    /// Writes the next refresh rotation before removing the prior slot.
    ///
    /// If the process exits between these writes, [`Self::load_refresh`] selects the new rotation.
    pub fn rotate_refresh(
        &self,
        scope: VaultScope,
        current: Option<&StoredRefresh>,
        record: &RefreshRecord,
    ) -> Result<StoredRefresh, ClientError> {
        if record.credential.expose_secret().is_empty()
            || current.is_some_and(|value| record.rotation <= value.record.rotation)
        {
            return Err(vault_error("vault_refresh_invalid"));
        }
        let _guard = self.gate.lock().map_err(|_| vault_error("vault_busy"))?;
        let slot = current.map_or(REFRESH_SLOTS[0], |value| 1 - value.slot);
        let encoded = serde_json::to_string(record)
            .map_err(|_| vault_error("vault_refresh_serialize_failed"))?;
        self.backend
            .set(&account_name(scope, Purpose::RefreshToken, slot), &encoded)?;
        if let Some(previous) = current {
            // The new rotation is authoritative once written. A stale old slot is safe because
            // reads choose the higher rotation; treating cleanup failure as rotation failure could
            // make the caller retry an already consumed token and revoke the session family.
            let _ = self
                .backend
                .delete(&account_name(scope, Purpose::RefreshToken, previous.slot));
        }
        Ok(StoredRefresh {
            slot,
            record: record.clone(),
        })
    }

    /// Removes all device keys and refresh slots for an explicit logout/account removal.
    pub fn delete_device(&self, scope: VaultScope) -> Result<(), ClientError> {
        let _guard = self.gate.lock().map_err(|_| vault_error("vault_busy"))?;
        for purpose in [
            Purpose::Ed25519Private,
            Purpose::X25519Private,
            Purpose::RefreshToken,
        ] {
            let slots: &[u8] = if purpose == Purpose::RefreshToken {
                &REFRESH_SLOTS
            } else {
                &[DEVICE_KEY_SLOT]
            };
            for slot in slots {
                self.backend.delete(&account_name(scope, purpose, *slot))?;
            }
        }
        Ok(())
    }

    pub(crate) fn store_device_keys(
        &self,
        scope: VaultScope,
        identity: &[u8; 32],
        encryption: &[u8; 32],
    ) -> Result<(), ClientError> {
        let _guard = self.gate.lock().map_err(|_| vault_error("vault_busy"))?;
        let identity_account = account_name(scope, Purpose::Ed25519Private, DEVICE_KEY_SLOT);
        let encryption_account = account_name(scope, Purpose::X25519Private, DEVICE_KEY_SLOT);
        let identity_value = URL_SAFE_NO_PAD.encode(identity);
        let encryption_value = URL_SAFE_NO_PAD.encode(encryption);
        let stored_identity = self.backend.get(&identity_account)?;
        let stored_encryption = self.backend.get(&encryption_account)?;
        if stored_identity.is_some() || stored_encryption.is_some() {
            if stored_identity.as_deref() == Some(identity_value.as_str())
                && stored_encryption.as_deref() == Some(encryption_value.as_str())
            {
                return Ok(());
            }
            return Err(vault_error("vault_device_key_conflict"));
        }
        self.backend.set(&identity_account, &identity_value)?;
        if let Err(error) = self.backend.set(&encryption_account, &encryption_value) {
            let _ = self.backend.delete(&identity_account);
            return Err(error);
        }
        Ok(())
    }

    fn load_or_create_key(
        &self,
        scope: VaultScope,
        purpose: Purpose,
    ) -> Result<[u8; 32], ClientError> {
        let account = account_name(scope, purpose, DEVICE_KEY_SLOT);
        if let Some(value) = self.backend.get(&account)? {
            return decode_private_key(&value);
        }
        let bytes = match purpose {
            Purpose::Ed25519Private => SigningKey::generate(&mut OsRng).to_bytes(),
            Purpose::X25519Private => StaticSecret::random_from_rng(OsRng).to_bytes(),
            Purpose::RefreshToken | Purpose::OperationNonce | Purpose::LoginOperation => {
                return Err(vault_error("vault_purpose_invalid"));
            }
        };
        self.backend.set(&account, &URL_SAFE_NO_PAD.encode(bytes))?;
        Ok(bytes)
    }

    fn load_existing_key(
        &self,
        scope: VaultScope,
        purpose: Purpose,
    ) -> Result<[u8; 32], ClientError> {
        self.backend
            .get(&account_name(scope, purpose, DEVICE_KEY_SLOT))?
            .ok_or_else(|| vault_error("vault_device_key_missing"))
            .and_then(|value| decode_private_key(&value))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Purpose {
    Ed25519Private,
    X25519Private,
    RefreshToken,
    OperationNonce,
    LoginOperation,
}

impl Purpose {
    const fn name(self) -> &'static str {
        match self {
            Self::Ed25519Private => "device-ed25519-private",
            Self::X25519Private => "device-x25519-private",
            Self::RefreshToken => "refresh-token",
            Self::OperationNonce => "operation-nonce",
            Self::LoginOperation => "login-operation",
        }
    }
}

fn account_name(scope: VaultScope, purpose: Purpose, slot: u8) -> String {
    format!(
        "v{VAULT_VERSION}:{}:{}:{}:{}:{slot}",
        scope.network_id,
        scope.user_id,
        scope.device_id,
        purpose.name()
    )
}

fn validate_installed_account(record: &InstalledAccountRecord) -> Result<(), ClientError> {
    if record.version != INSTALLED_ACCOUNT_VERSION {
        return Err(vault_error("vault_installed_account_version_unsupported"));
    }
    let origin = url::Url::parse(&record.controller_origin)
        .map_err(|_| vault_error("vault_installed_account_invalid"))?;
    crate::control_api::validate_origin(&origin)
        .map_err(|_| vault_error("vault_installed_account_invalid"))?;
    if origin.origin().ascii_serialization() != record.controller_origin {
        return Err(vault_error("vault_installed_account_invalid"));
    }
    Ok(())
}

fn pending_activation_account(activation_id: DeviceActivationId, purpose: Purpose) -> String {
    format!(
        "v{VAULT_VERSION}:pending-activation:{activation_id}:{}:{DEVICE_KEY_SLOT}",
        purpose.name()
    )
}

fn pending_login_account(network_id: NetworkId, operation_scope: &str) -> String {
    format!(
        "v{VAULT_VERSION}:pending-login:{network_id}:{operation_scope}:{}:{DEVICE_KEY_SLOT}",
        Purpose::LoginOperation.name()
    )
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PendingLoginRecord {
    identity_private_key: Secret<String>,
    encryption_private_key: Secret<String>,
    nonce: Nonce,
    idempotency_key: String,
    request_fingerprint: String,
}

impl PendingLoginRecord {
    fn from_operation(
        request_fingerprint: String,
        idempotency_key: String,
        keys: &PendingDeviceKeys,
    ) -> Self {
        Self {
            identity_private_key: Secret::new(URL_SAFE_NO_PAD.encode(*keys.identity)),
            encryption_private_key: Secret::new(URL_SAFE_NO_PAD.encode(*keys.encryption)),
            nonce: keys.nonce.clone(),
            idempotency_key,
            request_fingerprint,
        }
    }

    fn into_operation(self) -> Result<PendingLoginOperation, ClientError> {
        Ok(PendingLoginOperation {
            keys: PendingDeviceKeys {
                identity: Zeroizing::new(decode_private_key(
                    self.identity_private_key.expose_secret(),
                )?),
                encryption: Zeroizing::new(decode_private_key(
                    self.encryption_private_key.expose_secret(),
                )?),
                nonce: self.nonce,
            },
            idempotency_key: self.idempotency_key,
        })
    }
}

fn new_nonce() -> Result<Nonce, ClientError> {
    use rand_core::RngCore as _;

    let mut nonce = [0_u8; 16];
    OsRng.fill_bytes(&mut nonce);
    URL_SAFE_NO_PAD
        .encode(nonce)
        .parse()
        .map_err(|_| vault_error("vault_operation_nonce_invalid"))
}

fn decode_private_key(value: &str) -> Result<[u8; 32], ClientError> {
    let bytes = Zeroizing::new(
        URL_SAFE_NO_PAD
            .decode(value)
            .map_err(|_| vault_error("vault_device_key_invalid"))?,
    );
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| vault_error("vault_device_key_invalid"))
}

trait FixedBase64: Sized {
    fn parse_base64(encoded: String) -> Result<Self, ClientError>;

    fn from_base64(bytes: [u8; 32]) -> Result<Self, ClientError> {
        Self::parse_base64(URL_SAFE_NO_PAD.encode(bytes))
    }
}

impl FixedBase64 for Ed25519PublicKey {
    fn parse_base64(encoded: String) -> Result<Self, ClientError> {
        encoded
            .parse()
            .map_err(|_| vault_error("vault_public_key_invalid"))
    }
}

impl FixedBase64 for X25519PublicKey {
    fn parse_base64(encoded: String) -> Result<Self, ClientError> {
        encoded
            .parse()
            .map_err(|_| vault_error("vault_public_key_invalid"))
    }
}

fn vault_error(code: &str) -> ClientError {
    let message = match code {
        "vault_unavailable"
        | "vault_read_failed"
        | "vault_write_failed"
        | "vault_delete_failed" => native_vault_access_message(),
        _ => "The saved device credentials are unavailable or invalid.",
    };
    ClientError::internal(code, message)
}

#[cfg(not(target_os = "windows"))]
const fn native_vault_access_message() -> &'static str {
    "Connect cannot access its private local credential file. Check the app-data ownership and permissions, then reopen the app."
}

#[cfg(target_os = "windows")]
const fn native_vault_access_message() -> &'static str {
    "Connect cannot access Windows Credential Manager. Unlock Windows, then reopen the app."
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[derive(Default)]
    struct MemoryBackend(Mutex<HashMap<String, String>>);

    impl VaultBackend for MemoryBackend {
        fn set(&self, account: &str, value: &str) -> Result<(), ClientError> {
            self.0.lock().unwrap().insert(account.into(), value.into());
            Ok(())
        }

        fn get(&self, account: &str) -> Result<Option<String>, ClientError> {
            Ok(self.0.lock().unwrap().get(account).cloned())
        }

        fn delete(&self, account: &str) -> Result<(), ClientError> {
            self.0.lock().unwrap().remove(account);
            Ok(())
        }
    }

    fn scope() -> VaultScope {
        VaultScope {
            network_id: NetworkId::new(),
            user_id: UserId::new(),
            device_id: DeviceId::new(),
        }
    }

    fn timestamp(value: &str) -> Timestamp {
        value.parse().unwrap()
    }

    #[test]
    fn installed_account_record_is_versioned_discoverable_and_bearer_free() {
        let backend = Arc::new(MemoryBackend::default());
        let vault = CredentialVault::new(backend.clone());
        let record = InstalledAccountRecord::new(
            "https://control.example".to_string(),
            scope(),
            ControllerInstanceId::new(),
            URL_SAFE_NO_PAD.encode([19_u8; 32]).parse().unwrap(),
        );

        vault.store_installed_account(&record).unwrap();
        vault.store_installed_account(&record).unwrap();
        assert_eq!(
            vault.load_installed_account().unwrap(),
            Some(record.clone())
        );
        let encoded = backend
            .0
            .lock()
            .unwrap()
            .get(INSTALLED_ACCOUNT_KEY)
            .cloned()
            .unwrap();
        assert!(encoded.contains("\"version\":1"));
        for forbidden in [
            "accessToken",
            "refreshCredential",
            "activationSecret",
            "privateKey",
        ] {
            assert!(!encoded.contains(forbidden));
        }

        let conflicting = InstalledAccountRecord::new(
            "https://other.example".to_string(),
            scope(),
            ControllerInstanceId::new(),
            URL_SAFE_NO_PAD.encode([21_u8; 32]).parse().unwrap(),
        );
        assert!(vault.store_installed_account(&conflicting).is_err());
        assert!(vault.delete_installed_account_if(&record).unwrap());
        assert!(vault.load_installed_account().unwrap().is_none());
    }

    #[test]
    fn device_keys_are_stable_and_namespaced() {
        let backend = Arc::new(MemoryBackend::default());
        let vault = CredentialVault::new(backend.clone());
        let first_scope = scope();
        let second_scope = scope();

        let first = vault.device_public_keys(first_scope).unwrap();
        assert_eq!(first, vault.device_public_keys(first_scope).unwrap());
        assert_ne!(first, vault.device_public_keys(second_scope).unwrap());

        let values = backend.0.lock().unwrap();
        assert_eq!(values.len(), 4);
        assert!(values.keys().all(|key| key.starts_with("v1:")));
        assert!(values
            .keys()
            .any(|key| key.contains(&first_scope.network_id.to_string())));
    }

    #[test]
    fn activation_keys_survive_retry_until_device_state_commits() {
        let backend = Arc::new(MemoryBackend::default());
        let vault = CredentialVault::new(backend.clone());
        let activation_id = DeviceActivationId::new();
        let first = vault.load_or_create_activation_keys(activation_id).unwrap();
        let identity = *first.identity;
        let encryption = *first.encryption;
        let nonce = first.nonce.clone();
        drop(first);

        let retried = vault.load_or_create_activation_keys(activation_id).unwrap();
        assert_eq!(*retried.identity, identity);
        assert_eq!(*retried.encryption, encryption);
        assert_eq!(retried.nonce, nonce);

        let device_scope = scope();
        vault
            .store_device_keys(device_scope, &identity, &encryption)
            .unwrap();
        vault.delete_activation_keys(activation_id).unwrap();
        let values = backend.0.lock().unwrap();
        assert_eq!(values.len(), 2);
        assert!(values.keys().all(|key| !key.contains("pending-activation")));
    }

    #[test]
    fn existing_device_keys_cannot_be_overwritten() {
        let vault = CredentialVault::new(Arc::new(MemoryBackend::default()));
        let device_scope = scope();
        vault
            .store_device_keys(device_scope, &[1; 32], &[2; 32])
            .unwrap();
        vault
            .store_device_keys(device_scope, &[1; 32], &[2; 32])
            .unwrap();
        assert!(vault
            .store_device_keys(device_scope, &[3; 32], &[4; 32])
            .is_err());
    }

    #[test]
    fn login_operation_reuses_exact_material_and_rejects_changed_input() {
        let backend = Arc::new(MemoryBackend::default());
        let vault = CredentialVault::new(backend.clone());
        let network_id = NetworkId::new();
        let first = vault
            .load_or_create_login_operation(network_id, "account-scope", "request-one")
            .unwrap();
        let first_identity = *first.keys.identity;
        let first_encryption = *first.keys.encryption;
        let first_nonce = first.keys.nonce.clone();
        let first_key = first.idempotency_key.clone();
        drop(first);

        let replay = vault
            .load_or_create_login_operation(network_id, "account-scope", "request-one")
            .unwrap();
        assert_eq!(*replay.keys.identity, first_identity);
        assert_eq!(*replay.keys.encryption, first_encryption);
        assert_eq!(replay.keys.nonce, first_nonce);
        assert_eq!(replay.idempotency_key, first_key);
        assert!(vault
            .load_or_create_login_operation(network_id, "account-scope", "request-two")
            .is_err());

        vault
            .delete_login_operation(network_id, "account-scope")
            .unwrap();
        assert!(backend.0.lock().unwrap().is_empty());
    }

    #[test]
    fn refresh_rotation_uses_new_slot_and_recovers_highest_value() {
        let backend = Arc::new(MemoryBackend::default());
        let vault = CredentialVault::new(backend.clone());
        let scope = scope();
        let first = RefreshRecord {
            credential: Secret::new("first".to_string()),
            expires_at: timestamp("2030-01-01T00:00:00Z"),
            rotation: 1,
            pending_idempotency_key: None,
        };
        let stored = vault.rotate_refresh(scope, None, &first).unwrap();

        let newer = RefreshRecord {
            credential: Secret::new("newer".to_string()),
            expires_at: timestamp("2030-01-02T00:00:00Z"),
            rotation: 2,
            pending_idempotency_key: None,
        };
        let alternate = 1 - stored.slot;
        backend
            .set(
                &account_name(scope, Purpose::RefreshToken, alternate),
                &serde_json::to_string(&newer).unwrap(),
            )
            .unwrap();

        let recovered = vault.load_refresh(scope).unwrap().unwrap();
        assert_eq!(recovered.slot, alternate);
        assert_eq!(recovered.record.rotation, 2);
        assert_eq!(recovered.record.credential.expose_secret(), "newer");
    }

    #[test]
    fn refresh_operation_key_is_stable_per_source_rotation_and_changes_next_rotation() {
        let vault = CredentialVault::new(Arc::new(MemoryBackend::default()));
        let scope = scope();
        let current = vault
            .rotate_refresh(
                scope,
                None,
                &RefreshRecord {
                    credential: Secret::new("first".to_string()),
                    expires_at: timestamp("2030-01-01T00:00:00Z"),
                    rotation: 1,
                    pending_idempotency_key: None,
                },
            )
            .unwrap();
        let first = vault.prepare_refresh_operation(scope, &current).unwrap();
        let replay = vault.prepare_refresh_operation(scope, &first).unwrap();
        assert_eq!(
            first.record.pending_idempotency_key,
            replay.record.pending_idempotency_key
        );

        let next = vault
            .rotate_refresh(
                scope,
                Some(&replay),
                &RefreshRecord {
                    credential: Secret::new("second".to_string()),
                    expires_at: timestamp("2030-01-02T00:00:00Z"),
                    rotation: 2,
                    pending_idempotency_key: None,
                },
            )
            .unwrap();
        assert!(next.record.pending_idempotency_key.is_none());
        let next_prepared = vault.prepare_refresh_operation(scope, &next).unwrap();
        assert_ne!(
            next_prepared.record.pending_idempotency_key,
            first.record.pending_idempotency_key
        );
    }

    #[test]
    fn delete_device_removes_every_purpose_and_slot() {
        let backend = Arc::new(MemoryBackend::default());
        let vault = CredentialVault::new(backend.clone());
        let scope = scope();
        vault.device_public_keys(scope).unwrap();
        vault
            .rotate_refresh(
                scope,
                None,
                &RefreshRecord {
                    credential: Secret::new("refresh".to_string()),
                    expires_at: timestamp("2030-01-01T00:00:00Z"),
                    rotation: 1,
                    pending_idempotency_key: None,
                },
            )
            .unwrap();

        vault.delete_device(scope).unwrap();
        assert!(backend.0.lock().unwrap().is_empty());
    }
}
