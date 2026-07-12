//! Account-first device session lifecycle with serialized refresh-token rotation.

use crate::control_api::{validate_origin, BundleFetch, ControlPlane};
use crate::error::ClientError;
use crate::vault::{
    CredentialVault, InstalledAccountRecord, PendingDeviceKeys, RefreshRecord, StoredRefresh,
    VaultScope,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use control_protocol::account::{
    AccountMetadata, AccountStatus, ConsumeDeviceActivationRequest, CreateDeviceSessionResponse,
    CreateSessionRequest, DeviceEnrollment, RefreshSessionRequest, SessionCredentials,
};
use control_protocol::account_crypto::{
    device_activation_proof_transcript, device_login_proof_transcript,
};
use control_protocol::crypto::{Ed25519PublicKey, Ed25519Signature, X25519PublicKey};
use control_protocol::id::{
    ControllerInstanceId, DeviceActivationId, DeviceId, NetworkId, Timestamp, UserId,
};
use control_protocol::secret::Secret;
use ed25519_dalek::{Signer as _, SigningKey};
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use std::sync::Arc;
use time::Duration as TimeDuration;
use tokio::sync::Mutex;
use x25519_dalek::{PublicKey as X25519Public, StaticSecret};

const ACCESS_REFRESH_MARGIN: TimeDuration = TimeDuration::seconds(60);

/// Safe persistent identity of one enrolled session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionBinding {
    /// Bound private network.
    pub network_id: NetworkId,
    /// Bound logical account.
    pub user_id: UserId,
    /// Exact enrolled device.
    pub device_id: DeviceId,
}

impl From<SessionBinding> for VaultScope {
    fn from(value: SessionBinding) -> Self {
        Self {
            network_id: value.network_id,
            user_id: value.user_id,
            device_id: value.device_id,
        }
    }
}

/// One-time activation input retained only for the backend call.
#[derive(Clone)]
pub struct ActivationBootstrap {
    /// Expected private network from the authenticated activation link.
    pub network_id: NetworkId,
    /// Expected account from the activation creation response.
    pub user_id: UserId,
    /// Activation identity bound into the proof.
    pub activation_id: DeviceActivationId,
    /// Controller-provided activation deadline.
    pub expires_at: Timestamp,
    /// One-time write-only secret.
    pub secret: Secret<String>,
}

impl std::fmt::Debug for ActivationBootstrap {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ActivationBootstrap")
            .field("network_id", &self.network_id)
            .field("user_id", &self.user_id)
            .field("activation_id", &self.activation_id)
            .field("expires_at", &self.expires_at)
            .field("secret", &"[redacted]")
            .finish()
    }
}

/// Safe local device presentation metadata.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceMetadata {
    /// User-visible device name.
    pub display_name: String,
    /// Connect semantic version.
    pub client_version: String,
    /// Platform identifier.
    pub platform: String,
}

/// Controller trust persisted only as part of a successful account installation.
#[derive(Clone)]
pub struct AccountInstallTrust {
    /// Controller instance expected in signed bundles.
    pub controller_instance_id: ControllerInstanceId,
    /// Public key used to verify signed bundles.
    pub bundle_signing_public_key: Ed25519PublicKey,
}

impl std::fmt::Debug for AccountInstallTrust {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AccountInstallTrust")
            .field("controller_instance_id", &"[redacted]")
            .field("bundle_signing_public_key", &"[redacted]")
            .finish()
    }
}

/// Optional password login input.
#[derive(Clone)]
pub struct LoginInput {
    /// Expected private network selected from trusted Control configuration.
    pub network_id: NetworkId,
    /// Operator-configured account identifier.
    pub account: String,
    /// Write-only password.
    pub password: Secret<String>,
}

impl std::fmt::Debug for LoginInput {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LoginInput")
            .field("network_id", &self.network_id)
            .field("account", &self.account)
            .field("password", &"[redacted]")
            .finish()
    }
}

/// Safe renderer-facing session phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum AccountSessionPhase {
    /// No local device session.
    SignedOut,
    /// Refresh exists but no current in-memory access token.
    RefreshRequired,
    /// A short-lived access token is held only in backend memory.
    Active,
}

/// Secret-free session state suitable for a Tauri snapshot command.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountSessionSnapshot {
    /// Current lifecycle phase.
    pub phase: AccountSessionPhase,
    /// Safe enrolled identity.
    pub binding: Option<SessionBinding>,
    /// Safe current account metadata, when known.
    pub account: Option<AccountMetadata>,
    /// Access deadline without bearer material.
    pub access_expires_at: Option<Timestamp>,
    /// Refresh deadline without bearer material.
    pub refresh_expires_at: Option<Timestamp>,
    /// Current local rotation for idempotent refresh coalescing.
    pub refresh_rotation: Option<u64>,
}

struct AccessCredential {
    token: Secret<String>,
    expires_at: Timestamp,
}

#[derive(Default)]
struct SessionState {
    binding: Option<SessionBinding>,
    account: Option<AccountMetadata>,
    access: Option<AccessCredential>,
    refresh: Option<StoredRefresh>,
}

impl SessionState {
    fn snapshot(&self) -> AccountSessionSnapshot {
        AccountSessionSnapshot {
            phase: if self.access.is_some() {
                AccountSessionPhase::Active
            } else if self.refresh.is_some() {
                AccountSessionPhase::RefreshRequired
            } else {
                AccountSessionPhase::SignedOut
            },
            binding: self.binding,
            account: self.account.clone(),
            access_expires_at: self.access.as_ref().map(|access| access.expires_at),
            refresh_expires_at: self
                .refresh
                .as_ref()
                .map(|refresh| refresh.record.expires_at),
            refresh_rotation: self.refresh.as_ref().map(|refresh| refresh.record.rotation),
        }
    }
}

/// Serialized account session owner. No method returns bearer or private-key material publicly.
pub struct AccountSessionManager {
    control: Arc<dyn ControlPlane>,
    control_origin: String,
    vault: CredentialVault,
    install_trust: AccountInstallTrust,
    state: Mutex<SessionState>,
}

impl AccountSessionManager {
    /// Creates a manager for one trusted Control origin.
    pub fn new(
        control: Arc<dyn ControlPlane>,
        control_origin: String,
        vault: CredentialVault,
        install_trust: AccountInstallTrust,
    ) -> Result<Self, ClientError> {
        let parsed = url::Url::parse(&control_origin)
            .map_err(|_| session_error("session_control_origin_invalid"))?;
        validate_origin(&parsed).map_err(|_| session_error("session_control_origin_invalid"))?;
        Ok(Self {
            control,
            control_origin: control_origin.trim_end_matches('/').to_string(),
            vault,
            install_trust,
            state: Mutex::new(SessionState::default()),
        })
    }

    /// Returns the current secret-free session snapshot.
    pub async fn snapshot(&self) -> AccountSessionSnapshot {
        self.state.lock().await.snapshot()
    }

    /// Creates a device session from a one-time activation and persists keys only after success.
    pub async fn activate(
        &self,
        bootstrap: ActivationBootstrap,
        metadata: DeviceMetadata,
    ) -> Result<AccountSessionSnapshot, ClientError> {
        let mut state = self.state.lock().await;
        require_signed_out(&state)?;
        let vault = self.vault.clone();
        let activation_id = bootstrap.activation_id;
        let keys = tokio::task::spawn_blocking(move || {
            vault.load_or_create_activation_keys(activation_id)
        })
        .await
        .map_err(|_| session_error("activation_key_prepare_failed"))??;
        let mut enrollment = enrollment_from_keys(metadata, &keys)?;
        let transcript = device_activation_proof_transcript(
            bootstrap.activation_id,
            bootstrap.expires_at,
            &self.control_origin,
            &enrollment,
        )
        .map_err(|_| session_error("activation_proof_failed"))?;
        enrollment.proof = sign_pending(&keys, &transcript)?;
        let response = self
            .control
            .activate_device(&ConsumeDeviceActivationRequest {
                activation_secret: bootstrap.secret,
                device: enrollment,
            })
            .await?;
        if response.activation_id != Some(bootstrap.activation_id)
            || response.account.user_id != bootstrap.user_id
        {
            return Err(session_error("activation_response_binding_mismatch"));
        }
        self.commit_new_session(
            &mut state,
            bootstrap.network_id,
            keys,
            PendingCleanup::Activation(bootstrap.activation_id),
            response,
        )
        .await
    }

    /// Creates a device session through optional password login.
    pub async fn login(
        &self,
        input: LoginInput,
        metadata: DeviceMetadata,
    ) -> Result<AccountSessionSnapshot, ClientError> {
        let mut state = self.state.lock().await;
        require_signed_out(&state)?;
        let operation_scope = login_operation_scope(input.network_id, &input.account);
        let request_fingerprint = login_request_fingerprint(&input, &metadata)?;
        let vault = self.vault.clone();
        let network_id = input.network_id;
        let scope_for_load = operation_scope.clone();
        let operation = tokio::task::spawn_blocking(move || {
            vault.load_or_create_login_operation(network_id, &scope_for_load, &request_fingerprint)
        })
        .await
        .map_err(|_| session_error("login_operation_prepare_failed"))??;
        let keys = operation.keys;
        let mut enrollment = enrollment_from_keys(metadata, &keys)?;
        let transcript =
            device_login_proof_transcript(&input.account, &self.control_origin, &enrollment)
                .map_err(|_| session_error("login_proof_failed"))?;
        enrollment.proof = sign_pending(&keys, &transcript)?;
        let response = self
            .control
            .login_device(
                &CreateSessionRequest {
                    account: input.account,
                    password: input.password,
                    device: enrollment,
                },
                &operation.idempotency_key,
            )
            .await?;
        if response.activation_id.is_some() {
            return Err(session_error("login_response_binding_mismatch"));
        }
        self.commit_new_session(
            &mut state,
            input.network_id,
            keys,
            PendingCleanup::Login {
                network_id: input.network_id,
                operation_scope,
            },
            response,
        )
        .await
    }

    /// Restores a keyring-backed session without loading a bearer access token from disk.
    pub async fn restore(
        &self,
        binding: SessionBinding,
    ) -> Result<AccountSessionSnapshot, ClientError> {
        let mut state = self.state.lock().await;
        require_signed_out(&state)?;
        let vault = self.vault.clone();
        let refresh = tokio::task::spawn_blocking(move || vault.load_refresh(binding.into()))
            .await
            .map_err(|_| session_error("session_restore_failed"))??
            .ok_or_else(|| session_error("session_refresh_missing"))?;
        state.binding = Some(binding);
        state.refresh = Some(refresh);
        Ok(state.snapshot())
    }

    /// Coalesces concurrent refresh requests and returns only a safe snapshot.
    pub async fn ensure_fresh(
        &self,
        now: Timestamp,
    ) -> Result<AccountSessionSnapshot, ClientError> {
        let mut state = self.state.lock().await;
        self.ensure_access_locked(&mut state, now).await?;
        Ok(state.snapshot())
    }

    /// Refreshes only if the caller still observes the supplied rotation.
    pub async fn refresh_if_current(
        &self,
        expected_rotation: u64,
    ) -> Result<AccountSessionSnapshot, ClientError> {
        let mut state = self.state.lock().await;
        let current = state
            .refresh
            .as_ref()
            .ok_or_else(|| session_error("session_refresh_missing"))?;
        if current.record.rotation != expected_rotation {
            return Ok(state.snapshot());
        }
        self.rotate_locked(&mut state).await?;
        Ok(state.snapshot())
    }

    /// Fetches a bundle using a coalesced current access token.
    pub async fn fetch_bundle(
        &self,
        now: Timestamp,
        etag: Option<&str>,
    ) -> Result<BundleFetch, ClientError> {
        let mut state = self.state.lock().await;
        self.ensure_access_locked(&mut state, now).await?;
        let token = &state
            .access
            .as_ref()
            .ok_or_else(|| session_error("session_access_missing"))?
            .token;
        self.control.fetch_profile_bundle(token, etag).await
    }

    /// Revokes the server session, then removes all local device secrets.
    pub async fn logout(&self) -> Result<AccountSessionSnapshot, ClientError> {
        let mut state = self.state.lock().await;
        let binding = state
            .binding
            .ok_or_else(|| session_error("session_not_active"))?;
        let token = &state
            .access
            .as_ref()
            .ok_or_else(|| session_error("session_access_missing"))?
            .token;
        self.control.logout_device(token, binding.device_id).await?;
        let vault = self.vault.clone();
        let installed = self.installed_record(binding);
        tokio::task::spawn_blocking(move || {
            vault.delete_installed_account_if(&installed)?;
            vault.delete_device(binding.into())
        })
        .await
        .map_err(|_| session_error("session_logout_failed"))??;
        *state = SessionState::default();
        Ok(state.snapshot())
    }

    /// Removes local device credentials without requiring a Control round trip.
    ///
    /// This is reserved for cancelling an onboarding operation that has not been exposed as an
    /// installed runtime. Normal user logout must use [`Self::logout`] so the server session is
    /// revoked first.
    pub(crate) async fn discard_local(&self) -> Result<AccountSessionSnapshot, ClientError> {
        let mut state = self.state.lock().await;
        if let Some(binding) = state.binding {
            let vault = self.vault.clone();
            let installed = self.installed_record(binding);
            tokio::task::spawn_blocking(move || {
                vault.delete_installed_account_if(&installed)?;
                vault.delete_device(binding.into())
            })
            .await
            .map_err(|_| session_error("session_discard_failed"))??;
        }
        *state = SessionState::default();
        Ok(state.snapshot())
    }

    async fn commit_new_session(
        &self,
        state: &mut SessionState,
        network_id: NetworkId,
        keys: PendingDeviceKeys,
        pending_cleanup: PendingCleanup,
        response: CreateDeviceSessionResponse,
    ) -> Result<AccountSessionSnapshot, ClientError> {
        validate_credentials(&response.credentials)?;
        if response.account.status != AccountStatus::Active {
            return Err(session_error("session_account_disabled"));
        }
        let binding = SessionBinding {
            network_id,
            user_id: response.account.user_id,
            device_id: response.device_id,
        };
        let scope = VaultScope::from(binding);
        let installed = self.installed_record(binding);
        let vault = self.vault.clone();
        let identity = *keys.identity;
        let encryption = *keys.encryption;
        tokio::task::spawn_blocking(move || {
            vault.store_device_keys(scope, &identity, &encryption)?;
            let record = RefreshRecord {
                credential: response.credentials.refresh_credential.clone(),
                expires_at: response.credentials.refresh_expires_at,
                rotation: 1,
                pending_idempotency_key: None,
            };
            if let Err(error) = vault.rotate_refresh(scope, None, &record) {
                let _ = vault.delete_device(scope);
                return Err(error);
            }
            if let Err(error) = vault.store_installed_account(&installed) {
                let _ = vault.delete_installed_account_if(&installed);
                let _ = vault.delete_device(scope);
                return Err(error);
            }
            match pending_cleanup {
                PendingCleanup::Activation(activation_id) => {
                    vault.delete_activation_keys(activation_id)?;
                }
                PendingCleanup::Login {
                    network_id,
                    operation_scope,
                } => {
                    vault.delete_login_operation(network_id, &operation_scope)?;
                }
            }
            Ok(())
        })
        .await
        .map_err(|_| session_error("session_commit_failed"))??;

        state.binding = Some(binding);
        state.account = Some(response.account);
        state.access = Some(AccessCredential {
            token: response.credentials.access_token,
            expires_at: response.credentials.access_expires_at,
        });
        state.refresh = self.vault.load_refresh(scope)?;
        Ok(state.snapshot())
    }

    fn installed_record(&self, binding: SessionBinding) -> InstalledAccountRecord {
        InstalledAccountRecord::new(
            self.control_origin.clone(),
            binding.into(),
            self.install_trust.controller_instance_id,
            self.install_trust.bundle_signing_public_key.clone(),
        )
    }

    async fn ensure_access_locked(
        &self,
        state: &mut SessionState,
        now: Timestamp,
    ) -> Result<(), ClientError> {
        if state.access.as_ref().is_some_and(|access| {
            access.expires_at.as_datetime() > now.as_datetime() + ACCESS_REFRESH_MARGIN
        }) {
            return Ok(());
        }
        self.rotate_locked(state).await
    }

    async fn rotate_locked(&self, state: &mut SessionState) -> Result<(), ClientError> {
        let binding = state
            .binding
            .ok_or_else(|| session_error("session_not_active"))?;
        let current = state
            .refresh
            .clone()
            .ok_or_else(|| session_error("session_refresh_missing"))?;
        let vault = self.vault.clone();
        let current_for_prepare = current.clone();
        let prepared = tokio::task::spawn_blocking(move || {
            vault.prepare_refresh_operation(binding.into(), &current_for_prepare)
        })
        .await
        .map_err(|_| session_error("session_refresh_prepare_failed"))??;
        state.refresh = Some(prepared.clone());
        let idempotency_key = prepared
            .record
            .pending_idempotency_key
            .as_deref()
            .ok_or_else(|| session_error("session_refresh_operation_missing"))?;
        let response = self
            .control
            .refresh_session(
                &RefreshSessionRequest {
                    refresh_credential: prepared.record.credential.clone(),
                },
                idempotency_key,
            )
            .await?;
        validate_credentials(&response.credentials)?;
        if response.account.user_id != binding.user_id
            || response.account.status != AccountStatus::Active
        {
            return Err(session_error("refresh_response_binding_mismatch"));
        }
        let next_rotation = current
            .record
            .rotation
            .checked_add(1)
            .ok_or_else(|| session_error("refresh_rotation_exhausted"))?;
        let record = RefreshRecord {
            credential: response.credentials.refresh_credential.clone(),
            expires_at: response.credentials.refresh_expires_at,
            rotation: next_rotation,
            pending_idempotency_key: None,
        };
        let vault = self.vault.clone();
        let current_for_write = prepared;
        let stored = tokio::task::spawn_blocking(move || {
            vault.rotate_refresh(binding.into(), Some(&current_for_write), &record)
        })
        .await
        .map_err(|_| session_error("session_refresh_commit_failed"))??;

        state.account = Some(response.account);
        state.access = Some(AccessCredential {
            token: response.credentials.access_token,
            expires_at: response.credentials.access_expires_at,
        });
        state.refresh = Some(stored);
        Ok(())
    }
}

fn enrollment_from_keys(
    metadata: DeviceMetadata,
    keys: &PendingDeviceKeys,
) -> Result<DeviceEnrollment, ClientError> {
    let enrollment = DeviceEnrollment {
        display_name: metadata.display_name,
        client_version: metadata.client_version,
        platform: metadata.platform,
        identity_public_key: parse_ed25519(
            SigningKey::from_bytes(&keys.identity)
                .verifying_key()
                .to_bytes(),
        )?,
        encryption_public_key: parse_x25519(
            X25519Public::from(&StaticSecret::from(*keys.encryption)).to_bytes(),
        )?,
        nonce: keys.nonce.clone(),
        proof: URL_SAFE_NO_PAD
            .encode([0_u8; 64])
            .parse::<Ed25519Signature>()
            .map_err(|_| session_error("device_proof_failed"))?,
    };
    enrollment
        .validate_for_client()
        .map_err(|_| session_error("device_metadata_invalid"))?;
    Ok(enrollment)
}

enum PendingCleanup {
    Activation(DeviceActivationId),
    Login {
        network_id: NetworkId,
        operation_scope: String,
    },
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct LoginFingerprint<'a> {
    network_id: NetworkId,
    account: &'a str,
    password: &'a Secret<String>,
    metadata: &'a DeviceMetadata,
}

fn login_operation_scope(network_id: NetworkId, account: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(
        format!("{network_id}\0{account}").as_bytes(),
    ))
}

fn login_request_fingerprint(
    input: &LoginInput,
    metadata: &DeviceMetadata,
) -> Result<String, ClientError> {
    let serialized = zeroize::Zeroizing::new(
        serde_json::to_vec(&LoginFingerprint {
            network_id: input.network_id,
            account: &input.account,
            password: &input.password,
            metadata,
        })
        .map_err(|_| session_error("login_operation_fingerprint_failed"))?,
    );
    Ok(URL_SAFE_NO_PAD.encode(Sha256::digest(&*serialized)))
}

fn sign_pending(
    keys: &PendingDeviceKeys,
    transcript: &[u8],
) -> Result<Ed25519Signature, ClientError> {
    URL_SAFE_NO_PAD
        .encode(
            SigningKey::from_bytes(&keys.identity)
                .sign(transcript)
                .to_bytes(),
        )
        .parse()
        .map_err(|_| session_error("device_proof_failed"))
}

fn parse_ed25519(bytes: [u8; 32]) -> Result<Ed25519PublicKey, ClientError> {
    URL_SAFE_NO_PAD
        .encode(bytes)
        .parse()
        .map_err(|_| session_error("device_public_key_failed"))
}

fn parse_x25519(bytes: [u8; 32]) -> Result<X25519PublicKey, ClientError> {
    URL_SAFE_NO_PAD
        .encode(bytes)
        .parse()
        .map_err(|_| session_error("device_public_key_failed"))
}

fn validate_credentials(credentials: &SessionCredentials) -> Result<(), ClientError> {
    credentials
        .validate()
        .map_err(|_| session_error("session_credentials_invalid"))
}

fn require_signed_out(state: &SessionState) -> Result<(), ClientError> {
    if state.binding.is_some() || state.refresh.is_some() || state.access.is_some() {
        return Err(session_error("session_already_active"));
    }
    Ok(())
}

fn session_error(code: &str) -> ClientError {
    ClientError::internal(code, "The account session operation failed.")
}

trait ClientEnrollmentValidation {
    fn validate_for_client(&self) -> Result<(), control_protocol::ProtocolValidationError>;
}

impl ClientEnrollmentValidation for DeviceEnrollment {
    fn validate_for_client(&self) -> Result<(), control_protocol::ProtocolValidationError> {
        ConsumeDeviceActivationRequest {
            activation_secret: Secret::new("validation-placeholder".to_string()),
            device: self.clone(),
        }
        .validate()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control_api::BundleFetch;
    use crate::vault::VaultBackend;
    use async_trait::async_trait;
    use control_protocol::id::SessionId;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex as StdMutex;

    #[derive(Default)]
    struct MemoryBackend(StdMutex<HashMap<String, String>>);

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

    struct FakeControl {
        user_id: UserId,
        device_id: DeviceId,
        activation_id: DeviceActivationId,
        refreshes: AtomicUsize,
    }

    #[async_trait]
    impl ControlPlane for FakeControl {
        async fn activate_device(
            &self,
            _request: &ConsumeDeviceActivationRequest,
        ) -> Result<CreateDeviceSessionResponse, ClientError> {
            Ok(response(
                self.user_id,
                self.device_id,
                Some(self.activation_id),
                0,
            ))
        }

        async fn login_device(
            &self,
            _request: &CreateSessionRequest,
            _idempotency_key: &str,
        ) -> Result<CreateDeviceSessionResponse, ClientError> {
            Ok(response(self.user_id, self.device_id, None, 0))
        }

        async fn refresh_session(
            &self,
            _request: &RefreshSessionRequest,
            _idempotency_key: &str,
        ) -> Result<control_protocol::account::RefreshSessionResponse, ClientError> {
            let sequence = self.refreshes.fetch_add(1, Ordering::SeqCst) + 1;
            let response = response(self.user_id, self.device_id, None, sequence);
            Ok(control_protocol::account::RefreshSessionResponse {
                account: response.account,
                credentials: response.credentials,
            })
        }

        async fn fetch_profile_bundle(
            &self,
            _access_token: &Secret<String>,
            _etag: Option<&str>,
        ) -> Result<BundleFetch, ClientError> {
            Ok(BundleFetch::NotModified)
        }

        async fn logout_device(
            &self,
            _access_token: &Secret<String>,
            _device_id: DeviceId,
        ) -> Result<(), ClientError> {
            Ok(())
        }
    }

    fn response(
        user_id: UserId,
        device_id: DeviceId,
        activation_id: Option<DeviceActivationId>,
        sequence: usize,
    ) -> CreateDeviceSessionResponse {
        CreateDeviceSessionResponse {
            activation_id,
            account: AccountMetadata {
                user_id,
                display_name: "Account".to_string(),
                status: AccountStatus::Active,
            },
            device_id,
            credentials: SessionCredentials {
                session_id: SessionId::new(),
                access_token: Secret::new(format!("access-{sequence}")),
                access_expires_at: "2030-01-01T00:10:00Z".parse().unwrap(),
                refresh_credential: Secret::new(format!("refresh-{sequence}")),
                refresh_expires_at: "2030-02-01T00:00:00Z".parse().unwrap(),
            },
        }
    }

    fn metadata() -> DeviceMetadata {
        DeviceMetadata {
            display_name: "Laptop".to_string(),
            client_version: "0.1.0".to_string(),
            platform: "macos-arm64".to_string(),
        }
    }

    #[tokio::test]
    async fn activation_commits_keys_and_never_exposes_tokens_in_snapshot() {
        let user_id = UserId::new();
        let activation_id = DeviceActivationId::new();
        let control = Arc::new(FakeControl {
            user_id,
            device_id: DeviceId::new(),
            activation_id,
            refreshes: AtomicUsize::new(0),
        });
        let backend = Arc::new(MemoryBackend::default());
        let manager = AccountSessionManager::new(
            control,
            "https://control.example".to_string(),
            CredentialVault::new(backend.clone()),
            install_trust(),
        )
        .unwrap();
        let snapshot = manager
            .activate(
                ActivationBootstrap {
                    network_id: NetworkId::new(),
                    user_id,
                    activation_id,
                    expires_at: "2029-01-01T00:00:00Z".parse().unwrap(),
                    secret: Secret::new("activation-secret".to_string()),
                },
                metadata(),
            )
            .await
            .unwrap();

        let json = serde_json::to_string(&snapshot).unwrap();
        assert_eq!(snapshot.phase, AccountSessionPhase::Active);
        assert!(!json.contains("access-0"));
        assert!(!json.contains("refresh-0"));
        assert!(!json.contains("activation-secret"));
        assert_eq!(backend.0.lock().unwrap().len(), 4);
    }

    #[tokio::test]
    async fn concurrent_ensure_fresh_performs_one_rotation() {
        let user_id = UserId::new();
        let device_id = DeviceId::new();
        let activation_id = DeviceActivationId::new();
        let control = Arc::new(FakeControl {
            user_id,
            device_id,
            activation_id,
            refreshes: AtomicUsize::new(0),
        });
        let vault = CredentialVault::new(Arc::new(MemoryBackend::default()));
        let manager = Arc::new(
            AccountSessionManager::new(
                control.clone(),
                "https://control.example".to_string(),
                vault.clone(),
                install_trust(),
            )
            .unwrap(),
        );
        let binding = SessionBinding {
            network_id: NetworkId::new(),
            user_id,
            device_id,
        };
        vault
            .rotate_refresh(
                binding.into(),
                None,
                &RefreshRecord {
                    credential: Secret::new("refresh-0".to_string()),
                    expires_at: "2030-02-01T00:00:00Z".parse().unwrap(),
                    rotation: 1,
                    pending_idempotency_key: None,
                },
            )
            .unwrap();
        manager.restore(binding).await.unwrap();
        let now: Timestamp = "2030-01-01T00:00:00Z".parse().unwrap();
        let (first, second) = tokio::join!(manager.ensure_fresh(now), manager.ensure_fresh(now));
        assert!(first.is_ok());
        assert!(second.is_ok());
        assert_eq!(control.refreshes.load(Ordering::SeqCst), 1);
    }

    #[derive(Default)]
    struct FaultBackend {
        values: StdMutex<HashMap<String, String>>,
        fail_rotation: StdMutex<Option<u64>>,
        fail_installed_record: StdMutex<bool>,
    }

    impl FaultBackend {
        fn fail_next_rotation(&self, rotation: u64) {
            *self.fail_rotation.lock().unwrap() = Some(rotation);
        }

        fn fail_next_installed_record(&self) {
            *self.fail_installed_record.lock().unwrap() = true;
        }
    }

    impl VaultBackend for FaultBackend {
        fn set(&self, key: &str, value: &str) -> Result<(), ClientError> {
            if key.contains("installed-account") {
                let mut failure = self.fail_installed_record.lock().unwrap();
                if *failure {
                    *failure = false;
                    return Err(ClientError::internal(
                        "injected_installed_record_failure",
                        "injected installed record failure",
                    ));
                }
            }
            let rotation = serde_json::from_str::<serde_json::Value>(value)
                .ok()
                .and_then(|value| value.get("rotation").and_then(serde_json::Value::as_u64));
            let mut failure = self.fail_rotation.lock().unwrap();
            if rotation.is_some() && rotation == *failure {
                *failure = None;
                return Err(ClientError::internal(
                    "injected_vault_write_failure",
                    "injected vault write failure",
                ));
            }
            self.values
                .lock()
                .unwrap()
                .insert(key.to_string(), value.to_string());
            Ok(())
        }

        fn get(&self, key: &str) -> Result<Option<String>, ClientError> {
            Ok(self.values.lock().unwrap().get(key).cloned())
        }

        fn delete(&self, key: &str) -> Result<(), ClientError> {
            self.values.lock().unwrap().remove(key);
            Ok(())
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct ObservedRequest {
        key: Option<String>,
        body: String,
    }

    struct RecordingControl {
        user_id: UserId,
        device_id: DeviceId,
        activation_id: DeviceActivationId,
        activation_calls: StdMutex<Vec<ObservedRequest>>,
        login_calls: StdMutex<Vec<ObservedRequest>>,
        refresh_calls: StdMutex<Vec<ObservedRequest>>,
        login_responses: StdMutex<HashMap<String, CreateDeviceSessionResponse>>,
        refresh_responses:
            StdMutex<HashMap<String, control_protocol::account::RefreshSessionResponse>>,
    }

    impl RecordingControl {
        fn new(user_id: UserId, device_id: DeviceId, activation_id: DeviceActivationId) -> Self {
            Self {
                user_id,
                device_id,
                activation_id,
                activation_calls: StdMutex::new(Vec::new()),
                login_calls: StdMutex::new(Vec::new()),
                refresh_calls: StdMutex::new(Vec::new()),
                login_responses: StdMutex::new(HashMap::new()),
                refresh_responses: StdMutex::new(HashMap::new()),
            }
        }
    }

    #[async_trait]
    impl ControlPlane for RecordingControl {
        async fn activate_device(
            &self,
            request: &ConsumeDeviceActivationRequest,
        ) -> Result<CreateDeviceSessionResponse, ClientError> {
            self.activation_calls.lock().unwrap().push(ObservedRequest {
                key: None,
                body: serde_json::to_string(request).unwrap(),
            });
            Ok(response(
                self.user_id,
                self.device_id,
                Some(self.activation_id),
                0,
            ))
        }

        async fn login_device(
            &self,
            request: &CreateSessionRequest,
            idempotency_key: &str,
        ) -> Result<CreateDeviceSessionResponse, ClientError> {
            self.login_calls.lock().unwrap().push(ObservedRequest {
                key: Some(idempotency_key.to_string()),
                body: serde_json::to_string(request).unwrap(),
            });
            let mut responses = self.login_responses.lock().unwrap();
            let sequence = responses.len();
            Ok(responses
                .entry(idempotency_key.to_string())
                .or_insert_with(|| response(self.user_id, self.device_id, None, sequence))
                .clone())
        }

        async fn refresh_session(
            &self,
            request: &RefreshSessionRequest,
            idempotency_key: &str,
        ) -> Result<control_protocol::account::RefreshSessionResponse, ClientError> {
            self.refresh_calls.lock().unwrap().push(ObservedRequest {
                key: Some(idempotency_key.to_string()),
                body: serde_json::to_string(request).unwrap(),
            });
            let mut responses = self.refresh_responses.lock().unwrap();
            let sequence = responses.len() + 1;
            Ok(responses
                .entry(idempotency_key.to_string())
                .or_insert_with(|| {
                    let created = response(self.user_id, self.device_id, None, sequence);
                    control_protocol::account::RefreshSessionResponse {
                        account: created.account,
                        credentials: created.credentials,
                    }
                })
                .clone())
        }

        async fn fetch_profile_bundle(
            &self,
            _access_token: &Secret<String>,
            _etag: Option<&str>,
        ) -> Result<BundleFetch, ClientError> {
            Ok(BundleFetch::NotModified)
        }

        async fn logout_device(
            &self,
            _access_token: &Secret<String>,
            _device_id: DeviceId,
        ) -> Result<(), ClientError> {
            Ok(())
        }
    }

    fn manager(control: Arc<RecordingControl>, vault: CredentialVault) -> AccountSessionManager {
        AccountSessionManager::new(
            control,
            "https://control.example".to_string(),
            vault,
            install_trust(),
        )
        .unwrap()
    }

    fn install_trust() -> AccountInstallTrust {
        AccountInstallTrust {
            controller_instance_id: "b4045a8a-24a4-4d9f-bf89-57ae04cc769b".parse().unwrap(),
            bundle_signing_public_key: URL_SAFE_NO_PAD.encode([23_u8; 32]).parse().unwrap(),
        }
    }

    fn login_input(network_id: NetworkId) -> LoginInput {
        LoginInput {
            network_id,
            account: "member@example.test".to_string(),
            password: Secret::new("correct horse battery staple".to_string()),
        }
    }

    #[tokio::test]
    async fn activation_retry_after_local_commit_failure_reuses_nonce_keys_and_proof() {
        let user_id = UserId::new();
        let device_id = DeviceId::new();
        let activation_id = DeviceActivationId::new();
        let control = Arc::new(RecordingControl::new(user_id, device_id, activation_id));
        let backend = Arc::new(FaultBackend::default());
        backend.fail_next_rotation(1);
        let vault = CredentialVault::new(backend.clone());
        let bootstrap = ActivationBootstrap {
            network_id: NetworkId::new(),
            user_id,
            activation_id,
            expires_at: "2029-01-01T00:00:00Z".parse().unwrap(),
            secret: Secret::new("activation-secret".to_string()),
        };

        assert!(manager(control.clone(), vault.clone())
            .activate(bootstrap.clone(), metadata())
            .await
            .is_err());
        manager(control.clone(), vault)
            .activate(bootstrap, metadata())
            .await
            .unwrap();

        let calls = control.activation_calls.lock().unwrap();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].body, calls[1].body);
    }

    #[tokio::test]
    async fn installed_record_failure_keeps_pending_activation_for_exact_server_replay() {
        let user_id = UserId::new();
        let device_id = DeviceId::new();
        let activation_id = DeviceActivationId::new();
        let control = Arc::new(RecordingControl::new(user_id, device_id, activation_id));
        let backend = Arc::new(FaultBackend::default());
        backend.fail_next_installed_record();
        let vault = CredentialVault::new(backend.clone());
        let bootstrap = ActivationBootstrap {
            network_id: NetworkId::new(),
            user_id,
            activation_id,
            expires_at: "2029-01-01T00:00:00Z".parse().unwrap(),
            secret: Secret::new("activation-secret".to_string()),
        };

        assert!(manager(control.clone(), vault.clone())
            .activate(bootstrap.clone(), metadata())
            .await
            .is_err());
        assert!(vault.load_installed_account().unwrap().is_none());
        assert!(backend
            .values
            .lock()
            .unwrap()
            .keys()
            .any(|key| key.contains(&format!("pending-activation:{activation_id}"))));

        manager(control.clone(), vault.clone())
            .activate(bootstrap, metadata())
            .await
            .unwrap();
        assert!(vault.load_installed_account().unwrap().is_some());
        let calls = control.activation_calls.lock().unwrap();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].body, calls[1].body);
    }

    #[tokio::test]
    async fn login_replays_same_key_and_body_after_response_commit_failure() {
        let user_id = UserId::new();
        let device_id = DeviceId::new();
        let activation_id = DeviceActivationId::new();
        let control = Arc::new(RecordingControl::new(user_id, device_id, activation_id));
        let backend = Arc::new(FaultBackend::default());
        backend.fail_next_rotation(1);
        let vault = CredentialVault::new(backend.clone());
        let network_id = NetworkId::new();

        assert!(manager(control.clone(), vault.clone())
            .login(login_input(network_id), metadata())
            .await
            .is_err());
        manager(control.clone(), vault)
            .login(login_input(network_id), metadata())
            .await
            .unwrap();

        let calls = control.login_calls.lock().unwrap();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0], calls[1]);
        assert!(calls[0].key.as_ref().is_some_and(|key| !key.is_empty()));
        assert!(backend
            .values
            .lock()
            .unwrap()
            .keys()
            .all(|key| !key.contains("pending-login")));
    }

    #[tokio::test]
    async fn refresh_replays_pending_key_after_crash_and_changes_key_next_generation() {
        let user_id = UserId::new();
        let device_id = DeviceId::new();
        let activation_id = DeviceActivationId::new();
        let control = Arc::new(RecordingControl::new(user_id, device_id, activation_id));
        let backend = Arc::new(FaultBackend::default());
        let vault = CredentialVault::new(backend.clone());
        let binding = SessionBinding {
            network_id: NetworkId::new(),
            user_id,
            device_id,
        };
        vault
            .rotate_refresh(
                binding.into(),
                None,
                &RefreshRecord {
                    credential: Secret::new("refresh-0".to_string()),
                    expires_at: "2030-02-01T00:00:00Z".parse().unwrap(),
                    rotation: 1,
                    pending_idempotency_key: None,
                },
            )
            .unwrap();
        backend.fail_next_rotation(2);
        let now: Timestamp = "2030-01-01T00:00:00Z".parse().unwrap();

        let first = manager(control.clone(), vault.clone());
        first.restore(binding).await.unwrap();
        assert!(first.ensure_fresh(now).await.is_err());
        drop(first);

        let replay = manager(control.clone(), vault.clone());
        replay.restore(binding).await.unwrap();
        replay.ensure_fresh(now).await.unwrap();
        drop(replay);

        let next = manager(control.clone(), vault.clone());
        next.restore(binding).await.unwrap();
        next.ensure_fresh(now).await.unwrap();

        let calls = control.refresh_calls.lock().unwrap();
        assert_eq!(calls.len(), 3);
        assert_eq!(calls[0], calls[1]);
        assert_ne!(calls[1].key, calls[2].key);
        assert_ne!(calls[1].body, calls[2].body);
        let stored = vault.load_refresh(binding.into()).unwrap().unwrap();
        assert_eq!(stored.record.rotation, 3);
        assert!(stored.record.pending_idempotency_key.is_none());
    }
}
