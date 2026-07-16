//! Serialized process-local ownership of the single account-first Connect runtime.

use crate::connect_service::{ConnectService, ConnectSnapshot, ConnectTrust};
use crate::control_api::{ControlApi, ControlApiLimits};
use crate::error::ClientError;
use crate::member_setup::{CheckedOutSetup, SetupSessionStore};
use crate::process::XraySupervisor;
use crate::selection::SelectionMode;
use crate::session::{
    AccountInstallTrust, AccountSessionManager, ActivationBootstrap, DeviceMetadata, SessionBinding,
};
use crate::state::ProxyMode;
use crate::vault::{CredentialVault, InstalledAccountRecord};
use control_protocol::id::Timestamp;
use control_protocol::secret::Secret;
use semver::Version;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tauri::{AppHandle, Manager as _};
use time::OffsetDateTime;
use tokio::sync::Mutex;
use uuid::Uuid;

const BUNDLE_SYNC_INTERVAL: Duration = Duration::from_secs(6 * 60 * 60);
const HEALTH_MAINTENANCE_INTERVAL: Duration = Duration::from_secs(30);

struct PendingRuntime {
    setup_session_id: Uuid,
    service: Arc<ConnectService>,
}

#[derive(Default)]
struct RegistryState {
    pending: Option<PendingRuntime>,
    active: Option<Arc<ConnectService>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MaintenanceDue {
    bundle: bool,
    health: bool,
}

#[derive(Default)]
struct MaintenanceState {
    next_bundle: Duration,
    next_health: Duration,
}

impl MaintenanceState {
    fn due(&mut self, now: Duration) -> MaintenanceDue {
        let bundle = now >= self.next_bundle;
        let health = now >= self.next_health;
        if bundle {
            self.next_bundle = now.saturating_add(BUNDLE_SYNC_INTERVAL);
        }
        if health {
            self.next_health = now.saturating_add(HEALTH_MAINTENANCE_INTERVAL);
        }
        MaintenanceDue { bundle, health }
    }
}

/// Single-account runtime registry. Every public operation is serialized by `operations`.
pub struct ConnectRuntimeRegistry {
    operations: Mutex<()>,
    state: Mutex<RegistryState>,
    app_data_dir: PathBuf,
    supervisor: XraySupervisor,
    vault: CredentialVault,
    started_at: Instant,
    maintenance: Mutex<MaintenanceState>,
}

impl ConnectRuntimeRegistry {
    /// Creates an empty process-local registry around the shared Xray supervisor.
    pub fn new(app_data_dir: PathBuf, supervisor: XraySupervisor) -> Result<Self, ClientError> {
        let vault = CredentialVault::preferred(&app_data_dir)?;
        Ok(Self::new_with_vault(app_data_dir, supervisor, vault))
    }

    fn new_with_vault(
        app_data_dir: PathBuf,
        supervisor: XraySupervisor,
        vault: CredentialVault,
    ) -> Self {
        Self {
            operations: Mutex::new(()),
            state: Mutex::new(RegistryState::default()),
            app_data_dir,
            supervisor,
            vault,
            started_at: Instant::now(),
            maintenance: Mutex::new(MaintenanceState::default()),
        }
    }

    /// Activates a setup session, verifies and caches its first bundle, then installs it.
    ///
    /// A failed activation restores the exact setup session. If activation succeeds but bundle
    /// bootstrap fails, the candidate runtime is retained so retry never consumes the activation
    /// again or generates a different device identity.
    pub async fn confirm_setup(
        &self,
        setups: &SetupSessionStore,
        setup_session_id: Uuid,
        metadata: DeviceMetadata,
    ) -> Result<ConnectSnapshot, ClientError> {
        let _operation = self.operations.lock().await;
        self.lazy_restore().await?;
        let checked_out = setups.checkout(setup_session_id)?;
        let existing = {
            let state = self.state.lock().await;
            if state.active.is_some() {
                return restore_error(
                    setups,
                    setup_session_id,
                    checked_out,
                    runtime_error("connect_runtime_already_installed"),
                );
            }
            match &state.pending {
                Some(pending) if pending.setup_session_id == setup_session_id => {
                    Some(Arc::clone(&pending.service))
                }
                Some(_) => {
                    return restore_error(
                        setups,
                        setup_session_id,
                        checked_out,
                        runtime_error("connect_setup_in_progress"),
                    );
                }
                None => None,
            }
        };

        let now = now_timestamp();
        if existing.is_none() && checked_out.expires_at() <= now {
            return Err(runtime_error("member_setup_expired"));
        }

        let service = if let Some(service) = existing {
            service
        } else {
            let material = checked_out.material();
            let service = (|| {
                let control = Arc::new(ControlApi::new(
                    material.controller_origin.clone(),
                    ControlApiLimits::default(),
                )?);
                let vault = self.vault.clone();
                let session = Arc::new(AccountSessionManager::new(
                    control,
                    material.controller_origin.origin().ascii_serialization(),
                    vault.clone(),
                    AccountInstallTrust {
                        controller_instance_id: material.controller_instance_id,
                        bundle_signing_public_key: material.controller_signing_key.clone(),
                    },
                )?);
                Ok::<_, ClientError>(Arc::new(ConnectService::new(
                    session,
                    vault,
                    ConnectTrust {
                        controller_instance_id: material.controller_instance_id,
                        controller_signing_key: material.controller_signing_key.clone(),
                        client_version: Version::parse(env!("CARGO_PKG_VERSION"))
                            .map_err(|_| runtime_error("connect_client_version_invalid"))?,
                    },
                    self.app_data_dir.clone(),
                    self.supervisor.clone(),
                )))
            })();
            let service = match service {
                Ok(service) => service,
                Err(error) => return restore_error(setups, setup_session_id, checked_out, error),
            };
            let activation = ActivationBootstrap {
                network_id: material.network_id,
                user_id: material.user_id,
                activation_id: material.activation_id,
                expires_at: material.expires_at,
                secret: Secret::new(material.activation_secret.as_str().to_owned()),
            };
            if let Err(error) = service.activate(activation, metadata).await {
                return restore_error(setups, setup_session_id, checked_out, error);
            }
            self.state.lock().await.pending = Some(PendingRuntime {
                setup_session_id,
                service: Arc::clone(&service),
            });
            service
        };

        let snapshot = match service.bootstrap_bundle(now).await {
            Ok(snapshot) => snapshot,
            Err(error) => return restore_error(setups, setup_session_id, checked_out, error),
        };
        let mut state = self.state.lock().await;
        let pending = state
            .pending
            .take()
            .ok_or_else(|| runtime_error("connect_runtime_state_invalid"))?;
        if pending.setup_session_id != setup_session_id {
            state.pending = Some(pending);
            drop(state);
            return restore_error(
                setups,
                setup_session_id,
                checked_out,
                runtime_error("connect_runtime_state_invalid"),
            );
        }
        state.active = Some(pending.service);
        drop(checked_out);
        drop(state);

        Ok(snapshot)
    }

    /// Cancels setup and removes a partially activated local runtime before dropping its bearer.
    pub async fn cancel_setup(
        &self,
        setups: &SetupSessionStore,
        setup_session_id: Uuid,
    ) -> Result<bool, ClientError> {
        let _operation = self.operations.lock().await;
        self.lazy_restore().await?;
        let candidate = {
            let state = self.state.lock().await;
            state
                .pending
                .as_ref()
                .filter(|pending| pending.setup_session_id == setup_session_id)
                .map(|pending| Arc::clone(&pending.service))
        };
        let removed_runtime = if let Some(candidate) = candidate {
            candidate.abort_setup().await?;
            let mut state = self.state.lock().await;
            if state
                .pending
                .as_ref()
                .is_some_and(|pending| pending.setup_session_id == setup_session_id)
            {
                state.pending = None;
                true
            } else {
                false
            }
        } else {
            false
        };
        Ok(setups.cancel(setup_session_id)? || removed_runtime)
    }

    /// Returns the installed runtime's secret-free renderer snapshot.
    pub async fn snapshot(&self) -> Result<Option<ConnectSnapshot>, ClientError> {
        let _operation = self.operations.lock().await;
        self.lazy_restore().await?;
        match self.active().await {
            Ok(service) => service.snapshot().await.map(Some),
            Err(error) if error.code == "connect_runtime_missing" => Ok(None),
            Err(error) => Err(error),
        }
    }

    /// Refreshes and applies the current verified bundle without accepting renderer runtime mode.
    pub async fn refresh_bundle(&self, app: &AppHandle) -> Result<ConnectSnapshot, ClientError> {
        let _operation = self.operations.lock().await;
        self.lazy_restore().await?;
        self.active()
            .await?
            .refresh_bundle(app, now_timestamp(), self.started_at.elapsed())
            .await
    }

    /// Runs one bounded probe pass against active verified-bundle endpoints.
    pub async fn probe_nodes(&self) -> Result<ConnectSnapshot, ClientError> {
        let _operation = self.operations.lock().await;
        self.lazy_restore().await?;
        self.active().await?.probe_nodes().await
    }

    /// Updates the selection policy without exposing bundle credentials.
    pub async fn set_selection(&self, mode: SelectionMode) -> Result<ConnectSnapshot, ClientError> {
        let _operation = self.operations.lock().await;
        self.lazy_restore().await?;
        self.active().await?.set_selection_mode(mode).await
    }

    /// Selects and starts the account-owned Xray runtime.
    pub async fn connect(
        &self,
        app: &AppHandle,
        proxy_mode: ProxyMode,
    ) -> Result<ConnectSnapshot, ClientError> {
        let _operation = self.operations.lock().await;
        self.lazy_restore().await?;
        self.active()
            .await?
            .select_and_connect(app, now_timestamp(), self.started_at.elapsed(), proxy_mode)
            .await
    }

    /// Stops the account-owned Xray runtime.
    pub async fn stop(&self) -> Result<ConnectSnapshot, ClientError> {
        let _operation = self.operations.lock().await;
        self.lazy_restore().await?;
        self.active().await?.stop().await
    }

    /// Revokes and removes the installed account runtime.
    pub async fn logout(&self) -> Result<ConnectSnapshot, ClientError> {
        let _operation = self.operations.lock().await;
        self.lazy_restore().await?;
        let service = self.active().await?;
        let result = service.logout(now_timestamp()).await;
        self.state.lock().await.active = None;
        result
    }

    /// Runs due background work at caller-supplied clocks for deterministic scheduling tests.
    pub(crate) async fn maintenance_at(
        &self,
        app: &AppHandle,
        wall_now: Timestamp,
        monotonic_now: Duration,
    ) -> Result<Option<ConnectSnapshot>, ClientError> {
        let _operation = self.operations.lock().await;
        let due = self.maintenance.lock().await.due(monotonic_now);
        if !due.bundle && !due.health {
            return Ok(None);
        }
        self.lazy_restore().await?;
        let service = match self.active().await {
            Ok(service) => service,
            Err(error) if error.code == "connect_runtime_missing" => return Ok(None),
            Err(error) => return Err(error),
        };
        let mut latest = None;
        let mut first_error = None;
        if due.bundle {
            match service.refresh_bundle(app, wall_now, monotonic_now).await {
                Ok(snapshot) => latest = Some(snapshot),
                Err(error) => first_error = Some(error),
            }
        }
        if due.health {
            match service
                .maintain_connection(app, wall_now, monotonic_now)
                .await
            {
                Ok(snapshot) => latest = Some(snapshot),
                Err(error) if first_error.is_none() => first_error = Some(error),
                Err(_) => {}
            }
        }
        if let Some(error) = first_error {
            return Err(error);
        }
        Ok(latest)
    }

    async fn active(&self) -> Result<Arc<ConnectService>, ClientError> {
        self.state
            .lock()
            .await
            .active
            .as_ref()
            .map(Arc::clone)
            .ok_or_else(|| runtime_error("connect_runtime_missing"))
    }

    async fn lazy_restore(&self) -> Result<(), ClientError> {
        {
            let state = self.state.lock().await;
            if state.active.is_some() || state.pending.is_some() {
                return Ok(());
            }
        }
        let vault = self.vault.clone();
        let record = tokio::task::spawn_blocking(move || vault.load_installed_account())
            .await
            .map_err(|_| runtime_error("connect_installed_account_load_failed"))??;
        let Some(record) = record else {
            return Ok(());
        };
        let service = self.service_from_record(&record)?;
        service
            .restore(
                SessionBinding {
                    network_id: record.network_id,
                    user_id: record.user_id,
                    device_id: record.device_id,
                },
                now_timestamp(),
            )
            .await?;
        let mut state = self.state.lock().await;
        if state.active.is_none() && state.pending.is_none() {
            state.active = Some(service);
        }
        Ok(())
    }

    fn service_from_record(
        &self,
        record: &InstalledAccountRecord,
    ) -> Result<Arc<ConnectService>, ClientError> {
        let origin = url::Url::parse(&record.controller_origin)
            .map_err(|_| runtime_error("connect_installed_account_invalid"))?;
        let control = Arc::new(ControlApi::new(origin, ControlApiLimits::default())?);
        let session = Arc::new(AccountSessionManager::new(
            control,
            record.controller_origin.clone(),
            self.vault.clone(),
            AccountInstallTrust {
                controller_instance_id: record.controller_instance_id,
                bundle_signing_public_key: record.bundle_signing_public_key.clone(),
            },
        )?);
        Ok(Arc::new(ConnectService::new(
            session,
            self.vault.clone(),
            ConnectTrust {
                controller_instance_id: record.controller_instance_id,
                controller_signing_key: record.bundle_signing_public_key.clone(),
                client_version: Version::parse(env!("CARGO_PKG_VERSION"))
                    .map_err(|_| runtime_error("connect_client_version_invalid"))?,
            },
            self.app_data_dir.clone(),
            self.supervisor.clone(),
        )))
    }
}

/// Runs serialized maintenance until the Tauri runtime shuts down.
pub(crate) async fn run_background_maintenance(app: AppHandle) {
    let mut timer = tokio::time::interval(HEALTH_MAINTENANCE_INTERVAL);
    timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        timer.tick().await;
        let runtime = app.state::<ConnectRuntimeRegistry>();
        let _ = runtime
            .maintenance_at(&app, now_timestamp(), runtime.started_at.elapsed())
            .await;
    }
}

fn restore_error<T>(
    setups: &SetupSessionStore,
    setup_session_id: Uuid,
    checked_out: CheckedOutSetup,
    operation_error: ClientError,
) -> Result<T, ClientError> {
    setups.restore(setup_session_id, checked_out)?;
    Err(operation_error)
}

fn now_timestamp() -> Timestamp {
    Timestamp::from_datetime(OffsetDateTime::now_utc())
}

fn runtime_error(code: &str) -> ClientError {
    ClientError::internal(code, "The account runtime operation failed.")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::VaultBackend;
    use control_protocol::account::{
        AccountSummary, CreateAccountRequest, CreateDeviceActivationRequest,
    };
    use control_protocol::idempotency::IDEMPOTENCY_KEY_HEADER;
    use control_server::auth::BootstrapTokenVerifier;
    use control_server::{build_router, AppState, Database};
    use reqwest::header::{AUTHORIZATION, CONTENT_TYPE};
    use serde_json::Value;
    use std::collections::HashMap;
    use std::sync::Mutex as StdMutex;
    use std::time::Duration;
    use tokio::net::TcpListener;

    const ADMIN_TOKEN: &str = "client-integration-bootstrap-token-with-enough-entropy";

    #[derive(Default)]
    struct MemoryBackend(StdMutex<HashMap<String, String>>);

    impl VaultBackend for MemoryBackend {
        fn set(&self, account: &str, value: &str) -> Result<(), ClientError> {
            self.0
                .lock()
                .unwrap()
                .insert(account.to_string(), value.to_string());
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

    #[test]
    fn maintenance_cadence_uses_fake_monotonic_time_without_catch_up_bursts() {
        let mut state = MaintenanceState::default();
        assert_eq!(
            state.due(Duration::ZERO),
            MaintenanceDue {
                bundle: true,
                health: true
            }
        );
        assert_eq!(
            state.due(Duration::from_secs(29)),
            MaintenanceDue {
                bundle: false,
                health: false
            }
        );
        assert_eq!(
            state.due(Duration::from_secs(30)),
            MaintenanceDue {
                bundle: false,
                health: true
            }
        );
        assert_eq!(
            state.due(BUNDLE_SYNC_INTERVAL),
            MaintenanceDue {
                bundle: true,
                health: true
            }
        );
        assert_eq!(
            state.due(BUNDLE_SYNC_INTERVAL + Duration::from_secs(1)),
            MaintenanceDue {
                bundle: false,
                health: false
            }
        );
    }

    #[tokio::test]
    async fn real_loopback_setup_and_empty_bundle_restore_offline_after_registry_rebuild() {
        let directory = tempfile::tempdir().unwrap();
        let database =
            Database::open(&directory.path().join("control.sqlite3"), "Test network").unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let state = AppState::new(
            database,
            BootstrapTokenVerifier::new(ADMIN_TOKEN).unwrap(),
            origin.clone(),
            Duration::from_secs(10),
        );
        let server = tokio::spawn(async move {
            axum::serve(listener, build_router(state)).await.unwrap();
        });
        let client = reqwest::Client::new();
        let account = client
            .post(format!("{origin}/v1/admin/accounts"))
            .header(AUTHORIZATION, format!("Bearer {ADMIN_TOKEN}"))
            .header(CONTENT_TYPE, "application/json")
            .header(IDEMPOTENCY_KEY_HEADER, Uuid::new_v4().to_string())
            .json(&CreateAccountRequest {
                display_name: "Loopback member".to_string(),
            })
            .send()
            .await
            .unwrap();
        assert_eq!(account.status(), reqwest::StatusCode::CREATED);
        let account = account.json::<AccountSummary>().await.unwrap();
        let delivery = client
            .post(format!(
                "{origin}/v1/admin/accounts/{}/device-activations",
                account.account.user_id
            ))
            .header(AUTHORIZATION, format!("Bearer {ADMIN_TOKEN}"))
            .header(CONTENT_TYPE, "application/json")
            .header(IDEMPOTENCY_KEY_HEADER, Uuid::new_v4().to_string())
            .json(&CreateDeviceActivationRequest::default())
            .send()
            .await
            .unwrap();
        assert_eq!(delivery.status(), reqwest::StatusCode::CREATED);
        let delivery = delivery.json::<Value>().await.unwrap();
        let setup_link = delivery["setupLink"].as_str().unwrap();

        let setups = SetupSessionStore::new();
        let setup = setups.begin(setup_link).unwrap();
        let backend = Arc::new(MemoryBackend::default());
        let vault = CredentialVault::new(backend);
        let app_data = directory.path().join("client");
        let supervisor = XraySupervisor::new(app_data.clone()).unwrap();
        let registry =
            ConnectRuntimeRegistry::new_with_vault(app_data.clone(), supervisor, vault.clone());
        let snapshot = registry
            .confirm_setup(
                &setups,
                setup.session_id,
                DeviceMetadata {
                    display_name: "Integration laptop".to_string(),
                    client_version: env!("CARGO_PKG_VERSION").to_string(),
                    platform: "test-loopback".to_string(),
                },
            )
            .await
            .unwrap();
        assert!(snapshot
            .bundle
            .as_ref()
            .is_some_and(|bundle| bundle.nodes.is_empty()));
        assert!(vault.load_installed_account().unwrap().is_some());
        drop(registry);

        server.abort();
        let _ = server.await;

        let rebuilt = ConnectRuntimeRegistry::new_with_vault(
            app_data.clone(),
            XraySupervisor::new(app_data).unwrap(),
            vault,
        );
        let restored = rebuilt.snapshot().await.unwrap().unwrap();
        assert!(restored
            .bundle
            .as_ref()
            .is_some_and(|bundle| bundle.nodes.is_empty()));
        assert!(matches!(
            restored.session.phase,
            crate::session::AccountSessionPhase::RefreshRequired
        ));
    }
}
