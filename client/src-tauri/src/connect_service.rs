//! Account-first orchestration across sessions, bundles, selection, and the Xray supervisor.

use crate::bundle::{BundleCache, BundleTrust, BundleVerifier, VerifiedBundle};
use crate::control_api::BundleFetch;
use crate::error::ClientError;
use crate::process::XraySupervisor;
use crate::selection::{
    NodeSelector, ProbeOutcome, SelectionDecision, SelectionMode, SelectionReason,
};
use crate::session::{
    AccountSessionManager, AccountSessionSnapshot, ActivationBootstrap, DeviceMetadata, LoginInput,
    SessionBinding,
};
use crate::state::{ClientState, ProxyMode};
use crate::vault::CredentialVault;
use async_trait::async_trait;
use control_protocol::account::ProfileDescriptor;
use control_protocol::crypto::Ed25519PublicKey;
use control_protocol::id::{ControllerInstanceId, NodeId, Timestamp};
use control_protocol::node::EndpointMode;
use futures_util::{stream, StreamExt as _};
use semver::Version;
use serde::Serialize;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tauri::AppHandle;
use tokio::net::TcpStream;
use tokio::sync::Mutex;

const NODE_PROBE_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_CONCURRENT_NODE_PROBES: usize = 8;

#[derive(Clone)]
struct ProbeTarget {
    node_id: NodeId,
    address: String,
    port: u16,
}

#[async_trait]
trait NodeProbeExecutor: Send + Sync {
    async fn probe(&self, target: &ProbeTarget) -> ProbeOutcome;
}

struct TcpNodeProbe;

#[async_trait]
impl NodeProbeExecutor for TcpNodeProbe {
    async fn probe(&self, target: &ProbeTarget) -> ProbeOutcome {
        let started = Instant::now();
        match tokio::time::timeout(
            NODE_PROBE_TIMEOUT,
            TcpStream::connect((target.address.as_str(), target.port)),
        )
        .await
        {
            Ok(Ok(stream)) => {
                drop(stream);
                ProbeOutcome::Healthy {
                    latency: started.elapsed(),
                }
            }
            Ok(Err(_)) | Err(_) => ProbeOutcome::Failed,
        }
    }
}

/// Safe node metadata derived only from a verified manifest.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SafeNodeSnapshot {
    /// Stable node identity.
    pub node_id: NodeId,
    /// Safe controller-provided label.
    pub display_name: String,
    /// Optional safe region.
    pub region: Option<String>,
    /// Direct or opaque relay path.
    pub endpoint_mode: EndpointMode,
    /// Signed deterministic preference.
    pub priority: u16,
}

impl From<&ProfileDescriptor> for SafeNodeSnapshot {
    fn from(value: &ProfileDescriptor) -> Self {
        Self {
            node_id: value.node_id,
            display_name: value.display_name.clone(),
            region: value.region.clone(),
            endpoint_mode: value.endpoint_mode,
            priority: value.priority,
        }
    }
}

/// Safe summary of the active verified bundle.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SafeBundleSnapshot {
    /// Monotonic per-device generation.
    pub generation: i64,
    /// Recommended online refresh deadline.
    pub refresh_after: Timestamp,
    /// Hard offline use deadline.
    pub offline_expires_at: Timestamp,
    /// Complete safe assigned node list.
    pub nodes: Vec<SafeNodeSnapshot>,
}

/// Renderer-safe aggregate. It contains no bearer, private key, bundle bytes, or node credential.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectSnapshot {
    /// Account session lifecycle without credentials.
    pub session: AccountSessionSnapshot,
    /// Active verified bundle metadata.
    pub bundle: Option<SafeBundleSnapshot>,
    /// Current user selection policy.
    pub selection_mode: SelectionMode,
    /// Current selected node.
    pub selected_node_id: Option<NodeId>,
    /// Last deterministic selection reason.
    pub selection_reason: Option<SelectionReason>,
    /// Existing Xray supervisor state.
    pub runtime: ClientState,
}

struct ConnectInner {
    bundle: Option<VerifiedBundle>,
    selector: Option<NodeSelector>,
    mode: SelectionMode,
    last_reason: Option<SelectionReason>,
}

/// Controller trust values that remain fixed for the running installation.
#[derive(Clone)]
pub struct ConnectTrust {
    /// Controller epoch established through trusted onboarding.
    pub controller_instance_id: ControllerInstanceId,
    /// Pinned bundle-signing public key.
    pub controller_signing_key: Ed25519PublicKey,
    /// Running Connect version.
    pub client_version: Version,
}

/// Serialized account-first backend facade.
///
/// Every mutating operation holds `operations`, so refresh-token rotation, bundle activation, and
/// process switching cannot race one another.
pub struct ConnectService {
    operations: Mutex<()>,
    inner: Mutex<ConnectInner>,
    session: Arc<AccountSessionManager>,
    vault: CredentialVault,
    trust: ConnectTrust,
    app_data_dir: PathBuf,
    supervisor: XraySupervisor,
    probe: Arc<dyn NodeProbeExecutor>,
}

impl ConnectService {
    /// Creates an account-first orchestrator around the existing Xray supervisor.
    #[must_use]
    pub fn new(
        session: Arc<AccountSessionManager>,
        vault: CredentialVault,
        trust: ConnectTrust,
        app_data_dir: PathBuf,
        supervisor: XraySupervisor,
    ) -> Self {
        Self::new_with_probe(
            session,
            vault,
            trust,
            app_data_dir,
            supervisor,
            Arc::new(TcpNodeProbe),
        )
    }

    fn new_with_probe(
        session: Arc<AccountSessionManager>,
        vault: CredentialVault,
        trust: ConnectTrust,
        app_data_dir: PathBuf,
        supervisor: XraySupervisor,
        probe: Arc<dyn NodeProbeExecutor>,
    ) -> Self {
        Self {
            operations: Mutex::new(()),
            inner: Mutex::new(ConnectInner {
                bundle: None,
                selector: None,
                mode: SelectionMode::Automatic,
                last_reason: None,
            }),
            session,
            vault,
            trust,
            app_data_dir,
            supervisor,
            probe,
        }
    }

    /// Activates a new account device under the same mutation gate as later refreshes.
    pub async fn activate(
        &self,
        bootstrap: ActivationBootstrap,
        metadata: DeviceMetadata,
    ) -> Result<ConnectSnapshot, ClientError> {
        let _operation = self.operations.lock().await;
        self.session.activate(bootstrap, metadata).await?;
        self.snapshot_locked().await
    }

    /// Creates an optional password-backed account device session.
    pub async fn login(
        &self,
        input: LoginInput,
        metadata: DeviceMetadata,
    ) -> Result<ConnectSnapshot, ClientError> {
        let _operation = self.operations.lock().await;
        self.session.login(input, metadata).await?;
        self.snapshot_locked().await
    }

    /// Restores a refresh-backed session and the newest completely verified cache generation.
    pub async fn restore(
        &self,
        binding: SessionBinding,
        now: Timestamp,
    ) -> Result<ConnectSnapshot, ClientError> {
        let _operation = self.operations.lock().await;
        self.session.restore(binding).await?;
        let verifier = self.verifier(binding);
        let cache = BundleCache::new(self.app_data_dir.clone(), binding)?;
        let recovered = tokio::task::spawn_blocking(move || cache.recover(&verifier, now))
            .await
            .map_err(|_| connect_error("connect_cache_recovery_failed"))??;
        if let Some(bundle) = recovered {
            self.activate_verified(bundle).await?;
        }
        self.snapshot_locked().await
    }

    /// Coalesces access refresh without changing bundle or node state.
    pub async fn refresh_session(&self, now: Timestamp) -> Result<ConnectSnapshot, ClientError> {
        let _operation = self.operations.lock().await;
        self.session.ensure_fresh(now).await?;
        self.snapshot_locked().await
    }

    /// Fetches, verifies, caches, reconciles, and applies one bundle transactionally.
    pub async fn refresh_bundle(
        &self,
        app: &AppHandle,
        now: Timestamp,
        monotonic_now: Duration,
    ) -> Result<ConnectSnapshot, ClientError> {
        let _operation = self.operations.lock().await;
        let runtime_before = self.supervisor.snapshot()?;
        let modified = match self.refresh_bundle_locked(now).await {
            Ok(modified) => modified,
            Err(error) => {
                self.stop_if_bundle_expired(now).await?;
                return Err(error);
            }
        };
        if let Some((mode, force_restart)) = refresh_recovery(&runtime_before, modified) {
            if modified {
                self.probe_nodes_locked().await?;
            }
            self.apply_selection(app, monotonic_now, mode, force_restart, true)
                .await?;
        }
        self.snapshot_locked().await
    }

    /// Fetches and installs the first verified bundle without starting Xray.
    pub async fn bootstrap_bundle(&self, now: Timestamp) -> Result<ConnectSnapshot, ClientError> {
        let _operation = self.operations.lock().await;
        self.refresh_bundle_locked(now).await?;
        let snapshot = self.snapshot_locked().await?;
        if snapshot.bundle.is_none() {
            return Err(connect_error("connect_bundle_missing"));
        }
        Ok(snapshot)
    }

    async fn refresh_bundle_locked(&self, now: Timestamp) -> Result<bool, ClientError> {
        let session = self.session.snapshot().await;
        let binding = session
            .binding
            .ok_or_else(|| connect_error("connect_session_missing"))?;
        let etag = self
            .inner
            .lock()
            .await
            .bundle
            .as_ref()
            .and_then(VerifiedBundle::etag)
            .map(str::to_owned);
        let modified = match self.session.fetch_bundle(now, etag.as_deref()).await? {
            BundleFetch::NotModified => false,
            BundleFetch::Modified { bundle, etag } => {
                let verifier = self.verifier(binding);
                let verified =
                    tokio::task::spawn_blocking(move || verifier.verify(*bundle, etag, now))
                        .await
                        .map_err(|_| connect_error("connect_bundle_verify_failed"))??;
                let cache = BundleCache::new(self.app_data_dir.clone(), binding)?;
                let artifact = verified.signed().clone();
                let artifact_etag = verified.etag().map(str::to_owned);
                let cache_verifier = self.verifier(binding);
                tokio::task::spawn_blocking(move || {
                    // Re-verification inside this blocking boundary keeps cache writes tied to the
                    // exact authenticated envelope rather than a separately reconstructed view.
                    let verified = cache_verifier.verify(artifact, artifact_etag, now)?;
                    cache.install(&verified)
                })
                .await
                .map_err(|_| connect_error("connect_bundle_install_failed"))??;
                self.activate_verified(verified).await?;
                true
            }
        };
        Ok(modified)
    }

    /// Changes manual/automatic/pinned policy without exposing credentials.
    pub async fn set_selection_mode(
        &self,
        mode: SelectionMode,
    ) -> Result<ConnectSnapshot, ClientError> {
        let _operation = self.operations.lock().await;
        let mut inner = self.inner.lock().await;
        if let Some(selector) = inner.selector.as_mut() {
            selector.set_mode(mode.clone())?;
        }
        inner.mode = mode;
        drop(inner);
        self.snapshot_locked().await
    }

    /// Records one bounded endpoint probe without affecting unrelated nodes.
    pub async fn observe_probe(&self, node_id: NodeId, outcome: ProbeOutcome) {
        let _operation = self.operations.lock().await;
        if let Some(selector) = self.inner.lock().await.selector.as_mut() {
            selector.observe(node_id, outcome);
        }
    }

    /// Probes only endpoint targets derived from the active verified bundle.
    pub async fn probe_nodes(&self) -> Result<ConnectSnapshot, ClientError> {
        let _operation = self.operations.lock().await;
        self.probe_nodes_locked().await?;
        self.snapshot_locked().await
    }

    /// Evaluates and applies a manual, automatic, or pinned switch through the existing supervisor.
    pub async fn select_and_connect(
        &self,
        app: &AppHandle,
        wall_now: Timestamp,
        monotonic_now: Duration,
        proxy_mode: ProxyMode,
    ) -> Result<ConnectSnapshot, ClientError> {
        let _operation = self.operations.lock().await;
        if self.stop_if_bundle_expired(wall_now).await? {
            return Err(connect_error("connect_bundle_offline_expired"));
        }
        self.probe_nodes_locked().await?;
        self.apply_selection(app, monotonic_now, proxy_mode, false, true)
            .await?;
        self.snapshot_locked().await
    }

    /// Probes and maintains an already active runtime without starting a disconnected one.
    pub async fn maintain_connection(
        &self,
        app: &AppHandle,
        wall_now: Timestamp,
        monotonic_now: Duration,
    ) -> Result<ConnectSnapshot, ClientError> {
        let _operation = self.operations.lock().await;
        if self.stop_if_bundle_expired(wall_now).await? {
            return Err(connect_error("connect_bundle_offline_expired"));
        }
        let runtime = self.supervisor.snapshot()?;
        let Some((mode, force_restart)) = active_recovery(&runtime) else {
            return self.snapshot_locked().await;
        };
        self.probe_nodes_locked().await?;
        self.apply_selection(app, monotonic_now, mode, force_restart, false)
            .await?;
        self.snapshot_locked().await
    }

    /// Revokes the account session, stops Xray, purges cache, and removes keyring material.
    pub async fn logout(&self, now: Timestamp) -> Result<ConnectSnapshot, ClientError> {
        let _operation = self.operations.lock().await;
        let binding = self
            .session
            .snapshot()
            .await
            .binding
            .ok_or_else(|| connect_error("connect_session_missing"))?;
        self.supervisor.stop().await?;
        let remote_logout = match self.session.ensure_fresh(now).await {
            Ok(_) => self.session.logout().await,
            Err(error) => Err(error),
        };
        if remote_logout.is_err() {
            self.session.discard_local().await?;
        }
        let cache = BundleCache::new(self.app_data_dir.clone(), binding)?;
        tokio::task::spawn_blocking(move || cache.purge())
            .await
            .map_err(|_| connect_error("connect_cache_purge_failed"))??;
        let mut inner = self.inner.lock().await;
        inner.bundle = None;
        inner.selector = None;
        inner.last_reason = None;
        drop(inner);
        let snapshot = self.snapshot_locked().await?;
        remote_logout
            .map(|_| snapshot)
            .map_err(|_| connect_error("connect_remote_logout_unconfirmed"))
    }

    /// Returns the only renderer-facing aggregate view.
    pub async fn snapshot(&self) -> Result<ConnectSnapshot, ClientError> {
        let _operation = self.operations.lock().await;
        self.snapshot_locked().await
    }

    /// Stops the account-owned Xray process without changing account or selection state.
    pub async fn stop(&self) -> Result<ConnectSnapshot, ClientError> {
        let _operation = self.operations.lock().await;
        self.supervisor.stop().await?;
        self.snapshot_locked().await
    }

    /// Aborts a not-yet-installed setup runtime and removes all local account material.
    pub(crate) async fn abort_setup(&self) -> Result<(), ClientError> {
        let _operation = self.operations.lock().await;
        let binding = self.session.snapshot().await.binding;
        self.supervisor.stop().await?;
        if let Some(binding) = binding {
            let cache = BundleCache::new(self.app_data_dir.clone(), binding)?;
            tokio::task::spawn_blocking(move || cache.purge())
                .await
                .map_err(|_| connect_error("connect_cache_purge_failed"))??;
        }
        self.session.discard_local().await?;
        let mut inner = self.inner.lock().await;
        inner.bundle = None;
        inner.selector = None;
        inner.last_reason = None;
        Ok(())
    }

    fn verifier(&self, binding: SessionBinding) -> BundleVerifier {
        BundleVerifier::new(
            BundleTrust {
                binding,
                controller_instance_id: self.trust.controller_instance_id,
                controller_signing_key: self.trust.controller_signing_key.clone(),
                client_version: self.trust.client_version.clone(),
            },
            self.vault.clone(),
        )
    }

    async fn activate_verified(&self, bundle: VerifiedBundle) -> Result<(), ClientError> {
        let manifest = &bundle.signed().manifest;
        let mut inner = self.inner.lock().await;
        if let Some(selector) = inner.selector.as_mut() {
            selector.reconcile_bundle(&manifest.selection_hints, &manifest.profiles)?;
        } else {
            inner.selector = Some(NodeSelector::new(
                inner.mode.clone(),
                &manifest.selection_hints,
                &manifest.profiles,
            )?);
        }
        inner.bundle = Some(bundle);
        Ok(())
    }

    async fn probe_nodes_locked(&self) -> Result<(), ClientError> {
        let targets = {
            let inner = self.inner.lock().await;
            let bundle = inner
                .bundle
                .as_ref()
                .ok_or_else(|| connect_error("connect_bundle_missing"))?;
            bundle
                .profiles()
                .iter()
                .map(|(node_id, profile)| ProbeTarget {
                    node_id: *node_id,
                    address: profile.server_address.clone(),
                    port: profile.server_port,
                })
                .collect::<Vec<_>>()
        };
        let outcomes = run_bounded_probes(Arc::clone(&self.probe), targets).await;
        let mut inner = self.inner.lock().await;
        let selector = inner
            .selector
            .as_mut()
            .ok_or_else(|| connect_error("connect_bundle_missing"))?;
        for (node_id, outcome) in outcomes {
            selector.observe(node_id, outcome);
        }
        Ok(())
    }

    async fn apply_selection(
        &self,
        app: &AppHandle,
        now: Duration,
        proxy_mode: ProxyMode,
        force_restart: bool,
        stop_when_unavailable: bool,
    ) -> Result<SelectionDecision, ClientError> {
        let (decision, profile) = {
            let mut inner = self.inner.lock().await;
            let selector = inner
                .selector
                .as_mut()
                .ok_or_else(|| connect_error("connect_bundle_missing"))?;
            let decision = selector.select(now);
            inner.last_reason = Some(decision.reason);
            let profile = decision
                .node_id
                .and_then(|node_id| inner.bundle.as_ref()?.profiles().get(&node_id).cloned());
            (decision, profile)
        };
        if decision.node_id.is_none() {
            if stop_when_unavailable {
                self.supervisor.stop().await?;
            }
            return Ok(decision);
        }
        if decision.changed || force_restart {
            self.supervisor.stop().await?;
            let profile = profile.ok_or_else(|| connect_error("connect_profile_missing"))?;
            self.supervisor
                .start(
                    app,
                    decision.node_id.expect("checked selected node").to_string(),
                    profile,
                    proxy_mode,
                )
                .await?;
        }
        Ok(decision)
    }

    async fn stop_if_bundle_expired(&self, now: Timestamp) -> Result<bool, ClientError> {
        let expired = self
            .inner
            .lock()
            .await
            .bundle
            .as_ref()
            .map(|bundle| bundle.signed().manifest.offline_expires_at)
            .is_some_and(|deadline| offline_deadline_elapsed(deadline, now));
        if expired {
            self.supervisor.stop().await?;
        }
        Ok(expired)
    }

    async fn snapshot_locked(&self) -> Result<ConnectSnapshot, ClientError> {
        let session = self.session.snapshot().await;
        let inner = self.inner.lock().await;
        let bundle = inner.bundle.as_ref().map(|bundle| {
            let manifest = &bundle.signed().manifest;
            SafeBundleSnapshot {
                generation: manifest.generation.get(),
                refresh_after: manifest.refresh_after,
                offline_expires_at: manifest.offline_expires_at,
                nodes: manifest
                    .profiles
                    .iter()
                    .map(SafeNodeSnapshot::from)
                    .collect(),
            }
        });
        Ok(ConnectSnapshot {
            session,
            bundle,
            selection_mode: inner.mode.clone(),
            selected_node_id: inner.selector.as_ref().and_then(NodeSelector::active),
            selection_reason: inner.last_reason,
            runtime: self.supervisor.snapshot()?,
        })
    }
}

async fn run_bounded_probes(
    probe: Arc<dyn NodeProbeExecutor>,
    targets: Vec<ProbeTarget>,
) -> Vec<(NodeId, ProbeOutcome)> {
    stream::iter(targets)
        .map(|target| {
            let probe = Arc::clone(&probe);
            async move {
                let node_id = target.node_id;
                (node_id, probe.probe(&target).await)
            }
        })
        .buffer_unordered(MAX_CONCURRENT_NODE_PROBES)
        .collect()
        .await
}

fn active_recovery(runtime: &ClientState) -> Option<(ProxyMode, bool)> {
    runtime.active_profile_id.as_ref()?;
    match runtime.phase {
        crate::state::ClientPhase::Connected => runtime.mode.map(|mode| (mode, false)),
        crate::state::ClientPhase::Failed => runtime.mode.map(|mode| (mode, true)),
        crate::state::ClientPhase::Disconnected
        | crate::state::ClientPhase::Starting
        | crate::state::ClientPhase::Stopping => None,
    }
}

fn refresh_recovery(runtime: &ClientState, modified: bool) -> Option<(ProxyMode, bool)> {
    let (mode, failed) = active_recovery(runtime)?;
    (modified || failed).then_some((mode, true))
}

fn offline_deadline_elapsed(deadline: Timestamp, now: Timestamp) -> bool {
    deadline.as_datetime() <= now.as_datetime()
}

fn connect_error(code: &str) -> ClientError {
    ClientError::internal(code, "The account connection operation failed.")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control_api::{BundleFetch, ControlPlane};
    use crate::vault::VaultBackend;
    use async_trait::async_trait;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use control_protocol::account::{
        ConsumeDeviceActivationRequest, CreateDeviceSessionResponse, CreateSessionRequest,
        RefreshSessionRequest, RefreshSessionResponse, SelectionHints,
    };
    use control_protocol::id::{DeviceId, NodeId};
    use control_protocol::node::EndpointMode;
    use control_protocol::secret::Secret;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct UnusedControl;

    struct StaticProbe(HashMap<NodeId, ProbeOutcome>);

    #[async_trait]
    impl NodeProbeExecutor for StaticProbe {
        async fn probe(&self, target: &ProbeTarget) -> ProbeOutcome {
            self.0[&target.node_id]
        }
    }

    struct CountingProbe {
        active: AtomicUsize,
        maximum: AtomicUsize,
    }

    #[async_trait]
    impl NodeProbeExecutor for CountingProbe {
        async fn probe(&self, _target: &ProbeTarget) -> ProbeOutcome {
            let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
            self.maximum.fetch_max(active, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(5)).await;
            self.active.fetch_sub(1, Ordering::SeqCst);
            ProbeOutcome::Healthy {
                latency: Duration::from_millis(5),
            }
        }
    }

    #[async_trait]
    impl ControlPlane for UnusedControl {
        async fn activate_device(
            &self,
            _request: &ConsumeDeviceActivationRequest,
        ) -> Result<CreateDeviceSessionResponse, ClientError> {
            unreachable!()
        }

        async fn login_device(
            &self,
            _request: &CreateSessionRequest,
            _idempotency_key: &str,
        ) -> Result<CreateDeviceSessionResponse, ClientError> {
            unreachable!()
        }

        async fn refresh_session(
            &self,
            _request: &RefreshSessionRequest,
            _idempotency_key: &str,
        ) -> Result<RefreshSessionResponse, ClientError> {
            unreachable!()
        }

        async fn fetch_profile_bundle(
            &self,
            _access_token: &Secret<String>,
            _etag: Option<&str>,
        ) -> Result<BundleFetch, ClientError> {
            unreachable!()
        }

        async fn logout_device(
            &self,
            _access_token: &Secret<String>,
            _device_id: DeviceId,
        ) -> Result<(), ClientError> {
            unreachable!()
        }
    }

    struct EmptyVault;

    impl VaultBackend for EmptyVault {
        fn set(&self, _account: &str, _value: &str) -> Result<(), ClientError> {
            Ok(())
        }

        fn get(&self, _account: &str) -> Result<Option<String>, ClientError> {
            Ok(None)
        }

        fn delete(&self, _account: &str) -> Result<(), ClientError> {
            Ok(())
        }
    }

    fn descriptor(node_id: NodeId, priority: u16) -> ProfileDescriptor {
        ProfileDescriptor {
            node_id,
            display_name: node_id.to_string(),
            region: None,
            endpoint_mode: EndpointMode::Direct,
            encrypted_payload_digest: format!("sha256:{}", "0".repeat(64)).parse().unwrap(),
            priority,
        }
    }

    #[test]
    fn disconnected_refresh_never_has_a_runtime_recovery_action() {
        let directory = tempfile::tempdir().unwrap();
        let supervisor = XraySupervisor::new(directory.path().to_path_buf()).unwrap();
        let before = supervisor.snapshot().unwrap();

        assert!(refresh_recovery(&before, true).is_none());
        let after = supervisor.snapshot().unwrap();
        assert_eq!(after.phase, crate::state::ClientPhase::Disconnected);
        assert!(after.active_profile_id.is_none());
        assert!(after.mode.is_none());
    }

    #[test]
    fn refresh_recovery_reuses_only_the_backend_active_mode() {
        let mut runtime = ClientState::disconnected(10_808, 10_809);
        runtime.phase = crate::state::ClientPhase::Connected;
        runtime.active_profile_id = Some(NodeId::new().to_string());
        runtime.mode = Some(ProxyMode::Manual);
        assert_eq!(
            refresh_recovery(&runtime, true),
            Some((ProxyMode::Manual, true))
        );
        assert!(refresh_recovery(&runtime, false).is_none());

        runtime.phase = crate::state::ClientPhase::Failed;
        assert_eq!(
            refresh_recovery(&runtime, false),
            Some((ProxyMode::Manual, true))
        );
        runtime.active_profile_id = None;
        assert!(refresh_recovery(&runtime, true).is_none());
    }

    #[test]
    fn offline_deadline_is_closed_at_the_exact_boundary() {
        let deadline: Timestamp = "2030-01-01T00:00:00Z".parse().unwrap();
        let before: Timestamp = "2029-12-31T23:59:59Z".parse().unwrap();
        assert!(!offline_deadline_elapsed(deadline, before));
        assert!(offline_deadline_elapsed(deadline, deadline));
    }

    #[tokio::test]
    async fn backend_probe_results_drive_automatic_initial_selection() {
        let failed = NodeId::new();
        let healthy = NodeId::new();
        let probe = Arc::new(StaticProbe(HashMap::from([
            (failed, ProbeOutcome::Failed),
            (
                healthy,
                ProbeOutcome::Healthy {
                    latency: Duration::from_millis(12),
                },
            ),
        ])));
        let outcomes = run_bounded_probes(
            probe,
            vec![
                ProbeTarget {
                    node_id: failed,
                    address: "failed.example".to_string(),
                    port: 443,
                },
                ProbeTarget {
                    node_id: healthy,
                    address: "healthy.example".to_string(),
                    port: 443,
                },
            ],
        )
        .await;
        let mut selector = NodeSelector::new(
            SelectionMode::Automatic,
            &SelectionHints {
                minimum_hold_seconds: 60,
                latency_tolerance_milliseconds: 20,
                failure_threshold: 1,
            },
            &[descriptor(failed, 0), descriptor(healthy, 1)],
        )
        .unwrap();
        for (node_id, outcome) in outcomes {
            selector.observe(node_id, outcome);
        }

        let decision = selector.select(Duration::ZERO);
        assert_eq!(decision.node_id, Some(healthy));
        assert_eq!(decision.reason, SelectionReason::AutomaticInitial);
    }

    #[tokio::test]
    async fn backend_probe_concurrency_is_bounded() {
        let probe = Arc::new(CountingProbe {
            active: AtomicUsize::new(0),
            maximum: AtomicUsize::new(0),
        });
        let targets = (0..24)
            .map(|_| ProbeTarget {
                node_id: NodeId::new(),
                address: "probe.example".to_string(),
                port: 443,
            })
            .collect();

        let results = run_bounded_probes(probe.clone(), targets).await;
        assert_eq!(results.len(), 24);
        assert!(probe.maximum.load(Ordering::SeqCst) <= MAX_CONCURRENT_NODE_PROBES);
    }

    #[tokio::test]
    async fn aggregate_snapshot_never_serializes_controller_trust() {
        let controller_instance_id = ControllerInstanceId::new();
        let signing_key_text = URL_SAFE_NO_PAD.encode([31_u8; 32]);
        let signing_key: Ed25519PublicKey = signing_key_text.parse().unwrap();
        let directory = tempfile::tempdir().unwrap();
        let vault = CredentialVault::new(Arc::new(EmptyVault));
        let session = Arc::new(
            AccountSessionManager::new(
                Arc::new(UnusedControl),
                "https://control.example".to_string(),
                vault.clone(),
                crate::session::AccountInstallTrust {
                    controller_instance_id,
                    bundle_signing_public_key: signing_key.clone(),
                },
            )
            .unwrap(),
        );
        let service = ConnectService::new(
            session,
            vault,
            ConnectTrust {
                controller_instance_id,
                controller_signing_key: signing_key,
                client_version: Version::new(0, 1, 0),
            },
            directory.path().to_path_buf(),
            XraySupervisor::new(directory.path().to_path_buf()).unwrap(),
        );

        let json = serde_json::to_string(&service.snapshot().await.unwrap()).unwrap();
        assert!(!json.contains(&controller_instance_id.to_string()));
        assert!(!json.contains(&signing_key_text));
        assert!(!json.contains("controllerSigning"));
    }
}
