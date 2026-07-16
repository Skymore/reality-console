use crate::system_setup::{
    ProviderSetupPreferences, SystemServicePhase, SystemServiceStatus, SystemSetupErrorCode,
    SystemSetupOperation, SystemSetupRequest, SystemSetupResponse, SystemSetupResult,
    MAX_SYSTEM_REQUEST_BYTES, MAX_SYSTEM_RESPONSE_BYTES, PROVIDER_SETUP_FILE,
    SYSTEM_SETUP_SCHEMA_VERSION,
};
use crate::{
    bootstrap_with_identity_dir, clear_manual_endpoint, configure_manual_endpoint,
    configure_provider_policy, inspect_setup_code, pause_provider, provider_policy_status,
    query_local_service_status, resume_provider, run_until, status, uninstall_local,
    BootstrapRequest, EnrollmentState, HostStatus, SyncLoopOptions,
};
use anyhow::{bail, Context as _, Result};
use async_trait::async_trait;
use rusqlite::{params, TransactionBehavior};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::os::unix::fs::{
    FileTypeExt as _, MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _,
};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{mpsc, oneshot, watch, Mutex as AsyncMutex, Semaphore};
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};
use uuid::Uuid;
use zeroize::Zeroize as _;

pub const SYSTEM_SOCKET_PATH: &str =
    "/Library/Application Support/Private Network Node/run/control.sock";
pub const SYSTEM_SERVICE_STATE_ROOT_PATH: &str =
    "/Library/Application Support/Private Network Node/service-state";
pub const SYSTEM_STATE_PATH: &str =
    "/Library/Application Support/Private Network Node/service-state/state";
pub const SYSTEM_IDENTITY_PATH: &str =
    "/Library/Application Support/Private Network Node/service-state/identity";
pub const SYSTEM_RELEASES_PATH: &str = "/Library/Application Support/Private Network Node/releases";
pub const SYSTEM_CURRENT_PATH: &str = "/Library/Application Support/Private Network Node/current";
pub const SYSTEM_SIDECAR_MANIFEST: &str = "sidecars.json";
pub const SYSTEM_SERVICE_ACCOUNT: &str = "_privnetnode";
const LEGACY_IDENTITY_PATHS: [&str; 3] = [
    "/Library/Application Support/Private Network Node/identity",
    "/Library/Application Support/Private Network Node/identity/active",
    "/Library/Application Support/Private Network Node/.state.installation-identity",
];

const SOCKET_DIRECTORY_MODE: u32 = 0o775;
const SOCKET_MODE: u32 = 0o666;
const FILE_FORBIDDEN_MODE: u32 = 0o022;
const FRAME_IO_TIMEOUT: Duration = Duration::from_secs(2);
const OPERATION_TIMEOUT: Duration = Duration::from_secs(45);
const MAX_CONCURRENT_CONNECTIONS: usize = 8;
const MAX_RECENT_REQUESTS: usize = 128;
const UNPAIR_MARKER_FILE: &str = "last-unpair.json";
const SUPERVISOR_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
enum UnpairMarkerState {
    Pending,
    Complete,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct UnpairMarker {
    schema_version: u16,
    node_id: control_protocol::id::NodeId,
    state: UnpairMarkerState,
}

struct DataPlaneQuiesce {
    ready: oneshot::Sender<std::result::Result<(), ()>>,
    release: oneshot::Receiver<()>,
}

struct DataPlaneLease {
    release: Option<oneshot::Sender<()>>,
}

impl Drop for DataPlaneLease {
    fn drop(&mut self) {
        if let Some(release) = self.release.take() {
            let _ = release.send(());
        }
    }
}

#[derive(Debug, Clone)]
pub struct SystemServicePaths {
    pub socket_dir: PathBuf,
    pub socket_path: PathBuf,
    pub data_dir: PathBuf,
    pub identity_dir: PathBuf,
    pub service_state_root: PathBuf,
    pub releases_dir: PathBuf,
    pub current_link: PathBuf,
    pub console_device: PathBuf,
    pub expected_root_uid: u32,
    pub expected_root_gid: u32,
    pub expected_service_uid: u32,
    pub expected_service_gid: u32,
    pub enforce_current_executable: bool,
}

impl SystemServicePaths {
    /// Resolves the immutable production layout and installed service identity.
    ///
    /// # Errors
    ///
    /// Returns an error when the dedicated service account is unavailable.
    pub fn production() -> Result<Self> {
        let service = nix::unistd::User::from_name(SYSTEM_SERVICE_ACCOUNT)?
            .context("installed Node Host service account is missing")?;
        let socket_path = PathBuf::from(SYSTEM_SOCKET_PATH);
        let socket_dir = socket_path
            .parent()
            .context("fixed system socket path has no parent")?
            .to_path_buf();
        Ok(Self {
            socket_dir,
            socket_path,
            data_dir: PathBuf::from(SYSTEM_STATE_PATH),
            identity_dir: PathBuf::from(SYSTEM_IDENTITY_PATH),
            service_state_root: PathBuf::from(SYSTEM_SERVICE_STATE_ROOT_PATH),
            releases_dir: PathBuf::from(SYSTEM_RELEASES_PATH),
            current_link: PathBuf::from(SYSTEM_CURRENT_PATH),
            console_device: PathBuf::from("/dev/console"),
            expected_root_uid: 0,
            expected_root_gid: 0,
            expected_service_uid: service.uid.as_raw(),
            expected_service_gid: service.gid.as_raw(),
            enforce_current_executable: true,
        })
    }

    #[cfg(test)]
    fn for_test(root: &Path) -> Self {
        let uid = nix::unistd::getuid().as_raw();
        let gid = nix::unistd::getgid().as_raw();
        Self {
            socket_dir: root.join("run"),
            socket_path: root.join("run/control.sock"),
            data_dir: root.join("service-state/state"),
            identity_dir: root.join("service-state/identity"),
            service_state_root: root.join("service-state"),
            releases_dir: root.join("releases"),
            current_link: root.join("current"),
            console_device: root.join("console"),
            expected_root_uid: uid,
            expected_root_gid: gid,
            expected_service_uid: uid,
            expected_service_gid: gid,
            enforce_current_executable: false,
        }
    }
}

/// Rebinds a package-migrated installation identity to the fixed service-state
/// layout after proving that its public fingerprint is unchanged.
///
/// This entry point is intended only for the signed package `postinstall`
/// script. It accepts no caller-provided paths or secrets.
///
/// # Errors
///
/// Returns an error when fixed paths are unsafe, the previous binding is not a
/// known package layout, or the moved identity does not match its immutable
/// fingerprint.
pub fn migrate_system_layout_binding() -> Result<()> {
    let paths = SystemServicePaths::production()?;
    let recognized = LEGACY_IDENTITY_PATHS.map(PathBuf::from);
    migrate_layout_binding(&paths, &recognized)
}

fn migrate_layout_binding(
    paths: &SystemServicePaths,
    recognized_legacy_paths: &[PathBuf],
) -> Result<()> {
    validate_private_service_directory(&paths.service_state_root, paths)?;
    validate_private_service_directory(&paths.data_dir, paths)?;
    validate_private_service_directory(&paths.identity_dir, paths)?;
    if !paths.data_dir.join("node-host.sqlite3").try_exists()? {
        return Ok(());
    }
    let _lock = crate::DataDirLock::acquire(&paths.data_dir, false)?;
    let mut connection = crate::open_database(&paths.data_dir, false)?;
    crate::migrate(&mut connection)?;
    let Some((stored_path, fingerprint)) = crate::load_identity_binding(&connection)? else {
        crate::Identity::load_or_create(&connection, &paths.data_dir, &paths.identity_dir)?;
        return Ok(());
    };
    if stored_path == paths.identity_dir {
        crate::Identity::load_bound(&paths.identity_dir, &fingerprint)?;
        return Ok(());
    }
    if !recognized_legacy_paths.contains(&stored_path) {
        bail!("installation identity binding is not a recognized package layout");
    }
    crate::validate_identity_dir_path(&paths.data_dir, &paths.identity_dir)?;
    crate::Identity::load_bound(&paths.identity_dir, &fingerprint)?;
    let bound_at: i64 = connection.query_row(
        "SELECT bound_at FROM installation_identity_binding WHERE singleton = 1",
        [],
        |row| row.get(0),
    )?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    transaction.execute(
        "DELETE FROM installation_identity_binding WHERE singleton = 1",
        [],
    )?;
    transaction.execute(
        "INSERT INTO installation_identity_binding(
            singleton, identity_path, public_fingerprint, bound_at
         ) VALUES (1, ?1, ?2, ?3)",
        params![paths.identity_dir.to_string_lossy(), fingerprint, bound_at],
    )?;
    transaction.commit()?;
    Ok(())
}

#[derive(Debug, Clone)]
struct VerifiedPackage {
    xray_path: PathBuf,
    xray_sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SidecarManifest {
    schema_version: u16,
    components: Vec<SidecarComponent>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SidecarComponent {
    name: String,
    version: String,
    target: String,
    sha256: String,
    size: u64,
    version_output: Option<String>,
}

#[derive(Debug, Clone)]
pub struct PackageVerifier {
    paths: SystemServicePaths,
    probe_versions: bool,
    verified: Arc<tokio::sync::OnceCell<VerifiedPackage>>,
}

impl PackageVerifier {
    #[must_use]
    pub fn new(paths: SystemServicePaths) -> Self {
        Self {
            paths,
            probe_versions: true,
            verified: Arc::new(tokio::sync::OnceCell::new()),
        }
    }

    async fn verify(&self) -> Result<VerifiedPackage> {
        self.verified
            .get_or_try_init(|| self.verify_uncached())
            .await
            .cloned()
    }

    async fn verify_uncached(&self) -> Result<VerifiedPackage> {
        let install_root = self
            .paths
            .releases_dir
            .parent()
            .context("fixed releases directory has no install root")?;
        validate_directory(
            install_root,
            self.paths.expected_root_uid,
            self.paths.expected_root_gid,
            false,
        )?;
        validate_directory(
            &self.paths.releases_dir,
            self.paths.expected_root_uid,
            self.paths.expected_root_gid,
            false,
        )?;
        validate_private_service_directory(&self.paths.service_state_root, &self.paths)?;
        validate_private_service_directory(&self.paths.data_dir, &self.paths)?;
        validate_private_service_directory(&self.paths.identity_dir, &self.paths)?;
        validate_current_link(&self.paths)?;
        let release_dir = self
            .paths
            .current_link
            .canonicalize()
            .context("installed current release cannot be resolved")?;
        ensure_below(&release_dir, &self.paths.releases_dir)?;
        validate_directory(
            &release_dir,
            self.paths.expected_root_uid,
            self.paths.expected_root_gid,
            false,
        )?;

        let agent_path = release_dir.join("node-host");
        let xray_path = release_dir.join("xray");
        let manifest_path = release_dir.join(SYSTEM_SIDECAR_MANIFEST);
        validate_regular_file(
            &agent_path,
            self.paths.expected_root_uid,
            self.paths.expected_root_gid,
            true,
        )?;
        validate_regular_file(
            &xray_path,
            self.paths.expected_root_uid,
            self.paths.expected_root_gid,
            true,
        )?;
        validate_regular_file(
            &manifest_path,
            self.paths.expected_root_uid,
            self.paths.expected_root_gid,
            false,
        )?;
        if self.paths.enforce_current_executable {
            let running = std::env::current_exe()?.canonicalize()?;
            if running != agent_path.canonicalize()? {
                bail!("running Node Host does not match the installer-selected release");
            }
        }

        let bytes = read_bounded_file(&manifest_path, MAX_SYSTEM_REQUEST_BYTES)?;
        let manifest: SidecarManifest =
            serde_json::from_slice(&bytes).context("installed sidecar manifest is malformed")?;
        if manifest.schema_version != 1 || manifest.components.len() != 2 {
            bail!("installed sidecar manifest has an unsupported schema");
        }
        let expected_target = package_target();
        let mut names = BTreeSet::new();
        let mut node_component = None;
        let mut xray_component = None;
        for component in &manifest.components {
            if !names.insert(component.name.as_str()) || component.target != expected_target {
                bail!("installed sidecar manifest target or component set is invalid");
            }
            match component.name.as_str() {
                "node-host" => node_component = Some(component),
                "xray" => xray_component = Some(component),
                _ => bail!("installed sidecar manifest contains an unknown component"),
            }
        }
        let node_component = node_component.context("Node Host manifest entry is missing")?;
        let xray_component = xray_component.context("Xray manifest entry is missing")?;
        verify_component(&agent_path, node_component)?;
        verify_component(&xray_path, xray_component)?;
        if node_component.version != env!("CARGO_PKG_VERSION") {
            bail!("installed Node Host version does not match its manifest");
        }
        if self.probe_versions {
            verify_xray_version(&xray_path, xray_component).await?;
        }
        Ok(VerifiedPackage {
            xray_path,
            xray_sha256: xray_component.sha256.clone(),
        })
    }
}

fn package_target() -> &'static str {
    match std::env::consts::ARCH {
        "aarch64" => "aarch64-apple-darwin",
        "x86_64" => "x86_64-apple-darwin",
        _ => "unsupported-apple-darwin",
    }
}

fn validate_current_link(paths: &SystemServicePaths) -> Result<()> {
    let metadata = fs::symlink_metadata(&paths.current_link)
        .context("installed current release link is missing")?;
    if !metadata.file_type().is_symlink()
        || metadata.uid() != paths.expected_root_uid
        || metadata.gid() != paths.expected_root_gid
    {
        bail!("installed current release link is unsafe");
    }
    Ok(())
}

fn validate_directory(
    path: &Path,
    expected_user_id: u32,
    expected_group_id: u32,
    allow_group_write: bool,
) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("required directory {} is missing", path.display()))?;
    let forbidden = if allow_group_write { 0o002 } else { 0o022 };
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != expected_user_id
        || metadata.gid() != expected_group_id
        || metadata.mode() & forbidden != 0
    {
        bail!(
            "required directory {} has unsafe ownership or mode",
            path.display()
        );
    }
    Ok(())
}

fn validate_private_service_directory(path: &Path, paths: &SystemServicePaths) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("required directory {} is missing", path.display()))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != paths.expected_service_uid
        || metadata.gid() != paths.expected_service_gid
        || metadata.mode() & 0o777 != 0o700
    {
        bail!("private service directory has unsafe ownership or mode");
    }
    Ok(())
}

fn validate_regular_file(
    path: &Path,
    expected_user_id: u32,
    expected_group_id: u32,
    executable: bool,
) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("required file {} is missing", path.display()))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.uid() != expected_user_id
        || metadata.gid() != expected_group_id
        || metadata.mode() & FILE_FORBIDDEN_MODE != 0
        || (executable && metadata.mode() & 0o111 == 0)
    {
        bail!(
            "required file {} has unsafe ownership or mode",
            path.display()
        );
    }
    Ok(())
}

fn ensure_below(path: &Path, parent: &Path) -> Result<()> {
    let parent = parent.canonicalize()?;
    if !path.starts_with(&parent) || path == parent {
        bail!("installed current release resolves outside the release directory");
    }
    Ok(())
}

fn read_bounded_file(path: &Path, limit: usize) -> Result<Vec<u8>> {
    let mut file = File::open(path)?;
    let mut bytes = Vec::new();
    std::io::Read::by_ref(&mut file)
        .take(u64::try_from(limit)?.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        bail!("installed file exceeds its size limit");
    }
    Ok(bytes)
}

fn verify_component(path: &Path, component: &SidecarComponent) -> Result<()> {
    let metadata = path.metadata()?;
    if metadata.len() != component.size
        || component.sha256.len() != 64
        || !component
            .sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        || sha256_file(path)? != component.sha256
    {
        bail!("installed {} does not match its manifest", component.name);
    }
    Ok(())
}

fn sha256_file(path: &Path) -> Result<String> {
    let mut file = File::open(path)?;
    let mut digest = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    Ok(format!("{:x}", digest.finalize()))
}

async fn verify_xray_version(path: &Path, component: &SidecarComponent) -> Result<()> {
    let output = timeout(
        FRAME_IO_TIMEOUT,
        tokio::process::Command::new(path)
            .arg("version")
            .kill_on_drop(true)
            .output(),
    )
    .await
    .context("installed Xray version probe timed out")??;
    if !output.status.success() {
        bail!("installed Xray version probe failed");
    }
    let first_line = String::from_utf8(output.stdout)?
        .lines()
        .next()
        .unwrap_or_default()
        .to_string();
    if !first_line.starts_with(&format!("Xray {} ", component.version))
        || component
            .version_output
            .as_ref()
            .is_some_and(|expected| expected != &first_line)
    {
        bail!("installed Xray version does not match its manifest");
    }
    Ok(())
}

#[async_trait]
pub trait SystemSetupHandler: Send + Sync {
    async fn handle(&self, request: SystemSetupRequest) -> SystemSetupResponse;
}

pub struct SystemSetupExecutor {
    paths: SystemServicePaths,
    verifier: PackageVerifier,
    service_generation: watch::Sender<u64>,
    supervisor_commands: mpsc::Sender<DataPlaneQuiesce>,
    mutation_lock: AsyncMutex<()>,
}

impl SystemSetupExecutor {
    #[must_use]
    fn new(
        paths: SystemServicePaths,
        service_generation: watch::Sender<u64>,
        supervisor_commands: mpsc::Sender<DataPlaneQuiesce>,
    ) -> Self {
        Self {
            verifier: PackageVerifier::new(paths.clone()),
            paths,
            service_generation,
            supervisor_commands,
            mutation_lock: AsyncMutex::new(()),
        }
    }

    fn notify_service(&self) {
        self.service_generation.send_modify(|generation| {
            *generation = generation.saturating_add(1);
        });
    }

    async fn service_status(&self) -> Result<SystemServiceStatus> {
        let package_verified = self.verifier.verify().await.is_ok();
        if let Ok(local) = query_local_service_status(&self.paths.data_dir).await {
            return Ok(SystemServiceStatus::from_local(&local, package_verified));
        }
        match status(&self.paths.data_dir) {
            Ok(host) => Ok(status_from_host(&host, package_verified)),
            Err(_) => Ok(SystemServiceStatus {
                phase: if package_verified {
                    SystemServicePhase::Unpaired
                } else {
                    SystemServicePhase::NeedsAttention
                },
                package_verified,
                node_id: None,
                applied_revision: None,
                last_sync_at: None,
                provider_policy: None,
                service_instance_id: None,
                runtime_state: None,
                setup_phase: None,
                direct_verification: crate::system_setup::ProtocolVerification::Pending,
                relay_verification: crate::system_setup::ProtocolVerification::Pending,
                relay_connection: crate::system_setup::RelayConnectionState::NotRegistered,
            }),
        }
    }

    async fn confirm_setup(&self, operation: &SystemSetupOperation) -> Result<SystemServiceStatus> {
        let SystemSetupOperation::ConfirmSetup {
            setup_invitation,
            accept_host_owner,
            accept_exit_ip,
            accept_router_mapping,
            accept_relay,
            provider_policy,
        } = operation
        else {
            bail!("internal system setup operation mismatch");
        };
        provider_policy.validate()?;
        let package = self
            .verifier
            .verify()
            .await
            .context("installed package verification failed")?;
        inspect_setup_code(setup_invitation.expose())?;
        let request = BootstrapRequest::from_setup_code(
            setup_invitation.expose(),
            package.xray_path,
            package.xray_sha256,
            *accept_host_owner,
            *accept_exit_ip,
            *accept_router_mapping,
        )?;
        bootstrap_with_identity_dir(&self.paths.data_dir, &self.paths.identity_dir, request)
            .await?;
        set_provider_policy_idempotent(&self.paths.data_dir, provider_policy)?;
        persist_provider_setup_preferences(&self.paths, *accept_relay)?;
        remove_unpair_marker(&self.paths)?;
        self.notify_service();
        self.service_status().await
    }

    async fn quiesce_data_plane(&self) -> Result<DataPlaneLease> {
        let (ready_tx, ready_rx) = oneshot::channel();
        let (release_tx, release_rx) = oneshot::channel();
        timeout(
            FRAME_IO_TIMEOUT,
            self.supervisor_commands.send(DataPlaneQuiesce {
                ready: ready_tx,
                release: release_rx,
            }),
        )
        .await
        .context("data-plane supervisor request timed out")?
        .context("data-plane supervisor is unavailable")?;
        timeout(SUPERVISOR_HANDSHAKE_TIMEOUT, ready_rx)
            .await
            .context("data-plane shutdown timed out")?
            .context("data-plane supervisor dropped its shutdown response")?
            .map_err(|()| anyhow::anyhow!("data-plane shutdown did not complete safely"))?;
        Ok(DataPlaneLease {
            release: Some(release_tx),
        })
    }

    async fn unpair(
        &self,
        expected_node_id: control_protocol::id::NodeId,
    ) -> Result<SystemServiceStatus> {
        if let Some(marker) = load_unpair_marker(&self.paths)? {
            if marker.node_id != expected_node_id {
                bail!("unpair confirmation node ID does not match local enrollment");
            }
            if marker.state == UnpairMarkerState::Complete {
                return self.service_status().await;
            }
            if !self.paths.data_dir.join("node-host.sqlite3").try_exists()? {
                prepare_empty_active_directories(&self.paths)?;
                write_unpair_marker(&self.paths, expected_node_id, UnpairMarkerState::Complete)?;
                return self.service_status().await;
            }
        }

        let current_node_id =
            if let Ok(local) = query_local_service_status(&self.paths.data_dir).await {
                local.node_id
            } else {
                status(&self.paths.data_dir)?
                    .node_id
                    .context("node host is not enrolled")?
            };
        if current_node_id != expected_node_id {
            bail!("unpair confirmation node ID does not match local enrollment");
        }
        write_unpair_marker(&self.paths, expected_node_id, UnpairMarkerState::Pending)?;
        let lease = self.quiesce_data_plane().await?;
        uninstall_local(&self.paths.data_dir, expected_node_id)?;
        prepare_empty_active_directories(&self.paths)?;
        write_unpair_marker(&self.paths, expected_node_id, UnpairMarkerState::Complete)?;
        drop(lease);
        self.notify_service();
        self.service_status().await
    }

    fn error_response(
        request_id: Uuid,
        operation: &SystemSetupOperation,
        error: &anyhow::Error,
    ) -> SystemSetupResponse {
        let package_error = matches!(operation, SystemSetupOperation::ConfirmSetup { .. })
            && error.to_string().contains("installed");
        let (code, retryable) = if package_error {
            (SystemSetupErrorCode::PackageVerificationFailed, false)
        } else if matches!(operation, SystemSetupOperation::Unpair { .. })
            && error.to_string().contains("confirmation")
        {
            (SystemSetupErrorCode::ConfirmationMismatch, false)
        } else if matches!(operation, SystemSetupOperation::ConfirmSetup { .. }) {
            (SystemSetupErrorCode::SetupFailed, true)
        } else {
            (SystemSetupErrorCode::StateUnavailable, true)
        };
        warn!(request_id = %request_id, method = operation_name(operation), error = %error, "system setup operation failed");
        SystemSetupResponse::error(request_id, code, retryable)
    }
}

#[async_trait]
impl SystemSetupHandler for SystemSetupExecutor {
    async fn handle(&self, request: SystemSetupRequest) -> SystemSetupResponse {
        let request_id = request.request_id;
        let _mutation_guard = if matches!(request.operation, SystemSetupOperation::Status {}) {
            None
        } else {
            Some(self.mutation_lock.lock().await)
        };
        let result = match &request.operation {
            SystemSetupOperation::Status {} => self
                .service_status()
                .await
                .map(|status| SystemSetupResult::Status { status }),
            SystemSetupOperation::ConfirmSetup { .. } => self
                .confirm_setup(&request.operation)
                .await
                .map(|status| SystemSetupResult::SetupComplete { status }),
            SystemSetupOperation::UpdateProviderPolicy { provider_policy } => {
                set_provider_policy_idempotent(&self.paths.data_dir, provider_policy).map(
                    |status| {
                        self.notify_service();
                        SystemSetupResult::ProviderPolicyUpdated { status }
                    },
                )
            }
            SystemSetupOperation::Pause {} => {
                set_provider_pause_idempotent(&self.paths.data_dir, true).map(|status| {
                    self.notify_service();
                    SystemSetupResult::ProviderPolicyUpdated { status }
                })
            }
            SystemSetupOperation::Resume {} => {
                set_provider_pause_idempotent(&self.paths.data_dir, false).map(|status| {
                    self.notify_service();
                    SystemSetupResult::ProviderPolicyUpdated { status }
                })
            }
            SystemSetupOperation::ConfigureManualEndpoint { endpoint } => {
                configure_manual_endpoint(&self.paths.data_dir, endpoint).map(|status| {
                    self.notify_service();
                    SystemSetupResult::ManualEndpointUpdated { status }
                })
            }
            SystemSetupOperation::ClearManualEndpoint {} => {
                clear_manual_endpoint(&self.paths.data_dir).map(|()| {
                    self.notify_service();
                    SystemSetupResult::ManualEndpointCleared {}
                })
            }
            SystemSetupOperation::Unpair { confirm_node_id } => self
                .unpair(*confirm_node_id)
                .await
                .map(|status| SystemSetupResult::Unpaired { status }),
        };
        match result {
            Ok(result) => SystemSetupResponse::success(request_id, result),
            Err(error) => Self::error_response(request_id, &request.operation, &error),
        }
    }
}

fn set_provider_policy_idempotent(
    data_dir: &Path,
    policy: &crate::ProviderPolicy,
) -> Result<crate::ProviderPolicyStatus> {
    let current = provider_policy_status(data_dir)?;
    if current.policy == *policy {
        Ok(current)
    } else {
        configure_provider_policy(data_dir, policy)
    }
}

fn set_provider_pause_idempotent(
    data_dir: &Path,
    paused: bool,
) -> Result<crate::ProviderPolicyStatus> {
    let current = provider_policy_status(data_dir)?;
    if current.policy.paused == paused {
        Ok(current)
    } else if paused {
        pause_provider(data_dir)
    } else {
        resume_provider(data_dir)
    }
}

fn operation_name(operation: &SystemSetupOperation) -> &'static str {
    match operation {
        SystemSetupOperation::Status {} => "status",
        SystemSetupOperation::ConfirmSetup { .. } => "confirmSetup",
        SystemSetupOperation::UpdateProviderPolicy { .. } => "updateProviderPolicy",
        SystemSetupOperation::Pause {} => "pause",
        SystemSetupOperation::Resume {} => "resume",
        SystemSetupOperation::ConfigureManualEndpoint { .. } => "configureManualEndpoint",
        SystemSetupOperation::ClearManualEndpoint {} => "clearManualEndpoint",
        SystemSetupOperation::Unpair { .. } => "unpair",
    }
}

fn status_from_host(host: &HostStatus, package_verified: bool) -> SystemServiceStatus {
    let enrolled = host.enrollment_state == EnrollmentState::Enrolled;
    SystemServiceStatus {
        phase: if !package_verified {
            SystemServicePhase::NeedsAttention
        } else if !enrolled {
            SystemServicePhase::Unpaired
        } else if host.applied_revision.is_some() {
            SystemServicePhase::Ready
        } else {
            SystemServicePhase::Enrolled
        },
        package_verified,
        node_id: host.node_id,
        applied_revision: host.applied_revision,
        last_sync_at: host.last_sync_at,
        provider_policy: Some(host.provider_policy.clone()),
        service_instance_id: None,
        runtime_state: None,
        setup_phase: None,
        direct_verification: crate::system_setup::ProtocolVerification::Pending,
        relay_verification: crate::system_setup::ProtocolVerification::Pending,
        relay_connection: crate::system_setup::RelayConnectionState::NotRegistered,
    }
}

fn persist_provider_setup_preferences(
    paths: &SystemServicePaths,
    relay_accepted: bool,
) -> Result<()> {
    validate_private_service_directory(&paths.data_dir, paths)?;
    let destination = paths.data_dir.join(PROVIDER_SETUP_FILE);
    if destination.try_exists()? {
        validate_regular_file(
            &destination,
            paths.expected_service_uid,
            paths.expected_service_gid,
            false,
        )?;
    }
    let contents = serde_json::to_vec(&ProviderSetupPreferences {
        schema_version: 1,
        relay_accepted,
    })?;
    let temporary = paths
        .data_dir
        .join(format!(".{PROVIDER_SETUP_FILE}.{}.tmp", Uuid::new_v4()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)?;
    file.write_all(&contents)?;
    file.sync_all()?;
    fs::rename(&temporary, &destination)?;
    File::open(&paths.data_dir)?.sync_all()?;
    Ok(())
}

fn unpair_marker_path(paths: &SystemServicePaths) -> PathBuf {
    paths.service_state_root.join(UNPAIR_MARKER_FILE)
}

fn load_unpair_marker(paths: &SystemServicePaths) -> Result<Option<UnpairMarker>> {
    validate_private_service_directory(&paths.service_state_root, paths)?;
    let marker_path = unpair_marker_path(paths);
    let metadata = match fs::symlink_metadata(&marker_path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.uid() != paths.expected_service_uid
        || metadata.gid() != paths.expected_service_gid
        || metadata.mode() & 0o077 != 0
    {
        bail!("unpair marker has unsafe ownership or mode");
    }
    let bytes = read_bounded_file(&marker_path, 4 * 1024)?;
    let marker: UnpairMarker = serde_json::from_slice(&bytes)?;
    if marker.schema_version != 1 {
        bail!("unpair marker schema is unsupported");
    }
    Ok(Some(marker))
}

fn write_unpair_marker(
    paths: &SystemServicePaths,
    node_id: control_protocol::id::NodeId,
    state: UnpairMarkerState,
) -> Result<()> {
    validate_private_service_directory(&paths.service_state_root, paths)?;
    let destination = unpair_marker_path(paths);
    if destination.try_exists()? {
        validate_regular_file(
            &destination,
            paths.expected_service_uid,
            paths.expected_service_gid,
            false,
        )?;
    }
    let temporary = paths
        .service_state_root
        .join(format!(".{UNPAIR_MARKER_FILE}.{}.tmp", Uuid::new_v4()));
    let bytes = serde_json::to_vec(&UnpairMarker {
        schema_version: 1,
        node_id,
        state,
    })?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    fs::rename(&temporary, &destination)?;
    File::open(&paths.service_state_root)?.sync_all()?;
    Ok(())
}

fn remove_unpair_marker(paths: &SystemServicePaths) -> Result<()> {
    let marker_path = unpair_marker_path(paths);
    match fs::symlink_metadata(&marker_path) {
        Ok(metadata)
            if !metadata.file_type().is_symlink()
                && metadata.is_file()
                && metadata.uid() == paths.expected_service_uid
                && metadata.gid() == paths.expected_service_gid =>
        {
            fs::remove_file(marker_path)?;
            File::open(&paths.service_state_root)?.sync_all()?;
            Ok(())
        }
        Ok(_) => bail!("unpair marker has unsafe ownership or type"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn prepare_empty_active_directories(paths: &SystemServicePaths) -> Result<()> {
    validate_private_service_directory(&paths.service_state_root, paths)?;
    for directory in [&paths.data_dir, &paths.identity_dir] {
        if directory.try_exists()? {
            validate_private_service_directory(directory, paths)?;
            if fs::read_dir(directory)?.next().is_some() {
                bail!("unpaired active directory is unexpectedly non-empty");
            }
        } else {
            fs::create_dir(directory)?;
            fs::set_permissions(directory, fs::Permissions::from_mode(0o700))?;
            validate_private_service_directory(directory, paths)?;
        }
        File::open(directory)?.sync_all()?;
    }
    File::open(&paths.service_state_root)?.sync_all()?;
    Ok(())
}

#[async_trait]
pub trait PeerAuthorizer: Send + Sync {
    async fn authorize(&self, peer_uid: u32) -> Result<()>;
}

pub struct ConsolePeerAuthorizer {
    console_device: PathBuf,
}

impl ConsolePeerAuthorizer {
    #[must_use]
    pub fn new(console_device: PathBuf) -> Self {
        Self { console_device }
    }
}

#[async_trait]
impl PeerAuthorizer for ConsolePeerAuthorizer {
    async fn authorize(&self, peer_uid: u32) -> Result<()> {
        if peer_uid == 0 {
            return Ok(());
        }
        let metadata = fs::symlink_metadata(&self.console_device)
            .context("current console ownership is unavailable")?;
        if metadata.file_type().is_symlink() || peer_uid != metadata.uid() || metadata.uid() == 0 {
            bail!("local peer is not the current console user");
        }
        Ok(())
    }
}

struct RequestDispatcher {
    handler: Arc<dyn SystemSetupHandler>,
    recent: Mutex<BTreeMap<Uuid, SystemSetupResponse>>,
    in_flight: Mutex<BTreeSet<Uuid>>,
}

impl RequestDispatcher {
    fn new(handler: Arc<dyn SystemSetupHandler>) -> Self {
        Self {
            handler,
            recent: Mutex::new(BTreeMap::new()),
            in_flight: Mutex::new(BTreeSet::new()),
        }
    }

    async fn dispatch(&self, request: SystemSetupRequest) -> SystemSetupResponse {
        let request_id = request.request_id;
        if let Some(response) = self
            .recent
            .lock()
            .expect("recent lock poisoned")
            .get(&request_id)
        {
            return response.clone();
        }
        {
            let mut in_flight = self.in_flight.lock().expect("in-flight lock poisoned");
            if !in_flight.insert(request_id) {
                return SystemSetupResponse::error(
                    request_id,
                    SystemSetupErrorCode::DuplicateRequestInProgress,
                    true,
                );
            }
        }
        let response = self.handler.handle(request).await;
        self.in_flight
            .lock()
            .expect("in-flight lock poisoned")
            .remove(&request_id);
        let mut recent = self.recent.lock().expect("recent lock poisoned");
        if recent.len() >= MAX_RECENT_REQUESTS {
            if let Some(oldest) = recent.keys().next().copied() {
                recent.remove(&oldest);
            }
        }
        recent.insert(request_id, response.clone());
        response
    }
}

pub async fn serve_system_setup_socket(
    paths: SystemServicePaths,
    authorizer: Arc<dyn PeerAuthorizer>,
    handler: Arc<dyn SystemSetupHandler>,
    shutdown: CancellationToken,
) -> Result<()> {
    validate_socket_directory(&paths)?;
    remove_stale_socket(&paths)?;
    let listener = UnixListener::bind(&paths.socket_path)?;
    fs::set_permissions(&paths.socket_path, fs::Permissions::from_mode(SOCKET_MODE))?;
    let dispatcher = Arc::new(RequestDispatcher::new(handler));
    let permits = Arc::new(Semaphore::new(MAX_CONCURRENT_CONNECTIONS));
    loop {
        tokio::select! {
            () = shutdown.cancelled() => break,
            accepted = listener.accept() => {
                let (stream, _) = accepted?;
                let authorizer = Arc::clone(&authorizer);
                let dispatcher = Arc::clone(&dispatcher);
                let permit = Arc::clone(&permits).acquire_owned().await?;
                tokio::spawn(async move {
                    let _permit = permit;
                    if let Err(error) = handle_connection(stream, authorizer, dispatcher).await {
                        warn!(error = %error, "system setup IPC request was rejected");
                    }
                });
            }
        }
    }
    drop(listener);
    remove_stale_socket(&paths)?;
    Ok(())
}

async fn handle_connection(
    mut stream: UnixStream,
    authorizer: Arc<dyn PeerAuthorizer>,
    dispatcher: Arc<RequestDispatcher>,
) -> Result<()> {
    let peer_uid = nix::unistd::getpeereid(&stream)?.0.as_raw();
    authorizer
        .authorize(peer_uid)
        .await
        .context("unauthorized local peer")?;
    let mut bytes = read_frame(&mut stream, MAX_SYSTEM_REQUEST_BYTES).await?;
    let parsed = serde_json::from_slice(&bytes);
    bytes.zeroize();
    let request: SystemSetupRequest = parsed.context("malformed system setup request")?;
    request.validate()?;
    info!(request_id = %request.request_id, method = request.method_name(), "handling privileged local request");
    let response = dispatcher.dispatch(request).await;
    let bytes = serde_json::to_vec(&response)?;
    write_frame(&mut stream, &bytes, MAX_SYSTEM_RESPONSE_BYTES).await?;
    stream.shutdown().await?;
    Ok(())
}

fn validate_socket_directory(paths: &SystemServicePaths) -> Result<()> {
    let metadata = fs::symlink_metadata(&paths.socket_dir)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != paths.expected_root_uid
        || metadata.gid() != paths.expected_service_gid
        || metadata.mode() & 0o777 != SOCKET_DIRECTORY_MODE
    {
        bail!("system setup socket directory is unsafe");
    }
    Ok(())
}

fn remove_stale_socket(paths: &SystemServicePaths) -> Result<()> {
    let Ok(metadata) = fs::symlink_metadata(&paths.socket_path) else {
        return Ok(());
    };
    if metadata.file_type().is_symlink()
        || !metadata.file_type().is_socket()
        || metadata.uid() != paths.expected_service_uid
    {
        bail!("existing system setup socket is unsafe");
    }
    fs::remove_file(&paths.socket_path)?;
    Ok(())
}

async fn read_frame(stream: &mut UnixStream, limit: usize) -> Result<Vec<u8>> {
    read_frame_with_timeout(stream, limit, FRAME_IO_TIMEOUT).await
}

async fn read_frame_with_timeout(
    stream: &mut UnixStream,
    limit: usize,
    io_timeout: Duration,
) -> Result<Vec<u8>> {
    let length = timeout(io_timeout, stream.read_u32())
        .await
        .context("system setup frame header timed out")??;
    let length = usize::try_from(length)?;
    if length == 0 || length > limit {
        bail!("system setup frame length is invalid");
    }
    let mut bytes = vec![0_u8; length];
    timeout(io_timeout, stream.read_exact(&mut bytes))
        .await
        .context("system setup frame body timed out")??;
    Ok(bytes)
}

async fn write_frame(stream: &mut UnixStream, bytes: &[u8], limit: usize) -> Result<()> {
    if bytes.is_empty() || bytes.len() > limit {
        bail!("system setup response length is invalid");
    }
    let length = u32::try_from(bytes.len())?;
    timeout(FRAME_IO_TIMEOUT, async {
        stream.write_u32(length).await?;
        stream.write_all(bytes).await?;
        stream.flush().await
    })
    .await
    .context("system setup response write timed out")??;
    Ok(())
}

#[derive(Clone)]
pub struct SystemServiceClient {
    paths: SystemServicePaths,
}

impl SystemServiceClient {
    /// Creates a client pinned to the installed service account and fixed
    /// package socket.
    ///
    /// # Errors
    ///
    /// Returns an error when the package service account is unavailable.
    pub fn production() -> Result<Self> {
        Ok(Self {
            paths: SystemServicePaths::production()?,
        })
    }

    #[must_use]
    pub fn with_paths(paths: SystemServicePaths) -> Self {
        Self { paths }
    }

    /// Sends one closed privileged request after validating the installed
    /// socket and authenticating its service-side peer credentials.
    ///
    /// # Errors
    ///
    /// Returns an error for unsafe socket ownership, timeout, malformed framing,
    /// wrong peer identity, or response/request mismatch.
    pub async fn request(&self, operation: SystemSetupOperation) -> Result<SystemSetupResponse> {
        validate_client_socket(&self.paths)?;
        let request = SystemSetupRequest {
            schema_version: SYSTEM_SETUP_SCHEMA_VERSION,
            request_id: Uuid::new_v4(),
            operation,
        };
        request.validate()?;
        let mut bytes = serde_json::to_vec(&request)?;
        if bytes.len() > MAX_SYSTEM_REQUEST_BYTES {
            bail!("system setup request exceeds its size limit");
        }
        let mut stream = timeout(
            FRAME_IO_TIMEOUT,
            UnixStream::connect(&self.paths.socket_path),
        )
        .await
        .context("system setup socket connection timed out")??;
        if nix::unistd::getpeereid(&stream)?.0.as_raw() != self.paths.expected_service_uid {
            bail!("system setup server identity is invalid");
        }
        let write_result = write_frame(&mut stream, &bytes, MAX_SYSTEM_REQUEST_BYTES).await;
        bytes.zeroize();
        write_result?;
        let response_bytes = timeout(
            OPERATION_TIMEOUT,
            read_frame_with_timeout(&mut stream, MAX_SYSTEM_RESPONSE_BYTES, OPERATION_TIMEOUT),
        )
        .await
        .context("system setup operation timed out")??;
        let response: SystemSetupResponse = serde_json::from_slice(&response_bytes)?;
        if response.schema_version != SYSTEM_SETUP_SCHEMA_VERSION
            || response.request_id != request.request_id
        {
            bail!("system setup response is not bound to its request");
        }
        Ok(response)
    }
}

fn validate_client_socket(paths: &SystemServicePaths) -> Result<()> {
    validate_socket_directory(paths)?;
    let metadata = fs::symlink_metadata(&paths.socket_path)?;
    if metadata.file_type().is_symlink()
        || !metadata.file_type().is_socket()
        || metadata.uid() != paths.expected_service_uid
        || metadata.mode() & 0o777 != SOCKET_MODE
    {
        bail!("system setup socket has unsafe ownership or mode");
    }
    Ok(())
}

/// Runs the packaged macOS `LaunchDaemon` control plane and enrolled data plane.
///
/// # Errors
///
/// Returns an error when fixed package paths, socket ownership, or service
/// supervision cannot be established.
pub async fn run_system_service() -> Result<()> {
    let paths = SystemServicePaths::production()?;
    let (generation_tx, generation_rx) = watch::channel(0_u64);
    let (supervisor_tx, supervisor_rx) = mpsc::channel(8);
    let executor = Arc::new(SystemSetupExecutor::new(
        paths.clone(),
        generation_tx,
        supervisor_tx,
    ));
    let authorizer = Arc::new(ConsolePeerAuthorizer::new(paths.console_device.clone()));
    let shutdown = CancellationToken::new();
    let signal = shutdown.clone();
    tokio::spawn(async move {
        if system_shutdown_signal().await.is_ok() {
            signal.cancel();
        }
    });
    tokio::try_join!(
        serve_system_setup_socket(paths.clone(), authorizer, executor, shutdown.clone()),
        supervise_data_plane(paths, generation_rx, supervisor_rx, shutdown)
    )?;
    Ok(())
}

async fn system_shutdown_signal() -> Result<()> {
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! {
        result = tokio::signal::ctrl_c() => result?,
        _ = terminate.recv() => {}
    }
    Ok(())
}

async fn supervise_data_plane(
    paths: SystemServicePaths,
    mut generation: watch::Receiver<u64>,
    mut commands: mpsc::Receiver<DataPlaneQuiesce>,
    shutdown: CancellationToken,
) -> Result<()> {
    let verifier = PackageVerifier::new(paths.clone());
    loop {
        if shutdown.is_cancelled() {
            return Ok(());
        }
        if verifier.verify().await.is_err()
            || status(&paths.data_dir)
                .map(|host| host.enrollment_state != EnrollmentState::Enrolled)
                .unwrap_or(true)
        {
            tokio::select! {
                () = shutdown.cancelled() => return Ok(()),
                changed = generation.changed() => changed.context("system service generation closed")?,
                command = commands.recv() => {
                    let command = command.context("data-plane supervisor command channel closed")?;
                    if hold_data_plane_quiesced(command, true, &shutdown).await {
                        return Ok(());
                    }
                }
                () = tokio::time::sleep(Duration::from_secs(10)) => {}
            }
            continue;
        }
        let service_stop = CancellationToken::new();
        let service_cancel = service_stop.clone();
        let data_dir = paths.data_dir.clone();
        let service = run_until(&data_dir, SyncLoopOptions::default(), async move {
            service_cancel.cancelled().await;
            Ok(())
        });
        tokio::pin!(service);
        tokio::select! {
            () = shutdown.cancelled() => {
                service_stop.cancel();
                service.await?;
                return Ok(());
            }
            changed = generation.changed() => {
                changed.context("system service generation closed")?;
                service_stop.cancel();
                service.await?;
            }
            command = commands.recv() => {
                let command = command.context("data-plane supervisor command channel closed")?;
                service_stop.cancel();
                let stopped_safely = service.await.is_ok();
                if hold_data_plane_quiesced(command, stopped_safely, &shutdown).await {
                    return Ok(());
                }
            }
            result = &mut service => {
                if let Err(error) = result {
                    error!(error = %error, "Node Host data plane stopped unexpectedly");
                }
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        }
    }
}

async fn hold_data_plane_quiesced(
    command: DataPlaneQuiesce,
    stopped_safely: bool,
    shutdown: &CancellationToken,
) -> bool {
    let ready_result = if stopped_safely { Ok(()) } else { Err(()) };
    let _ = command.ready.send(ready_result);
    if !stopped_safely {
        return false;
    }
    tokio::select! {
        _ = command.release => false,
        () = shutdown.cancelled() => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SetupInvitation, SystemSetupOutcome};
    use control_protocol::id::{ControllerInstanceId, NetworkId, NodeKeyId, Timestamp};
    use rusqlite::params;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use time::{Duration as TimeDuration, OffsetDateTime};

    struct AllowUid(u32);

    #[async_trait]
    impl PeerAuthorizer for AllowUid {
        async fn authorize(&self, peer_uid: u32) -> Result<()> {
            anyhow::ensure!(peer_uid == self.0, "wrong peer UID");
            Ok(())
        }
    }

    struct CountingHandler(AtomicUsize);

    #[async_trait]
    impl SystemSetupHandler for CountingHandler {
        async fn handle(&self, request: SystemSetupRequest) -> SystemSetupResponse {
            self.0.fetch_add(1, Ordering::SeqCst);
            SystemSetupResponse::success(
                request.request_id,
                SystemSetupResult::ManualEndpointCleared {},
            )
        }
    }

    struct DelayedHandler(Duration);

    #[async_trait]
    impl SystemSetupHandler for DelayedHandler {
        async fn handle(&self, request: SystemSetupRequest) -> SystemSetupResponse {
            tokio::time::sleep(self.0).await;
            SystemSetupResponse::success(
                request.request_id,
                SystemSetupResult::ManualEndpointCleared {},
            )
        }
    }

    fn make_socket_directory(paths: &SystemServicePaths) {
        fs::create_dir(&paths.socket_dir).unwrap();
        fs::set_permissions(
            &paths.socket_dir,
            fs::Permissions::from_mode(SOCKET_DIRECTORY_MODE),
        )
        .unwrap();
    }

    fn make_active_directories(paths: &SystemServicePaths) {
        fs::create_dir(&paths.service_state_root).unwrap();
        fs::create_dir(&paths.data_dir).unwrap();
        fs::create_dir(&paths.identity_dir).unwrap();
        for directory in [
            &paths.service_state_root,
            &paths.data_dir,
            &paths.identity_dir,
        ] {
            fs::set_permissions(directory, fs::Permissions::from_mode(0o700)).unwrap();
        }
    }

    #[tokio::test]
    async fn framed_socket_authenticates_peer_and_deduplicates_request() {
        let temporary = tempfile::tempdir().unwrap();
        let paths = SystemServicePaths::for_test(temporary.path());
        make_socket_directory(&paths);
        let shutdown = CancellationToken::new();
        let handler = Arc::new(CountingHandler(AtomicUsize::new(0)));
        let server = tokio::spawn(serve_system_setup_socket(
            paths.clone(),
            Arc::new(AllowUid(paths.expected_service_uid)),
            handler.clone(),
            shutdown.clone(),
        ));
        for _ in 0..20 {
            if paths.socket_path.exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let request = SystemSetupRequest {
            schema_version: 1,
            request_id: Uuid::new_v4(),
            operation: SystemSetupOperation::ClearManualEndpoint {},
        };
        let bytes = serde_json::to_vec(&request).unwrap();
        serde_json::from_slice::<SystemSetupRequest>(&bytes).unwrap();
        for _ in 0..2 {
            let mut stream = UnixStream::connect(&paths.socket_path).await.unwrap();
            write_frame(&mut stream, &bytes, MAX_SYSTEM_REQUEST_BYTES)
                .await
                .unwrap();
            let response = read_frame(&mut stream, MAX_SYSTEM_RESPONSE_BYTES)
                .await
                .unwrap();
            let response: SystemSetupResponse = serde_json::from_slice(&response).unwrap();
            assert_eq!(response.request_id, request.request_id);
        }
        assert_eq!(handler.0.load(Ordering::SeqCst), 1);
        shutdown.cancel();
        server.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn client_waits_past_frame_timeout_for_a_long_running_operation() {
        let temporary = tempfile::tempdir().unwrap();
        let paths = SystemServicePaths::for_test(temporary.path());
        make_socket_directory(&paths);
        let shutdown = CancellationToken::new();
        let server = tokio::spawn(serve_system_setup_socket(
            paths.clone(),
            Arc::new(AllowUid(paths.expected_service_uid)),
            Arc::new(DelayedHandler(
                FRAME_IO_TIMEOUT + Duration::from_millis(100),
            )),
            shutdown.clone(),
        ));
        for _ in 0..20 {
            if paths.socket_path.exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        let response = SystemServiceClient::with_paths(paths)
            .request(SystemSetupOperation::ClearManualEndpoint {})
            .await
            .unwrap();
        assert!(matches!(
            response.outcome,
            SystemSetupOutcome::Success { result }
                if matches!(*result, SystemSetupResult::ManualEndpointCleared {})
        ));
        shutdown.cancel();
        server.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn wrong_peer_authorizer_and_oversized_frames_never_reach_handler() {
        let temporary = tempfile::tempdir().unwrap();
        let paths = SystemServicePaths::for_test(temporary.path());
        make_socket_directory(&paths);
        let shutdown = CancellationToken::new();
        let handler = Arc::new(CountingHandler(AtomicUsize::new(0)));
        let server = tokio::spawn(serve_system_setup_socket(
            paths.clone(),
            Arc::new(AllowUid(paths.expected_service_uid.saturating_add(1))),
            handler.clone(),
            shutdown.clone(),
        ));
        for _ in 0..20 {
            if paths.socket_path.exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let mut stream = UnixStream::connect(&paths.socket_path).await.unwrap();
        stream
            .write_u32(u32::try_from(MAX_SYSTEM_REQUEST_BYTES + 1).unwrap())
            .await
            .unwrap();
        stream.shutdown().await.unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(handler.0.load(Ordering::SeqCst), 0);
        shutdown.cancel();
        server.await.unwrap().unwrap();
    }

    #[test]
    fn socket_and_package_paths_fail_closed_on_symlinks_and_modes() {
        let temporary = tempfile::tempdir().unwrap();
        let paths = SystemServicePaths::for_test(temporary.path());
        make_socket_directory(&paths);
        fs::set_permissions(&paths.socket_dir, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(validate_socket_directory(&paths).is_err());
        fs::set_permissions(
            &paths.socket_dir,
            fs::Permissions::from_mode(SOCKET_DIRECTORY_MODE),
        )
        .unwrap();
        let real_socket = temporary.path().join("real.sock");
        let listener = std::os::unix::net::UnixListener::bind(&real_socket).unwrap();
        std::os::unix::fs::symlink(&real_socket, &paths.socket_path).unwrap();
        assert!(validate_client_socket(&paths).is_err());
        drop(listener);
        fs::remove_file(&paths.socket_path).unwrap();

        let real = temporary.path().join("real-file");
        let linked = temporary.path().join("linked-file");
        fs::write(&real, b"payload").unwrap();
        std::os::unix::fs::symlink(&real, &linked).unwrap();
        assert!(validate_regular_file(
            &linked,
            paths.expected_root_uid,
            paths.expected_root_gid,
            false
        )
        .is_err());

        let mut wrong_owner = paths;
        wrong_owner.expected_root_uid = wrong_owner.expected_root_uid.saturating_add(1);
        assert!(validate_socket_directory(&wrong_owner).is_err());
    }

    #[test]
    fn provider_setup_file_contains_consent_but_no_invitation() {
        let temporary = tempfile::tempdir().unwrap();
        let paths = SystemServicePaths::for_test(temporary.path());
        make_active_directories(&paths);
        persist_provider_setup_preferences(&paths, true).unwrap();
        let contents = fs::read_to_string(paths.data_dir.join(PROVIDER_SETUP_FILE)).unwrap();
        assert_eq!(contents, r#"{"schemaVersion":1,"relayAccepted":true}"#);
        assert!(!contents.contains("invitation"));
    }

    fn make_package(paths: &SystemServicePaths) {
        let release = paths.releases_dir.join("1.2.3");
        fs::create_dir_all(&release).unwrap();
        make_active_directories(paths);
        let agent = release.join("node-host");
        let xray = release.join("xray");
        fs::write(&agent, b"test node host").unwrap();
        fs::write(&xray, b"test xray").unwrap();
        fs::set_permissions(&agent, fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(&xray, fs::Permissions::from_mode(0o755)).unwrap();
        let manifest = serde_json::json!({
            "schemaVersion": 1,
            "components": [
                {
                    "name": "node-host",
                    "version": env!("CARGO_PKG_VERSION"),
                    "target": package_target(),
                    "sha256": sha256_file(&agent).unwrap(),
                    "size": agent.metadata().unwrap().len(),
                    "versionOutput": null
                },
                {
                    "name": "xray",
                    "version": "26.3.27",
                    "target": package_target(),
                    "sha256": sha256_file(&xray).unwrap(),
                    "size": xray.metadata().unwrap().len(),
                    "versionOutput": null
                }
            ]
        });
        fs::write(
            release.join(SYSTEM_SIDECAR_MANIFEST),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        std::os::unix::fs::symlink("releases/1.2.3", &paths.current_link).unwrap();
    }

    fn seed_enrolled_system(paths: &SystemServicePaths) -> control_protocol::id::NodeId {
        let host = crate::initialize_with_identity_dir(
            &paths.data_dir,
            &paths.identity_dir,
            "http://127.0.0.1:9",
        )
        .unwrap();
        let node_id = control_protocol::id::NodeId::new();
        let connection = crate::open_database(&paths.data_dir, false).unwrap();
        connection
            .execute(
                "INSERT INTO enrollment_registration(
                    singleton, invitation_id, network_id, node_id, controller_instance_id,
                    controller_fingerprint, controller_signing_public_key, credential_key_id,
                    credential_mode, credential_expires_at, enrolled_at
                 ) VALUES (1, ?1, ?2, ?3, ?4, 'test-fingerprint', ?5, ?6,
                    'signedRequest', ?7, ?8)",
                params![
                    Uuid::new_v4().to_string(),
                    NetworkId::new().to_string(),
                    node_id.to_string(),
                    ControllerInstanceId::new().to_string(),
                    host.identity_public_key.as_str(),
                    NodeKeyId::new().to_string(),
                    Timestamp::from_datetime(OffsetDateTime::now_utc() + TimeDuration::hours(2))
                        .to_string(),
                    OffsetDateTime::now_utc().unix_timestamp(),
                ],
            )
            .unwrap();
        node_id
    }

    #[tokio::test]
    async fn package_verification_binds_target_size_digest_and_safe_paths() {
        let temporary = tempfile::tempdir().unwrap();
        let paths = SystemServicePaths::for_test(temporary.path());
        make_package(&paths);
        let mut verifier = PackageVerifier::new(paths.clone());
        verifier.probe_versions = false;
        assert!(verifier.verify().await.is_ok());

        fs::write(paths.current_link.join("xray"), b"tampered").unwrap();
        fs::set_permissions(
            paths.current_link.join("xray"),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        let mut verifier = PackageVerifier::new(paths);
        verifier.probe_versions = false;
        assert!(verifier.verify().await.is_err());
    }

    #[tokio::test]
    async fn malformed_and_oversized_frames_do_not_reach_mutation_handler() {
        let temporary = tempfile::tempdir().unwrap();
        let paths = SystemServicePaths::for_test(temporary.path());
        make_socket_directory(&paths);
        let shutdown = CancellationToken::new();
        let handler = Arc::new(CountingHandler(AtomicUsize::new(0)));
        let server = tokio::spawn(serve_system_setup_socket(
            paths.clone(),
            Arc::new(AllowUid(paths.expected_service_uid)),
            handler.clone(),
            shutdown.clone(),
        ));
        for _ in 0..20 {
            if paths.socket_path.exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        let mut malformed = UnixStream::connect(&paths.socket_path).await.unwrap();
        write_frame(&mut malformed, b"{}", MAX_SYSTEM_REQUEST_BYTES)
            .await
            .unwrap();
        assert!(read_frame(&mut malformed, MAX_SYSTEM_RESPONSE_BYTES)
            .await
            .is_err());

        let mut oversized = UnixStream::connect(&paths.socket_path).await.unwrap();
        oversized
            .write_u32(u32::try_from(MAX_SYSTEM_REQUEST_BYTES + 1).unwrap())
            .await
            .unwrap();
        oversized.shutdown().await.unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(handler.0.load(Ordering::SeqCst), 0);
        shutdown.cancel();
        server.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn partial_frame_timeout_does_not_mutate_or_stop_server() {
        let temporary = tempfile::tempdir().unwrap();
        let paths = SystemServicePaths::for_test(temporary.path());
        make_socket_directory(&paths);
        let shutdown = CancellationToken::new();
        let handler = Arc::new(CountingHandler(AtomicUsize::new(0)));
        let server = tokio::spawn(serve_system_setup_socket(
            paths.clone(),
            Arc::new(AllowUid(paths.expected_service_uid)),
            handler.clone(),
            shutdown.clone(),
        ));
        for _ in 0..20 {
            if paths.socket_path.exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let mut partial = UnixStream::connect(&paths.socket_path).await.unwrap();
        partial.write_u32(4).await.unwrap();
        partial.write_all(b"{").await.unwrap();
        tokio::time::sleep(FRAME_IO_TIMEOUT + Duration::from_millis(50)).await;
        assert_eq!(handler.0.load(Ordering::SeqCst), 0);

        let client = SystemServiceClient::with_paths(paths.clone());
        let response = client
            .request(SystemSetupOperation::ClearManualEndpoint {})
            .await
            .unwrap();
        assert!(matches!(
            response.outcome,
            SystemSetupOutcome::Success { result }
                if matches!(*result, SystemSetupResult::ManualEndpointCleared {})
        ));
        shutdown.cancel();
        server.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn package_failure_precedes_invitation_parsing_and_persistence() {
        let temporary = tempfile::tempdir().unwrap();
        let paths = SystemServicePaths::for_test(temporary.path());
        make_active_directories(&paths);
        fs::create_dir(&paths.releases_dir).unwrap();
        let (generation, _) = watch::channel(0_u64);
        let (supervisor, _) = mpsc::channel(1);
        let executor = SystemSetupExecutor::new(paths.clone(), generation, supervisor);
        let marker = "invitation-must-never-be-written";
        let response = executor
            .handle(SystemSetupRequest {
                schema_version: 1,
                request_id: Uuid::new_v4(),
                operation: SystemSetupOperation::ConfirmSetup {
                    setup_invitation: SetupInvitation::new(marker.to_string()),
                    accept_host_owner: true,
                    accept_exit_ip: true,
                    accept_router_mapping: false,
                    accept_relay: false,
                    provider_policy: crate::ProviderPolicy::default(),
                },
            })
            .await;
        assert!(matches!(
            response.outcome,
            SystemSetupOutcome::Error {
                error: crate::SystemSetupError {
                    code: SystemSetupErrorCode::PackageVerificationFailed,
                    ..
                }
            }
        ));
        for entry in fs::read_dir(&paths.data_dir).unwrap() {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_file() {
                assert!(!fs::read(entry.path())
                    .unwrap()
                    .windows(marker.len())
                    .any(|bytes| bytes == marker.as_bytes()));
            }
        }
    }

    #[tokio::test]
    async fn unpair_waits_for_shutdown_then_removes_state_and_identity_offline() {
        let temporary = tempfile::tempdir().unwrap();
        let paths = SystemServicePaths::for_test(temporary.path());
        make_package(&paths);
        let node_id = seed_enrolled_system(&paths);
        let database = paths.data_dir.join("node-host.sqlite3");
        let identity_seed = paths.identity_dir.join("identity.ed25519.seed");
        assert!(database.exists());
        assert!(identity_seed.exists());

        let (generation, _) = watch::channel(0_u64);
        let (supervisor_tx, mut supervisor_rx) = mpsc::channel(1);
        let mut executor = SystemSetupExecutor::new(paths.clone(), generation, supervisor_tx);
        executor.verifier.probe_versions = false;
        let observed_paths = paths.clone();
        let supervisor = tokio::spawn(async move {
            let command = supervisor_rx.recv().await.unwrap();
            assert!(observed_paths.data_dir.join("node-host.sqlite3").exists());
            assert!(observed_paths
                .identity_dir
                .join("identity.ed25519.seed")
                .exists());
            command.ready.send(Ok(())).unwrap();
            command.release.await.unwrap();
            assert!(!observed_paths.data_dir.join("node-host.sqlite3").exists());
            assert!(!observed_paths
                .identity_dir
                .join("identity.ed25519.seed")
                .exists());
        });

        let response = executor
            .handle(SystemSetupRequest {
                schema_version: 1,
                request_id: Uuid::new_v4(),
                operation: SystemSetupOperation::Unpair {
                    confirm_node_id: node_id,
                },
            })
            .await;
        let result = match response.outcome {
            SystemSetupOutcome::Success { result } => result,
            outcome @ SystemSetupOutcome::Error { .. } => {
                panic!("unpair failed: {outcome:?}")
            }
        };
        let SystemSetupResult::Unpaired { status } = *result else {
            panic!("unexpected unpair result");
        };
        assert_eq!(status.phase, SystemServicePhase::Unpaired);
        assert_eq!(status.node_id, None);
        supervisor.await.unwrap();
        assert!(fs::read_dir(&paths.data_dir).unwrap().next().is_none());
        assert!(fs::read_dir(&paths.identity_dir).unwrap().next().is_none());
        assert_eq!(
            load_unpair_marker(&paths).unwrap().unwrap(),
            UnpairMarker {
                schema_version: 1,
                node_id,
                state: UnpairMarkerState::Complete,
            }
        );

        // Simulate a crash after deletion but before the completion marker,
        // then retry without another supervisor stop or Control connectivity.
        write_unpair_marker(&paths, node_id, UnpairMarkerState::Pending).unwrap();
        let retry = executor
            .handle(SystemSetupRequest {
                schema_version: 1,
                request_id: Uuid::new_v4(),
                operation: SystemSetupOperation::Unpair {
                    confirm_node_id: node_id,
                },
            })
            .await;
        assert!(matches!(retry.outcome, SystemSetupOutcome::Success { .. }));
        assert_eq!(
            load_unpair_marker(&paths).unwrap().unwrap().state,
            UnpairMarkerState::Complete
        );
    }

    #[tokio::test]
    async fn unpair_rejects_wrong_exact_id_without_quiescing_or_deleting() {
        let temporary = tempfile::tempdir().unwrap();
        let paths = SystemServicePaths::for_test(temporary.path());
        make_package(&paths);
        let node_id = seed_enrolled_system(&paths);
        let wrong_id = control_protocol::id::NodeId::new();
        assert_ne!(node_id, wrong_id);
        let (generation, _) = watch::channel(0_u64);
        let (supervisor_tx, mut supervisor_rx) = mpsc::channel(1);
        let executor = SystemSetupExecutor::new(paths.clone(), generation, supervisor_tx);

        let response = executor
            .handle(SystemSetupRequest {
                schema_version: 1,
                request_id: Uuid::new_v4(),
                operation: SystemSetupOperation::Unpair {
                    confirm_node_id: wrong_id,
                },
            })
            .await;
        assert!(matches!(
            response.outcome,
            SystemSetupOutcome::Error {
                error: crate::SystemSetupError {
                    code: SystemSetupErrorCode::ConfirmationMismatch,
                    retryable: false,
                }
            }
        ));
        assert!(paths.data_dir.join("node-host.sqlite3").exists());
        assert!(paths.identity_dir.join("identity.ed25519.seed").exists());
        assert!(supervisor_rx.try_recv().is_err());
    }

    #[test]
    fn production_layout_separates_root_assets_from_service_owned_unpair_state() {
        let temporary = tempfile::tempdir().unwrap();
        let paths = SystemServicePaths::for_test(temporary.path());
        assert_eq!(
            paths.data_dir.parent(),
            Some(paths.service_state_root.as_path())
        );
        assert_eq!(
            paths.identity_dir.parent(),
            Some(paths.service_state_root.as_path())
        );
        assert_eq!(
            paths.service_state_root.parent(),
            paths.releases_dir.parent()
        );
        assert_ne!(paths.service_state_root, paths.releases_dir);
        make_package(&paths);
        validate_private_service_directory(&paths.service_state_root, &paths).unwrap();
        validate_directory(
            paths.releases_dir.parent().unwrap(),
            paths.expected_root_uid,
            paths.expected_root_gid,
            false,
        )
        .unwrap();
        let postinstall = include_str!("../../packaging/macos/pkg-scripts/postinstall");
        assert!(postinstall.contains("SERVICE_STATE=\"$BASE/service-state\""));
        assert!(postinstall
            .contains("/usr/sbin/chown _privnetnode:_privnetnode \"$SERVICE_STATE\" \"$LOGS\""));
        assert!(postinstall.contains("/bin/chmod 700 \"$SERVICE_STATE\" \"$LOGS\""));
        assert!(postinstall.contains("RUNTIME=\"$BASE/run\""));
        assert!(postinstall.contains("/usr/sbin/chown root:_privnetnode \"$RUNTIME\""));
        assert!(postinstall.contains("/bin/chmod 775 \"$RUNTIME\""));
        assert!(postinstall.contains(
            "/usr/bin/sudo -u _privnetnode \"$BASE/current/node-host\" migrate-system-layout"
        ));
        assert!(postinstall.contains("[ \"$service_shell\" = /usr/bin/false ]"));
        assert!(postinstall.contains("[ \"$service_home\" = /var/empty ]"));
        assert!(postinstall.contains("[ \"$service_hidden\" = 1 ]"));
    }

    #[test]
    fn package_layout_migration_rebinds_only_the_same_moved_identity() {
        let temporary = tempfile::tempdir().unwrap();
        let paths = SystemServicePaths::for_test(temporary.path());
        let legacy_state = temporary.path().join("state");
        let legacy_identity = temporary.path().join("identity");
        let original = crate::initialize_with_identity_dir(
            &legacy_state,
            &legacy_identity,
            "http://127.0.0.1:9",
        )
        .unwrap();
        fs::create_dir(&paths.service_state_root).unwrap();
        fs::set_permissions(&paths.service_state_root, fs::Permissions::from_mode(0o700)).unwrap();
        fs::rename(&legacy_state, &paths.data_dir).unwrap();
        fs::rename(&legacy_identity, &paths.identity_dir).unwrap();

        migrate_layout_binding(&paths, std::slice::from_ref(&legacy_identity)).unwrap();
        let migrated = crate::status(&paths.data_dir).unwrap();
        assert_eq!(migrated.identity_public_key, original.identity_public_key);
        assert_eq!(
            migrated.encryption_public_key,
            original.encryption_public_key
        );
        assert!(!legacy_state.exists());
        assert!(!legacy_identity.exists());
    }
}
