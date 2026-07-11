use crate::background::{BackgroundServiceStatus, UserServiceInstallRequest, USER_SERVICE_LABEL};
use crate::{status as host_status, EnrollmentState};
use anyhow::{anyhow, bail, Context as _, Result};
use async_trait::async_trait;
use fs2::FileExt as _;
use nix::unistd::{Uid, User};
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;
use tokio::process::Command;
use tokio::time::{sleep, timeout};
use uuid::Uuid;

const PLATFORM: &str = "macos-user-launch-agent";
const LAUNCHCTL_PATH: &str = "/bin/launchctl";
const LAUNCHCTL_TIMEOUT: Duration = Duration::from_secs(15);
const LOCK_RELEASE_TIMEOUT: Duration = Duration::from_secs(5);
const LOCK_RELEASE_POLL: Duration = Duration::from_millis(100);
const LAUNCHD_MISSING_SERVICE_EXIT: i32 = 113;
const MAX_PLIST_BYTES: u64 = 64 * 1024;

#[derive(Debug)]
struct ServiceLayout {
    uid: u32,
    home_dir: PathBuf,
    launch_agents_dir: PathBuf,
    management_dir: PathBuf,
    plist_path: PathBuf,
    lock_path: PathBuf,
    domain: String,
    service_target: String,
}

impl ServiceLayout {
    fn current() -> Result<Self> {
        let effective_uid = Uid::effective();
        let uid = effective_uid.as_raw();
        if uid == 0 {
            bail!("the preview user service must be registered by the logged-in user, not root");
        }
        let user = User::from_uid(effective_uid)
            .context("failed to resolve the current user")?
            .context("the current user has no local account record")?;
        Self::new(&user.dir, uid)
    }

    fn new(home_dir: &Path, uid: u32) -> Result<Self> {
        if !home_dir.is_absolute() {
            bail!("the user home directory must be absolute");
        }
        let metadata = fs::symlink_metadata(home_dir)
            .with_context(|| format!("failed to inspect user home {}", home_dir.display()))?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            bail!("the user home directory must be a real directory, not a symlink");
        }
        if metadata.uid() != uid {
            bail!("the user home directory is not owned by the current user");
        }
        let home_dir = fs::canonicalize(home_dir).context("failed to canonicalize user home")?;
        let launch_agents_dir = home_dir.join("Library/LaunchAgents");
        let management_dir = home_dir.join("Library/Application Support/Private Network/Node Host");
        let plist_path = launch_agents_dir.join(format!("{USER_SERVICE_LABEL}.plist"));
        let lock_path = management_dir.join("service-management.lock");
        let domain = format!("gui/{uid}");
        let service_target = format!("{domain}/{USER_SERVICE_LABEL}");
        Ok(Self {
            uid,
            home_dir,
            launch_agents_dir,
            management_dir,
            plist_path,
            lock_path,
            domain,
            service_target,
        })
    }

    fn prepare_directories(&self) -> Result<()> {
        ensure_owned_directory(&self.launch_agents_dir, self.uid, false)?;
        ensure_owned_directory(&self.management_dir, self.uid, true)
    }
}

struct ServiceManagementLock {
    _file: File,
}

impl ServiceManagementLock {
    fn acquire(layout: &ServiceLayout) -> Result<Self> {
        layout.prepare_directories()?;
        let mut options = OpenOptions::new();
        options
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(nix::libc::O_NOFOLLOW);
        let file = options
            .open(&layout.lock_path)
            .context("failed to open the service-management lock")?;
        let metadata = file
            .metadata()
            .context("failed to inspect the service-management lock")?;
        if !metadata.is_file() || metadata.uid() != layout.uid {
            bail!("the service-management lock is not an owner-controlled regular file");
        }
        fs::set_permissions(&layout.lock_path, fs::Permissions::from_mode(0o600))?;
        file.try_lock_exclusive()
            .context("another Node Host service operation is already running")?;
        Ok(Self { _file: file })
    }
}

#[derive(Debug, Clone)]
struct LaunchctlOutput {
    code: Option<i32>,
    stderr: String,
}

impl LaunchctlOutput {
    #[cfg(test)]
    fn success() -> Self {
        Self {
            code: Some(0),
            stderr: String::new(),
        }
    }

    #[cfg(test)]
    fn failed(code: i32, stderr: impl Into<String>) -> Self {
        Self {
            code: Some(code),
            stderr: stderr.into(),
        }
    }

    fn is_success(&self) -> bool {
        self.code == Some(0)
    }
}

#[async_trait]
trait LaunchctlRunner: Send + Sync {
    async fn run(&self, arguments: &[OsString]) -> Result<LaunchctlOutput>;
}

struct SystemLaunchctl;

#[async_trait]
impl LaunchctlRunner for SystemLaunchctl {
    async fn run(&self, arguments: &[OsString]) -> Result<LaunchctlOutput> {
        let mut command = Command::new(LAUNCHCTL_PATH);
        command
            .args(arguments)
            .stdout(Stdio::null())
            .kill_on_drop(true);
        let output = timeout(LAUNCHCTL_TIMEOUT, command.output())
            .await
            .context("launchctl timed out")?
            .context("failed to execute launchctl")?;
        Ok(LaunchctlOutput {
            code: output.status.code(),
            stderr: bounded_stderr(&output.stderr),
        })
    }
}

pub(crate) async fn install(
    data_dir: &Path,
    request: &UserServiceInstallRequest,
) -> Result<BackgroundServiceStatus> {
    let layout = ServiceLayout::current()?;
    install_with(&layout, data_dir, request, &SystemLaunchctl).await
}

pub(crate) async fn status() -> Result<BackgroundServiceStatus> {
    let layout = ServiceLayout::current()?;
    status_with(&layout, &SystemLaunchctl).await
}

pub(crate) async fn remove() -> Result<BackgroundServiceStatus> {
    let layout = ServiceLayout::current()?;
    remove_with(&layout, &SystemLaunchctl).await
}

async fn install_with(
    layout: &ServiceLayout,
    data_dir: &Path,
    request: &UserServiceInstallRequest,
    launchctl: &dyn LaunchctlRunner,
) -> Result<BackgroundServiceStatus> {
    let agent_binary = validate_agent_binary(&request.agent_binary_path, layout.uid)?;
    let data_dir = validate_data_dir(data_dir, layout)?;
    let manifest = render_manifest(&agent_binary, &data_dir)?;
    let _lock = ServiceManagementLock::acquire(layout)?;
    let previous_manifest = read_existing_manifest(layout)?;
    let previously_loaded = is_loaded(layout, launchctl).await?;
    if previously_loaded && previous_manifest.is_none() {
        bail!("launchd has a loaded Node Host service but its definition is missing");
    }
    if previously_loaded {
        run_required(
            launchctl,
            "stop the existing Node Host service",
            vec!["bootout".into(), layout.service_target.clone().into()],
        )
        .await?;
    }

    let install_result = async {
        let local_status = wait_for_host_status(&data_dir).await?;
        if local_status.enrollment_state != EnrollmentState::Enrolled {
            bail!("Node Host must finish enrollment before its background service is installed");
        }
        write_manifest_atomically(layout, manifest.as_bytes())?;
        run_required(
            launchctl,
            "enable the Node Host service",
            vec!["enable".into(), layout.service_target.clone().into()],
        )
        .await?;
        run_required(
            launchctl,
            "register the Node Host service",
            vec![
                "bootstrap".into(),
                layout.domain.clone().into(),
                layout.plist_path.as_os_str().to_owned(),
            ],
        )
        .await?;
        run_required(
            launchctl,
            "start the Node Host service",
            vec!["kickstart".into(), layout.service_target.clone().into()],
        )
        .await?;
        let current = status_with(layout, launchctl).await?;
        if !current.installed || !current.loaded {
            bail!("launchd did not retain the Node Host service registration");
        }
        Ok(current)
    }
    .await;

    match install_result {
        Ok(current) => Ok(current),
        Err(install_error) => {
            let rollback = rollback_install(
                layout,
                previous_manifest.as_deref(),
                previously_loaded,
                launchctl,
            )
            .await;
            match rollback {
                Ok(()) => Err(install_error)
                    .context("Node Host background-service installation failed; service state was restored"),
                Err(rollback_error) => Err(anyhow!(
                    "Node Host background-service installation failed ({install_error:#}); rollback also failed ({rollback_error:#})"
                )),
            }
        }
    }
}

async fn rollback_install(
    layout: &ServiceLayout,
    previous_manifest: Option<&[u8]>,
    previously_loaded: bool,
    launchctl: &dyn LaunchctlRunner,
) -> Result<()> {
    if is_loaded(layout, launchctl).await? {
        run_required(
            launchctl,
            "stop the failed Node Host service",
            vec!["bootout".into(), layout.service_target.clone().into()],
        )
        .await?;
    }
    match previous_manifest {
        Some(contents) => write_manifest_atomically(layout, contents)?,
        None => remove_manifest(layout)?,
    }
    if previously_loaded {
        run_required(
            launchctl,
            "restore the previous Node Host service",
            vec![
                "bootstrap".into(),
                layout.domain.clone().into(),
                layout.plist_path.as_os_str().to_owned(),
            ],
        )
        .await?;
        run_required(
            launchctl,
            "restart the previous Node Host service",
            vec!["kickstart".into(), layout.service_target.clone().into()],
        )
        .await?;
    }
    Ok(())
}

async fn remove_with(
    layout: &ServiceLayout,
    launchctl: &dyn LaunchctlRunner,
) -> Result<BackgroundServiceStatus> {
    let _lock = ServiceManagementLock::acquire(layout)?;
    if is_loaded(layout, launchctl).await? {
        run_required(
            launchctl,
            "stop the Node Host service",
            vec!["bootout".into(), layout.service_target.clone().into()],
        )
        .await?;
    }
    remove_manifest(layout)?;
    let current = status_with(layout, launchctl).await?;
    if current.installed || current.loaded {
        bail!("Node Host service removal did not converge");
    }
    Ok(current)
}

async fn status_with(
    layout: &ServiceLayout,
    launchctl: &dyn LaunchctlRunner,
) -> Result<BackgroundServiceStatus> {
    Ok(BackgroundServiceStatus {
        platform: PLATFORM,
        label: USER_SERVICE_LABEL,
        installed: inspect_manifest(layout)?,
        loaded: is_loaded(layout, launchctl).await?,
    })
}

async fn wait_for_host_status(data_dir: &Path) -> Result<crate::HostStatus> {
    let deadline = tokio::time::Instant::now() + LOCK_RELEASE_TIMEOUT;
    loop {
        match host_status(data_dir) {
            Ok(status) => return Ok(status),
            Err(error) if data_dir_is_busy(&error) && tokio::time::Instant::now() < deadline => {
                sleep(LOCK_RELEASE_POLL).await;
            }
            Err(error) => return Err(error).context("failed to verify Node Host enrollment state"),
        }
    }
}

fn data_dir_is_busy(error: &anyhow::Error) -> bool {
    error
        .chain()
        .any(|cause| cause.to_string().contains("already in use"))
}

async fn is_loaded(layout: &ServiceLayout, launchctl: &dyn LaunchctlRunner) -> Result<bool> {
    let output = launchctl
        .run(&["print".into(), layout.service_target.clone().into()])
        .await
        .context("failed to query launchd")?;
    if output.is_success() {
        return Ok(true);
    }
    if output.code == Some(LAUNCHD_MISSING_SERVICE_EXIT) {
        return Ok(false);
    }
    bail!(
        "launchd status query failed with {}: {}",
        display_exit_code(output.code),
        output.stderr
    );
}

async fn run_required(
    launchctl: &dyn LaunchctlRunner,
    operation: &str,
    arguments: Vec<OsString>,
) -> Result<()> {
    let output = launchctl
        .run(&arguments)
        .await
        .with_context(|| format!("failed to {operation}"))?;
    if !output.is_success() {
        bail!(
            "failed to {operation}; launchctl exited with {}: {}",
            display_exit_code(output.code),
            output.stderr
        );
    }
    Ok(())
}

fn display_exit_code(code: Option<i32>) -> String {
    code.map_or_else(|| "a signal".to_owned(), |value| value.to_string())
}

fn bounded_stderr(bytes: &[u8]) -> String {
    const MAX_BYTES: usize = 2 * 1024;
    let value = String::from_utf8_lossy(&bytes[..bytes.len().min(MAX_BYTES)]);
    value
        .chars()
        .map(|character| {
            if character == '\n' || character == '\t' || !character.is_control() {
                character
            } else {
                ' '
            }
        })
        .collect::<String>()
        .trim()
        .to_owned()
}

fn validate_agent_binary(path: &Path, uid: u32) -> Result<PathBuf> {
    if !path.is_absolute() {
        bail!("the Node Host agent binary path must be absolute");
    }
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect Node Host binary {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!("the Node Host agent binary must be a regular non-symlink file");
    }
    if metadata.uid() != uid && metadata.uid() != 0 {
        bail!("the Node Host agent binary must be owned by the current user or root");
    }
    if metadata.permissions().mode() & 0o022 != 0 {
        bail!("the Node Host agent binary must not be group- or world-writable");
    }
    if metadata.permissions().mode() & 0o111 == 0 {
        bail!("the Node Host agent binary must be executable");
    }
    fs::canonicalize(path).context("failed to canonicalize the Node Host agent binary")
}

fn validate_data_dir(path: &Path, layout: &ServiceLayout) -> Result<PathBuf> {
    if !path.is_absolute() {
        bail!("the Node Host data directory must be absolute");
    }
    let metadata = fs::symlink_metadata(path).with_context(|| {
        format!(
            "failed to inspect Node Host data directory {}",
            path.display()
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!("the Node Host data directory must be a real directory, not a symlink");
    }
    if metadata.uid() != layout.uid {
        bail!("the Node Host data directory is not owned by the current user");
    }
    if metadata.permissions().mode() & 0o077 != 0 {
        bail!("the Node Host data directory must be accessible only to its owner");
    }
    let canonical = fs::canonicalize(path).context("failed to canonicalize Node Host data")?;
    if !canonical.starts_with(&layout.home_dir) {
        bail!("the preview user service requires its data directory inside the user home");
    }
    Ok(canonical)
}

fn ensure_owned_directory(path: &Path, uid: u32, owner_only: bool) -> Result<()> {
    fs::create_dir_all(path).with_context(|| format!("failed to create {}", path.display()))?;
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() || metadata.uid() != uid {
        bail!("service directory must be a current-user-owned real directory");
    }
    if owner_only {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn render_manifest(agent_binary: &Path, data_dir: &Path) -> Result<String> {
    let binary = xml_escape(path_text(agent_binary, "agent binary")?)?;
    let data = xml_escape(path_text(data_dir, "data directory")?)?;
    Ok(format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \
\"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
<plist version=\"1.0\">\n\
<dict>\n\
  <key>Label</key>\n\
  <string>{USER_SERVICE_LABEL}</string>\n\
  <key>ProgramArguments</key>\n\
  <array>\n\
    <string>{binary}</string>\n\
    <string>run</string>\n\
    <string>--data-dir</string>\n\
    <string>{data}</string>\n\
  </array>\n\
  <key>WorkingDirectory</key>\n\
  <string>{data}</string>\n\
  <key>RunAtLoad</key>\n\
  <true/>\n\
  <key>KeepAlive</key>\n\
  <true/>\n\
  <key>ProcessType</key>\n\
  <string>Background</string>\n\
  <key>ThrottleInterval</key>\n\
  <integer>10</integer>\n\
  <key>Umask</key>\n\
  <integer>63</integer>\n\
</dict>\n\
</plist>\n"
    ))
}

fn path_text<'a>(path: &'a Path, purpose: &str) -> Result<&'a str> {
    path.to_str()
        .with_context(|| format!("the {purpose} path must be valid UTF-8 for launchd"))
}

fn xml_escape(value: &str) -> Result<String> {
    if value
        .chars()
        .any(|character| character.is_control() && !matches!(character, '\t' | '\n' | '\r'))
    {
        bail!("launchd paths cannot contain XML control characters");
    }
    Ok(value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;"))
}

fn inspect_manifest(layout: &ServiceLayout) -> Result<bool> {
    match fs::symlink_metadata(&layout.plist_path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink()
                || !metadata.is_file()
                || metadata.uid() != layout.uid
                || metadata.len() > MAX_PLIST_BYTES
                || metadata.permissions().mode() & 0o077 != 0
            {
                bail!("the Node Host service definition is not an owner-only regular file");
            }
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).context("failed to inspect the Node Host service definition"),
    }
}

fn read_existing_manifest(layout: &ServiceLayout) -> Result<Option<Vec<u8>>> {
    if !inspect_manifest(layout)? {
        return Ok(None);
    }
    fs::read(&layout.plist_path)
        .map(Some)
        .context("failed to read the existing Node Host service definition")
}

fn write_manifest_atomically(layout: &ServiceLayout, contents: &[u8]) -> Result<()> {
    if contents.len() as u64 > MAX_PLIST_BYTES {
        bail!("the Node Host service definition is unexpectedly large");
    }
    inspect_manifest(layout)?;
    let temporary = layout
        .launch_agents_dir
        .join(format!(".{USER_SERVICE_LABEL}.{}.tmp", Uuid::new_v4()));
    let write_result = (|| -> Result<()> {
        let mut options = OpenOptions::new();
        options
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(nix::libc::O_NOFOLLOW);
        let mut file = options
            .open(&temporary)
            .context("failed to create a temporary service definition")?;
        file.write_all(contents)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temporary, &layout.plist_path)?;
        sync_directory(&layout.launch_agents_dir)
    })();
    if write_result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    write_result.context("failed to install the Node Host service definition")
}

fn remove_manifest(layout: &ServiceLayout) -> Result<()> {
    if inspect_manifest(layout)? {
        fs::remove_file(&layout.plist_path)
            .context("failed to remove the Node Host service definition")?;
        sync_directory(&layout.launch_agents_dir)?;
    }
    Ok(())
}

fn sync_directory(path: &Path) -> Result<()> {
    File::open(path)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::{params, Connection};
    use std::collections::VecDeque;
    use std::sync::Mutex;

    #[derive(Default)]
    struct FakeLaunchctl {
        outputs: Mutex<VecDeque<LaunchctlOutput>>,
        calls: Mutex<Vec<Vec<String>>>,
    }

    impl FakeLaunchctl {
        fn with_outputs(outputs: impl IntoIterator<Item = LaunchctlOutput>) -> Self {
            Self {
                outputs: Mutex::new(outputs.into_iter().collect()),
                calls: Mutex::new(Vec::new()),
            }
        }

        fn calls(&self) -> Vec<Vec<String>> {
            self.calls.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl LaunchctlRunner for FakeLaunchctl {
        async fn run(&self, arguments: &[OsString]) -> Result<LaunchctlOutput> {
            self.calls.lock().unwrap().push(
                arguments
                    .iter()
                    .map(|value| value.to_string_lossy().into_owned())
                    .collect(),
            );
            self.outputs
                .lock()
                .unwrap()
                .pop_front()
                .context("fake launchctl output exhausted")
        }
    }

    fn fixture() -> (tempfile::TempDir, ServiceLayout, PathBuf, PathBuf) {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("home & host");
        fs::create_dir(&home).unwrap();
        let uid = Uid::effective().as_raw();
        let layout = ServiceLayout::new(&home, uid).unwrap();
        let data_dir = home.join("Library/Application Support/Private Network/state");
        crate::initialize(&data_dir, "https://controller.example").unwrap();
        let agent = home.join("Node & Host");
        fs::write(&agent, b"test agent").unwrap();
        fs::set_permissions(&agent, fs::Permissions::from_mode(0o700)).unwrap();
        (temp, layout, data_dir, agent)
    }

    fn mark_enrolled(data_dir: &Path) {
        let connection = Connection::open(data_dir.join("node-host.sqlite3")).unwrap();
        connection
            .execute(
                "INSERT INTO enrollment_registration(
                    singleton, invitation_id, network_id, node_id, controller_instance_id,
                    controller_fingerprint, controller_signing_public_key, credential_key_id,
                    credential_mode, credential_expires_at, enrolled_at
                 ) VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                params![
                    "00000000-0000-4000-8000-000000000001",
                    "00000000-0000-4000-8000-000000000002",
                    "00000000-0000-4000-8000-000000000003",
                    "00000000-0000-4000-8000-000000000004",
                    "sha256:test",
                    "test-public-key",
                    "00000000-0000-4000-8000-000000000005",
                    "signed-request-v1",
                    "2099-01-01T00:00:00Z",
                    1_i64,
                ],
            )
            .unwrap();
    }

    #[test]
    fn manifest_contains_only_the_fixed_agent_command_and_escaped_paths() {
        let (_temp, _layout, data_dir, agent) = fixture();
        let manifest = render_manifest(&agent, &data_dir).unwrap();
        assert!(manifest.contains("<string>run</string>"));
        assert!(manifest.contains("<string>--data-dir</string>"));
        assert!(manifest.contains("Node &amp; Host"));
        assert!(manifest.contains("home &amp; host"));
        assert!(manifest.contains("<key>KeepAlive</key>\n<true/>"));
        assert!(!manifest.contains("invitation"));
        assert!(!manifest.contains("PreventSystemSleep"));
    }

    #[tokio::test]
    async fn install_rejects_unenrolled_state_before_writing_a_definition() {
        let (_temp, layout, data_dir, agent) = fixture();
        let launchctl = FakeLaunchctl::with_outputs([
            LaunchctlOutput::failed(LAUNCHD_MISSING_SERVICE_EXIT, "missing"),
            LaunchctlOutput::failed(LAUNCHD_MISSING_SERVICE_EXIT, "missing"),
        ]);
        let error = install_with(
            &layout,
            &data_dir,
            &UserServiceInstallRequest::new(agent),
            &launchctl,
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("service state was restored"));
        assert!(!layout.plist_path.exists());
        assert_eq!(launchctl.calls().len(), 2);
    }

    #[tokio::test]
    async fn install_registers_an_enrolled_host_and_persists_owner_only_manifest() {
        let (_temp, layout, data_dir, agent) = fixture();
        mark_enrolled(&data_dir);
        let launchctl = FakeLaunchctl::with_outputs([
            LaunchctlOutput::failed(LAUNCHD_MISSING_SERVICE_EXIT, "missing"),
            LaunchctlOutput::success(),
            LaunchctlOutput::success(),
            LaunchctlOutput::success(),
            LaunchctlOutput::success(),
        ]);
        let service = install_with(
            &layout,
            &data_dir,
            &UserServiceInstallRequest::new(agent),
            &launchctl,
        )
        .await
        .unwrap();
        assert!(service.installed);
        assert!(service.loaded);
        assert_eq!(
            fs::metadata(&layout.plist_path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        let calls = launchctl.calls();
        assert_eq!(calls[1][0], "enable");
        assert_eq!(calls[2][0], "bootstrap");
        assert_eq!(calls[3][0], "kickstart");
    }

    #[tokio::test]
    async fn failed_replacement_restores_the_previous_manifest_and_service() {
        let (_temp, layout, data_dir, agent) = fixture();
        mark_enrolled(&data_dir);
        layout.prepare_directories().unwrap();
        write_manifest_atomically(&layout, b"previous manifest").unwrap();
        let launchctl = FakeLaunchctl::with_outputs([
            LaunchctlOutput::success(),
            LaunchctlOutput::success(),
            LaunchctlOutput::success(),
            LaunchctlOutput::failed(5, "bootstrap failed"),
            LaunchctlOutput::failed(LAUNCHD_MISSING_SERVICE_EXIT, "missing"),
            LaunchctlOutput::success(),
            LaunchctlOutput::success(),
        ]);
        let error = install_with(
            &layout,
            &data_dir,
            &UserServiceInstallRequest::new(agent),
            &launchctl,
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("service state was restored"));
        assert_eq!(fs::read(&layout.plist_path).unwrap(), b"previous manifest");
        let calls = launchctl.calls();
        assert_eq!(calls[0][0], "print");
        assert_eq!(calls[1][0], "bootout");
        assert_eq!(calls[5][0], "bootstrap");
        assert_eq!(calls[6][0], "kickstart");
    }

    #[test]
    fn group_writable_agent_binary_is_rejected() {
        let (_temp, layout, _data_dir, agent) = fixture();
        fs::set_permissions(&agent, fs::Permissions::from_mode(0o720)).unwrap();
        let error = validate_agent_binary(&agent, layout.uid).unwrap_err();
        assert!(error.to_string().contains("group- or world-writable"));
    }
}
