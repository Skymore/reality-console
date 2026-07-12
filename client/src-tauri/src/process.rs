use crate::core::config::{build_xray_config, DEFAULT_HTTP_PORT, DEFAULT_SOCKS_PORT};
use crate::core::connection::ConnectionProfile;
use crate::error::ClientError;
use crate::state::{ClientPhase, ClientState, ProxyMode};
use crate::system_proxy::SystemProxyManager;
use std::fs;
use std::io::Write;
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tauri::AppHandle;
use tauri_plugin_shell::process::{CommandChild, CommandEvent};
use tauri_plugin_shell::ShellExt;

const START_ATTEMPTS: usize = 50;
const START_RETRY_DELAY: Duration = Duration::from_millis(100);

#[derive(Clone)]
pub struct XraySupervisor {
    inner: Arc<Mutex<SupervisorInner>>,
    runtime_dir: PathBuf,
    system_proxy: SystemProxyManager,
    lifecycle: Arc<tokio::sync::Mutex<()>>,
    startup_recovered: Arc<AtomicBool>,
}

struct SupervisorInner {
    state: ClientState,
    child: Option<CommandChild>,
    config_path: Option<PathBuf>,
    generation: u64,
}

impl XraySupervisor {
    pub fn new(app_data_dir: PathBuf) -> Result<Self, ClientError> {
        let system_proxy = SystemProxyManager::new(&app_data_dir)?;
        Self::new_with_system_proxy(app_data_dir, system_proxy)
    }

    fn new_with_system_proxy(
        app_data_dir: PathBuf,
        system_proxy: SystemProxyManager,
    ) -> Result<Self, ClientError> {
        let runtime_dir = app_data_dir.join("runtime");
        fs::create_dir_all(&runtime_dir).map_err(|_| process_error("runtime_directory_failed"))?;
        remove_stale_runtime_config(&runtime_dir)?;

        Ok(Self {
            inner: Arc::new(Mutex::new(SupervisorInner {
                state: ClientState::disconnected(DEFAULT_SOCKS_PORT, DEFAULT_HTTP_PORT),
                child: None,
                config_path: None,
                generation: 0,
            })),
            runtime_dir,
            system_proxy,
            lifecycle: Arc::new(tokio::sync::Mutex::new(())),
            startup_recovered: Arc::new(AtomicBool::new(false)),
        })
    }

    pub fn snapshot(&self) -> Result<ClientState, ClientError> {
        self.inner
            .lock()
            .map(|inner| inner.state.clone())
            .map_err(|_| process_error("client_state_unavailable"))
    }

    pub async fn start(
        &self,
        app: &AppHandle,
        profile_id: String,
        profile: ConnectionProfile,
        mode: ProxyMode,
    ) -> Result<ClientState, ClientError> {
        let _lifecycle = self.lifecycle.lock().await;
        self.ensure_startup_recovery().await?;
        if let Some(state) = self.active_connection(&profile_id, mode)? {
            return Ok(state);
        }
        let generation = self.begin_start(profile_id, mode)?;
        if let Err(error) = ensure_port_available(DEFAULT_SOCKS_PORT)
            .and_then(|_| ensure_port_available(DEFAULT_HTTP_PORT))
        {
            self.fail(generation, &error);
            return Err(error);
        }
        let config_path = self.runtime_dir.join("xray-config.json");

        if let Err(error) = write_runtime_config(&config_path, &profile) {
            self.fail(generation, &error);
            return Err(error);
        }

        let command = match app.shell().sidecar("xray") {
            Ok(command) => command.args(["run", "-config", &config_path.to_string_lossy()]),
            Err(_) => {
                let error = process_error("xray_sidecar_unavailable");
                let _ = fs::remove_file(&config_path);
                self.fail(generation, &error);
                return Err(error);
            }
        };
        let (mut events, child) = match command.spawn() {
            Ok(result) => result,
            Err(_) => {
                let error = process_error("xray_start_failed");
                let _ = fs::remove_file(&config_path);
                self.fail(generation, &error);
                return Err(error);
            }
        };

        if let Err(error) = self.attach_child(generation, child, config_path.clone()) {
            let _ = fs::remove_file(config_path);
            return Err(error);
        }
        let monitor = self.clone();
        tauri::async_runtime::spawn(async move {
            while let Some(event) = events.recv().await {
                if matches!(event, CommandEvent::Terminated(_)) {
                    let _ = tokio::task::spawn_blocking(move || {
                        monitor.handle_termination(generation);
                    })
                    .await;
                    break;
                }
            }
        });

        for _ in 0..START_ATTEMPTS {
            if ports_ready(DEFAULT_SOCKS_PORT, DEFAULT_HTTP_PORT) {
                if mode == ProxyMode::System {
                    let proxy = self.system_proxy.clone();
                    let apply = match tokio::task::spawn_blocking(move || {
                        proxy.apply(DEFAULT_SOCKS_PORT, DEFAULT_HTTP_PORT)
                    })
                    .await
                    {
                        Ok(result) => result,
                        Err(_) => Err(process_error("system_proxy_task_failed")),
                    };
                    if let Err(error) = apply {
                        self.fail_start(generation, &error).await;
                        return Err(error);
                    }
                }
                return match self.mark_connected(generation) {
                    Ok(state) => Ok(state),
                    Err(error) => {
                        self.fail_start(generation, &error).await;
                        Err(error)
                    }
                };
            }
            if self.phase()? == ClientPhase::Failed {
                return Err(process_error("xray_exited_during_start"));
            }
            tokio::time::sleep(START_RETRY_DELAY).await;
        }

        let error = process_error("xray_start_timeout");
        self.fail_start(generation, &error).await;
        Err(error)
    }

    pub async fn stop(&self) -> Result<ClientState, ClientError> {
        let _lifecycle = self.lifecycle.lock().await;
        self.ensure_startup_recovery().await?;
        let (child, config_path, already_disconnected) = {
            let mut inner = self
                .inner
                .lock()
                .map_err(|_| process_error("client_state_unavailable"))?;
            let already_disconnected = inner.state.phase == ClientPhase::Disconnected;
            inner.generation = inner.generation.wrapping_add(1);
            if !already_disconnected {
                inner.state.phase = ClientPhase::Stopping;
            }
            (
                inner.child.take(),
                inner.config_path.take(),
                already_disconnected,
            )
        };
        cleanup_child(child, config_path);
        let restore = self.restore_proxy_async().await;
        self.finish_stop(restore, already_disconnected)
    }

    /// Performs crash recovery off the UI thread. Concurrent lifecycle operations wait for it.
    pub async fn startup_recovery(&self) -> Result<(), ClientError> {
        let _lifecycle = self.lifecycle.lock().await;
        self.ensure_startup_recovery().await
    }

    /// Synchronous fallback used only after Tauri has begun exiting.
    pub fn stop_blocking(&self) -> Result<ClientState, ClientError> {
        let (child, config_path) = {
            let mut inner = self
                .inner
                .lock()
                .map_err(|_| process_error("client_state_unavailable"))?;
            inner.generation = inner.generation.wrapping_add(1);
            inner.state.phase = ClientPhase::Stopping;
            (inner.child.take(), inner.config_path.take())
        };
        cleanup_child(child, config_path);
        let restore = self.system_proxy.restore_pending();
        self.startup_recovered
            .store(restore.is_ok(), Ordering::Release);
        self.finish_stop(restore, false)
    }

    fn begin_start(&self, profile_id: String, mode: ProxyMode) -> Result<u64, ClientError> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| process_error("client_state_unavailable"))?;
        if !matches!(
            inner.state.phase,
            ClientPhase::Disconnected | ClientPhase::Failed
        ) {
            return Err(process_error("xray_transition_in_progress"));
        }
        inner.generation = inner.generation.wrapping_add(1);
        inner.state.phase = ClientPhase::Starting;
        inner.state.active_profile_id = Some(profile_id);
        inner.state.mode = Some(mode);
        inner.state.error_code = None;
        inner.state.error_message = None;
        Ok(inner.generation)
    }

    fn active_connection(
        &self,
        profile_id: &str,
        mode: ProxyMode,
    ) -> Result<Option<ClientState>, ClientError> {
        let inner = self
            .inner
            .lock()
            .map_err(|_| process_error("client_state_unavailable"))?;
        let matches = inner.state.phase == ClientPhase::Connected
            && inner.state.active_profile_id.as_deref() == Some(profile_id)
            && inner.state.mode == Some(mode);
        Ok(matches.then(|| inner.state.clone()))
    }

    fn attach_child(
        &self,
        generation: u64,
        child: CommandChild,
        config_path: PathBuf,
    ) -> Result<(), ClientError> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| process_error("client_state_unavailable"))?;
        if inner.generation != generation {
            let _ = child.kill();
            return Err(process_error("xray_start_cancelled"));
        }
        inner.child = Some(child);
        inner.config_path = Some(config_path);
        Ok(())
    }

    fn mark_connected(&self, generation: u64) -> Result<ClientState, ClientError> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| process_error("client_state_unavailable"))?;
        if inner.generation != generation || inner.state.phase != ClientPhase::Starting {
            return Err(process_error("xray_start_cancelled"));
        }
        inner.state.phase = ClientPhase::Connected;
        Ok(inner.state.clone())
    }

    fn fail(&self, generation: u64, error: &ClientError) {
        if let Ok(mut inner) = self.inner.lock() {
            if inner.generation == generation {
                inner.state.phase = ClientPhase::Failed;
                inner.state.error_code = Some(error.code.clone());
                inner.state.error_message = Some(error.message.clone());
            }
        }
    }

    async fn fail_start(&self, generation: u64, error: &ClientError) {
        let (child, config_path) = if let Ok(mut inner) = self.inner.lock() {
            if inner.generation != generation {
                return;
            }
            inner.generation = inner.generation.wrapping_add(1);
            inner.state.phase = ClientPhase::Failed;
            inner.state.error_code = Some(error.code.clone());
            inner.state.error_message = Some(error.message.clone());
            (inner.child.take(), inner.config_path.take())
        } else {
            return;
        };
        cleanup_child(child, config_path);
        let restore = self.restore_proxy_async().await;
        if let Err(restore_error) = restore {
            self.record_restore_failure(&restore_error);
        }
    }

    fn handle_termination(&self, generation: u64) {
        let config_path = if let Ok(mut inner) = self.inner.lock() {
            if inner.generation != generation {
                return;
            }
            inner.child = None;
            inner.state.phase = ClientPhase::Failed;
            inner.state.error_code = Some("xray_exited_unexpectedly".to_string());
            inner.state.error_message = Some("Xray stopped unexpectedly.".to_string());
            inner.config_path.take()
        } else {
            None
        };
        if let Some(path) = config_path {
            let _ = fs::remove_file(path);
        }
        if let Err(error) = self.system_proxy.restore_pending() {
            self.startup_recovered.store(false, Ordering::Release);
            self.record_restore_failure(&error);
        } else {
            self.startup_recovered.store(true, Ordering::Release);
        }
    }

    async fn ensure_startup_recovery(&self) -> Result<(), ClientError> {
        if self.startup_recovered.load(Ordering::Acquire) {
            return Ok(());
        }
        let result = self.restore_proxy_async().await;
        if let Err(error) = &result {
            self.record_restore_failure(error);
        }
        result
    }

    async fn restore_proxy_async(&self) -> Result<(), ClientError> {
        let proxy = self.system_proxy.clone();
        let restore = tokio::task::spawn_blocking(move || proxy.restore_pending())
            .await
            .map_err(|_| process_error("system_proxy_task_failed"))?;
        self.startup_recovered
            .store(restore.is_ok(), Ordering::Release);
        restore
    }

    fn finish_stop(
        &self,
        restore: Result<(), ClientError>,
        already_disconnected: bool,
    ) -> Result<ClientState, ClientError> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| process_error("client_state_unavailable"))?;
        match restore {
            Ok(()) => {
                if !already_disconnected || inner.state.phase != ClientPhase::Disconnected {
                    inner.state = ClientState::disconnected(DEFAULT_SOCKS_PORT, DEFAULT_HTTP_PORT);
                }
                Ok(inner.state.clone())
            }
            Err(error) => {
                inner.state.phase = ClientPhase::Failed;
                inner.state.error_code = Some(error.code.clone());
                inner.state.error_message = Some(error.message.clone());
                Err(error)
            }
        }
    }

    fn record_restore_failure(&self, error: &ClientError) {
        if let Ok(mut inner) = self.inner.lock() {
            inner.state.phase = ClientPhase::Failed;
            inner.state.error_code = Some(error.code.clone());
            inner.state.error_message = Some(error.message.clone());
        }
    }

    fn phase(&self) -> Result<ClientPhase, ClientError> {
        self.inner
            .lock()
            .map(|inner| inner.state.phase)
            .map_err(|_| process_error("client_state_unavailable"))
    }
}

fn cleanup_child(child: Option<CommandChild>, config_path: Option<PathBuf>) {
    if let Some(child) = child {
        let _ = child.kill();
    }
    if let Some(path) = config_path {
        let _ = fs::remove_file(path);
    }
}

fn remove_stale_runtime_config(runtime_dir: &Path) -> Result<(), ClientError> {
    let path = runtime_dir.join("xray-config.json");
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(process_error("stale_config_remove_failed")),
    }
}

fn ensure_port_available(port: u16) -> Result<(), ClientError> {
    TcpListener::bind(("127.0.0.1", port))
        .map(drop)
        .map_err(|_| {
            ClientError::internal(
                "local_proxy_port_in_use",
                format!("Local proxy port {port} is already in use."),
            )
        })
}

fn ports_ready(socks_port: u16, http_port: u16) -> bool {
    TcpStream::connect(("127.0.0.1", socks_port)).is_ok()
        && TcpStream::connect(("127.0.0.1", http_port)).is_ok()
}

fn write_runtime_config(path: &Path, profile: &ConnectionProfile) -> Result<(), ClientError> {
    let config = build_xray_config(profile, DEFAULT_SOCKS_PORT, DEFAULT_HTTP_PORT);
    let bytes = serde_json::to_vec_pretty(&config).map_err(|_| process_error("config_failed"))?;
    let parent = path
        .parent()
        .ok_or_else(|| process_error("runtime_directory_failed"))?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)
        .map_err(|_| process_error("config_write_failed"))?;
    temporary
        .write_all(&bytes)
        .and_then(|_| temporary.as_file().sync_all())
        .map_err(|_| process_error("config_write_failed"))?;
    set_owner_only_permissions(temporary.path())?;
    temporary
        .persist(path)
        .map(|_| ())
        .map_err(|_| process_error("config_write_failed"))
}

#[cfg(unix)]
fn set_owner_only_permissions(path: &Path) -> Result<(), ClientError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .map_err(|_| process_error("config_permissions_failed"))
}

#[cfg(not(unix))]
fn set_owner_only_permissions(_path: &Path) -> Result<(), ClientError> {
    Ok(())
}

fn process_error(code: &str) -> ClientError {
    let message = match code {
        "xray_sidecar_unavailable" => "The bundled Xray core is unavailable.",
        "xray_start_timeout" => "Xray did not open its local proxy ports in time.",
        "xray_exited_during_start" => "Xray exited before the local proxy became ready.",
        _ => "The Xray process operation failed.",
    };
    ClientError::internal(code, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::system_proxy::SystemProxyAdapter;
    use serde_json::Value;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct FakeProxyAdapter {
        state: Mutex<Value>,
        restores: AtomicUsize,
        restore_delay: Duration,
    }

    impl SystemProxyAdapter for FakeProxyAdapter {
        fn platform(&self) -> &'static str {
            "process-test"
        }

        fn capture(&self) -> Result<Value, ClientError> {
            Ok(self.state.lock().unwrap().clone())
        }

        fn apply(
            &self,
            _snapshot: &Value,
            socks_port: u16,
            http_port: u16,
        ) -> Result<(), ClientError> {
            *self.state.lock().unwrap() =
                serde_json::json!({ "socks": socks_port, "http": http_port });
            Ok(())
        }

        fn restore(&self, snapshot: &Value) -> Result<(), ClientError> {
            std::thread::sleep(self.restore_delay);
            self.restores.fetch_add(1, Ordering::SeqCst);
            *self.state.lock().unwrap() = snapshot.clone();
            Ok(())
        }
    }

    fn fixture() -> (tempfile::TempDir, XraySupervisor, Arc<FakeProxyAdapter>) {
        let directory = tempfile::tempdir().unwrap();
        let adapter = Arc::new(FakeProxyAdapter {
            state: Mutex::new(serde_json::json!({ "original": true })),
            restores: AtomicUsize::new(0),
            restore_delay: Duration::ZERO,
        });
        let proxy =
            SystemProxyManager::new_with_adapter(directory.path(), adapter.clone()).unwrap();
        let supervisor =
            XraySupervisor::new_with_system_proxy(directory.path().to_path_buf(), proxy).unwrap();
        (directory, supervisor, adapter)
    }

    fn simulate_system_connection(directory: &Path, supervisor: &XraySupervisor) -> (u64, PathBuf) {
        supervisor
            .system_proxy
            .apply(DEFAULT_SOCKS_PORT, DEFAULT_HTTP_PORT)
            .unwrap();
        let config = directory.join("runtime/xray-config.json");
        fs::write(&config, b"ephemeral secret config").unwrap();
        let mut inner = supervisor.inner.lock().unwrap();
        inner.generation = 7;
        inner.state.phase = ClientPhase::Connected;
        inner.state.active_profile_id = Some("node-1".to_owned());
        inner.state.mode = Some(ProxyMode::System);
        inner.config_path = Some(config.clone());
        (inner.generation, config)
    }

    #[tokio::test]
    async fn stop_restores_proxy_and_deletes_runtime_config() {
        let (directory, supervisor, adapter) = fixture();
        let (_, config) = simulate_system_connection(directory.path(), &supervisor);

        let state = supervisor.stop().await.unwrap();
        assert_eq!(state.phase, ClientPhase::Disconnected);
        assert!(!config.exists());
        assert_eq!(adapter.restores.load(Ordering::SeqCst), 1);
        assert_eq!(
            *adapter.state.lock().unwrap(),
            serde_json::json!({ "original": true })
        );
    }

    #[test]
    fn unexpected_exit_restores_proxy_and_preserves_failed_state() {
        let (directory, supervisor, adapter) = fixture();
        let (generation, config) = simulate_system_connection(directory.path(), &supervisor);

        supervisor.handle_termination(generation);
        let state = supervisor.snapshot().unwrap();
        assert_eq!(state.phase, ClientPhase::Failed);
        assert_eq!(
            state.error_code.as_deref(),
            Some("xray_exited_unexpectedly")
        );
        assert!(!config.exists());
        assert_eq!(adapter.restores.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn failed_start_restores_proxy_and_deletes_runtime_config() {
        let (directory, supervisor, adapter) = fixture();
        let (generation, config) = simulate_system_connection(directory.path(), &supervisor);
        let error = process_error("xray_start_failed");

        supervisor.fail_start(generation, &error).await;
        let state = supervisor.snapshot().unwrap();
        assert_eq!(state.phase, ClientPhase::Failed);
        assert!(!config.exists());
        assert_eq!(adapter.restores.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn manual_stop_does_not_capture_or_mutate_system_proxy() {
        let (_directory, supervisor, adapter) = fixture();
        let state = supervisor.stop().await.unwrap();
        assert_eq!(state.phase, ClientPhase::Disconnected);
        assert_eq!(adapter.restores.load(Ordering::SeqCst), 0);
        assert_eq!(
            *adapter.state.lock().unwrap(),
            serde_json::json!({ "original": true })
        );
    }

    #[tokio::test]
    async fn construction_is_non_recovering_and_immediate_stop_joins_startup_gate() {
        let directory = tempfile::tempdir().unwrap();
        let adapter = Arc::new(FakeProxyAdapter {
            state: Mutex::new(serde_json::json!({ "original": true })),
            restores: AtomicUsize::new(0),
            restore_delay: Duration::from_millis(50),
        });
        let first_owner =
            SystemProxyManager::new_with_adapter(directory.path(), adapter.clone()).unwrap();
        first_owner
            .apply(DEFAULT_SOCKS_PORT, DEFAULT_HTTP_PORT)
            .unwrap();
        drop(first_owner);

        let rebuilt_owner =
            SystemProxyManager::new_with_adapter(directory.path(), adapter.clone()).unwrap();
        let supervisor =
            XraySupervisor::new_with_system_proxy(directory.path().to_path_buf(), rebuilt_owner)
                .unwrap();
        assert_eq!(adapter.restores.load(Ordering::SeqCst), 0);

        let (recovery, stop) = tokio::join!(supervisor.startup_recovery(), supervisor.stop());
        recovery.unwrap();
        assert_eq!(stop.unwrap().phase, ClientPhase::Disconnected);
        assert_eq!(adapter.restores.load(Ordering::SeqCst), 1);
        assert_eq!(
            *adapter.state.lock().unwrap(),
            serde_json::json!({ "original": true })
        );
    }
}
