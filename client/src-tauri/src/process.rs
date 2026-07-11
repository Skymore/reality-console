use crate::core::config::{build_xray_config, DEFAULT_HTTP_PORT, DEFAULT_SOCKS_PORT};
use crate::core::invite::RealityProfile;
use crate::error::ClientError;
use crate::state::{ClientPhase, ClientState, ProxyMode};
use std::fs;
use std::io::Write;
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
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
}

struct SupervisorInner {
    state: ClientState,
    child: Option<CommandChild>,
    config_path: Option<PathBuf>,
    generation: u64,
}

impl XraySupervisor {
    pub fn new(app_data_dir: PathBuf) -> Result<Self, ClientError> {
        let runtime_dir = app_data_dir.join("runtime");
        fs::create_dir_all(&runtime_dir).map_err(|_| process_error("runtime_directory_failed"))?;

        Ok(Self {
            inner: Arc::new(Mutex::new(SupervisorInner {
                state: ClientState::disconnected(DEFAULT_SOCKS_PORT, DEFAULT_HTTP_PORT),
                child: None,
                config_path: None,
                generation: 0,
            })),
            runtime_dir,
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
        profile: RealityProfile,
        mode: ProxyMode,
    ) -> Result<ClientState, ClientError> {
        if mode == ProxyMode::System {
            return Err(ClientError::internal(
                "system_proxy_not_available",
                "System proxy mode is not available in this build yet.",
            ));
        }

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

        let command = app
            .shell()
            .sidecar("xray")
            .map_err(|_| process_error("xray_sidecar_unavailable"))?
            .args(["run", "-config", &config_path.to_string_lossy()]);
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
                    monitor.handle_termination(generation);
                    break;
                }
            }
        });

        for _ in 0..START_ATTEMPTS {
            if ports_ready(DEFAULT_SOCKS_PORT, DEFAULT_HTTP_PORT) {
                return self.mark_connected(generation);
            }
            if self.phase()? == ClientPhase::Failed {
                return Err(process_error("xray_exited_during_start"));
            }
            tokio::time::sleep(START_RETRY_DELAY).await;
        }

        let _ = self.stop();
        Err(process_error("xray_start_timeout"))
    }

    pub fn stop(&self) -> Result<ClientState, ClientError> {
        let (child, config_path) = {
            let mut inner = self
                .inner
                .lock()
                .map_err(|_| process_error("client_state_unavailable"))?;
            if inner.state.phase == ClientPhase::Disconnected {
                return Ok(inner.state.clone());
            }
            inner.generation = inner.generation.wrapping_add(1);
            inner.state.phase = ClientPhase::Stopping;
            (inner.child.take(), inner.config_path.take())
        };

        if let Some(child) = child {
            let _ = child.kill();
        }
        if let Some(path) = config_path {
            let _ = fs::remove_file(path);
        }

        let mut inner = self
            .inner
            .lock()
            .map_err(|_| process_error("client_state_unavailable"))?;
        inner.state = ClientState::disconnected(DEFAULT_SOCKS_PORT, DEFAULT_HTTP_PORT);
        Ok(inner.state.clone())
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
    }

    fn phase(&self) -> Result<ClientPhase, ClientError> {
        self.inner
            .lock()
            .map(|inner| inner.state.phase)
            .map_err(|_| process_error("client_state_unavailable"))
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

fn write_runtime_config(path: &Path, profile: &RealityProfile) -> Result<(), ClientError> {
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
