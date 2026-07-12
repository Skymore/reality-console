use node_host::{NodeSetupSession, NodeSetupSessionStore};
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::process::Stdio;
use tauri::State;
use uuid::Uuid;

const SERVICE_LABEL: &str = "com.sky.realitynode.agent";
const AGENT_PATH: &str = "/Library/Application Support/Private Network Node/current/node-host";
const SERVICE_PATH: &str = "/Library/LaunchDaemons/com.sky.realitynode.agent.plist";
const STATE_PATH: &str = "/Library/Application Support/Private Network Node/state";

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct SystemPackageStatus {
    platform: &'static str,
    agent: Presence,
    service_definition: Presence,
    service_registration: Presence,
    state_directory: Presence,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
enum Presence {
    Present,
    Missing,
}

impl From<bool> for Presence {
    fn from(present: bool) -> Self {
        if present {
            Self::Present
        } else {
            Self::Missing
        }
    }
}

fn regular_file(path: &Path) -> bool {
    path.symlink_metadata()
        .map(|metadata| metadata.file_type().is_file() && !metadata.file_type().is_symlink())
        .unwrap_or(false)
}

fn system_package_status_with(
    agent: &Path,
    service: &Path,
    state: &Path,
    service_loaded: impl FnOnce() -> bool,
) -> SystemPackageStatus {
    SystemPackageStatus {
        platform: std::env::consts::OS,
        agent: regular_file(agent).into(),
        service_definition: regular_file(service).into(),
        service_registration: service_loaded().into(),
        state_directory: state.is_dir().into(),
    }
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)] // Tauri deserializes owned command arguments.
fn node_begin_setup(
    input: String,
    setups: State<'_, NodeSetupSessionStore>,
) -> Result<NodeSetupSession, String> {
    setups
        .begin(&input)
        .map_err(|_| "The setup code is invalid or expired.".to_string())
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)] // Tauri extracts managed state by value.
fn node_cancel_setup(
    session_id: Uuid,
    setups: State<'_, NodeSetupSessionStore>,
) -> Result<bool, String> {
    setups
        .cancel(session_id)
        .map_err(|_| "The setup session could not be cancelled.".to_string())
}

#[tauri::command]
async fn node_system_package_status() -> Result<SystemPackageStatus, String> {
    tauri::async_runtime::spawn_blocking(|| {
        let loaded = || {
            #[cfg(target_os = "macos")]
            {
                Command::new("/bin/launchctl")
                    .args(["print", &format!("system/{SERVICE_LABEL}")])
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status()
                    .map(|status| status.success())
                    .unwrap_or(false)
            }
            #[cfg(not(target_os = "macos"))]
            {
                false
            }
        };
        system_package_status_with(
            &PathBuf::from(AGENT_PATH),
            &PathBuf::from(SERVICE_PATH),
            &PathBuf::from(STATE_PATH),
            loaded,
        )
    })
    .await
    .map_err(|_| "The package status check could not be completed.".to_string())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
/// Starts the native Node Host packaging shell.
///
/// # Panics
///
/// Panics when Tauri cannot initialize or run the application event loop.
pub fn run() {
    tauri::Builder::default()
        .manage(NodeSetupSessionStore::new())
        .invoke_handler(tauri::generate_handler![
            node_begin_setup,
            node_cancel_setup,
            node_system_package_status
        ])
        .run(tauri::generate_context!())
        .expect("failed to run the Private Network Node packaging shell");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn package_status_rejects_symlinked_agent() {
        let temporary = tempfile::tempdir().expect("tempdir");
        let real = temporary.path().join("real");
        let agent = temporary.path().join("agent");
        let service = temporary.path().join("service.plist");
        let state = temporary.path().join("state");
        fs::write(&real, "agent").expect("write agent");
        fs::write(&service, "plist").expect("write service");
        fs::create_dir(&state).expect("create state");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&real, &agent).expect("symlink agent");

        let status = system_package_status_with(&agent, &service, &state, || true);

        #[cfg(unix)]
        assert_eq!(status.agent, Presence::Missing);
        assert_eq!(status.service_definition, Presence::Present);
        assert_eq!(status.service_registration, Presence::Present);
        assert_eq!(status.state_directory, Presence::Present);
    }
}
