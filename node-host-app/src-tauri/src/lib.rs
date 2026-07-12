use node_host::{
    ManualEndpointInput, ManualEndpointStatus, NodeSetupSession, NodeSetupSessionStore,
    ProviderPolicy, ProviderPolicyStatus, SetupInvitation, SystemServiceClient,
    SystemServiceStatus, SystemSetupOperation, SystemSetupOutcome, SystemSetupResponse,
    SystemSetupResult,
};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::process::Stdio;
use tauri::State;
use uuid::Uuid;

const SERVICE_LABEL: &str = "com.sky.realitynode.agent";
const AGENT_PATH: &str = "/Library/Application Support/Private Network Node/current/node-host";
const SERVICE_PATH: &str = "/Library/LaunchDaemons/com.sky.realitynode.agent.plist";
const STATE_PATH: &str = "/Library/Application Support/Private Network Node/service-state/state";

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

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ConfirmSystemSetupInput {
    authority: HostAuthorityInput,
    sharing: SharingConsentInput,
    provider_policy: ProviderPolicy,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct HostAuthorityInput {
    accept_host_owner: bool,
    accept_exit_ip: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SharingConsentInput {
    accept_router_mapping: bool,
    accept_relay: bool,
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

fn system_client() -> Result<SystemServiceClient, String> {
    SystemServiceClient::production()
        .map_err(|_| "The installed Node Host service is unavailable.".to_string())
}

fn system_result(response: SystemSetupResponse) -> Result<SystemSetupResult, String> {
    match response.outcome {
        SystemSetupOutcome::Success { result } => Ok(*result),
        SystemSetupOutcome::Error { error } => Err(if error.retryable {
            "The Node Host service could not complete this action. Try again.".to_string()
        } else {
            "The installed Node Host service rejected this action.".to_string()
        }),
    }
}

#[tauri::command]
async fn node_system_service_status() -> Result<SystemServiceStatus, String> {
    let response = system_client()?
        .request(SystemSetupOperation::Status {})
        .await
        .map_err(|_| "The Node Host service status is unavailable.".to_string())?;
    match system_result(response)? {
        SystemSetupResult::Status { status } => Ok(status),
        _ => Err("The Node Host service returned an unexpected response.".to_string()),
    }
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)] // Tauri deserializes owned command arguments.
async fn node_confirm_system_setup(
    session_id: Uuid,
    input: ConfirmSystemSetupInput,
    setups: State<'_, NodeSetupSessionStore>,
) -> Result<SystemServiceStatus, String> {
    let client = system_client()?;
    let pending = setups
        .checkout(session_id)
        .map_err(|_| "The setup session is missing or expired.".to_string())?;
    let operation = SystemSetupOperation::ConfirmSetup {
        setup_invitation: SetupInvitation::new(pending.setup_invitation().to_string()),
        accept_host_owner: input.authority.accept_host_owner,
        accept_exit_ip: input.authority.accept_exit_ip,
        accept_router_mapping: input.sharing.accept_router_mapping,
        accept_relay: input.sharing.accept_relay,
        provider_policy: input.provider_policy,
    };
    let Ok(response) = client.request(operation).await else {
        return if setups.restore(session_id, pending).unwrap_or(false) {
            Err("The Node Host service did not respond. Try again.".to_string())
        } else {
            Err("The setup code expired. Start setup again.".to_string())
        };
    };
    match response.outcome {
        SystemSetupOutcome::Success { result } => match *result {
            SystemSetupResult::SetupComplete { status } => Ok(status),
            _ => {
                if setups.restore(session_id, pending).unwrap_or(false) {
                    Err("The Node Host service returned an unexpected response.".to_string())
                } else {
                    Err("The setup code expired. Start setup again.".to_string())
                }
            }
        },
        SystemSetupOutcome::Error { error } => {
            if error.retryable {
                if setups.restore(session_id, pending).unwrap_or(false) {
                    Err("Setup did not complete. Try again.".to_string())
                } else {
                    Err("The setup code expired. Start setup again.".to_string())
                }
            } else {
                Err("The installed Node Host service rejected setup.".to_string())
            }
        }
    }
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)] // Tauri deserializes owned command arguments.
async fn node_update_provider_policy(
    provider_policy: ProviderPolicy,
) -> Result<ProviderPolicyStatus, String> {
    let response = system_client()?
        .request(SystemSetupOperation::UpdateProviderPolicy { provider_policy })
        .await
        .map_err(|_| "The Node Host service did not respond.".to_string())?;
    match system_result(response)? {
        SystemSetupResult::ProviderPolicyUpdated { status } => Ok(status),
        _ => Err("The Node Host service returned an unexpected response.".to_string()),
    }
}

async fn set_provider_pause(paused: bool) -> Result<ProviderPolicyStatus, String> {
    let operation = if paused {
        SystemSetupOperation::Pause {}
    } else {
        SystemSetupOperation::Resume {}
    };
    let response = system_client()?
        .request(operation)
        .await
        .map_err(|_| "The Node Host service did not respond.".to_string())?;
    match system_result(response)? {
        SystemSetupResult::ProviderPolicyUpdated { status } => Ok(status),
        _ => Err("The Node Host service returned an unexpected response.".to_string()),
    }
}

#[tauri::command]
async fn node_pause_provider() -> Result<ProviderPolicyStatus, String> {
    set_provider_pause(true).await
}

#[tauri::command]
async fn node_resume_provider() -> Result<ProviderPolicyStatus, String> {
    set_provider_pause(false).await
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)] // Tauri deserializes owned command arguments.
async fn node_configure_manual_endpoint(
    endpoint: ManualEndpointInput,
) -> Result<ManualEndpointStatus, String> {
    let response = system_client()?
        .request(SystemSetupOperation::ConfigureManualEndpoint { endpoint })
        .await
        .map_err(|_| "The Node Host service did not respond.".to_string())?;
    match system_result(response)? {
        SystemSetupResult::ManualEndpointUpdated { status } => Ok(status),
        _ => Err("The Node Host service returned an unexpected response.".to_string()),
    }
}

#[tauri::command]
async fn node_clear_manual_endpoint() -> Result<(), String> {
    let response = system_client()?
        .request(SystemSetupOperation::ClearManualEndpoint {})
        .await
        .map_err(|_| "The Node Host service did not respond.".to_string())?;
    match system_result(response)? {
        SystemSetupResult::ManualEndpointCleared {} => Ok(()),
        _ => Err("The Node Host service returned an unexpected response.".to_string()),
    }
}

#[tauri::command]
async fn node_unpair(confirm_node_id: Uuid) -> Result<SystemServiceStatus, String> {
    let confirm_node_id = confirm_node_id
        .to_string()
        .parse()
        .map_err(|_| "The node confirmation is invalid.".to_string())?;
    let response = system_client()?
        .request(SystemSetupOperation::Unpair { confirm_node_id })
        .await
        .map_err(|_| "The Node Host service did not respond.".to_string())?;
    match system_result(response)? {
        SystemSetupResult::Unpaired { status } => Ok(status),
        _ => Err("The Node Host service returned an unexpected response.".to_string()),
    }
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
            node_system_package_status,
            node_system_service_status,
            node_confirm_system_setup,
            node_update_provider_policy,
            node_pause_provider,
            node_resume_provider,
            node_configure_manual_endpoint,
            node_clear_manual_endpoint,
            node_unpair
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
