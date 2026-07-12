pub mod bundle;
pub mod connect_service;
pub mod control_api;
mod core;
mod error;
mod member_setup;
mod process;
mod profile;
mod runtime;
pub mod selection;
pub mod session;
mod state;
pub mod vault;

use core::config::{build_xray_config, DEFAULT_HTTP_PORT, DEFAULT_SOCKS_PORT};
use core::invite::{parse_invitation, InvitationPreview};
use error::ClientError;
use member_setup::{MemberSetupSession, SetupSessionStore};
use process::XraySupervisor;
use profile::{ProfileRepository, StoredProfile};
use runtime::ConnectRuntimeRegistry;
use selection::SelectionMode;
use session::DeviceMetadata;
use state::{ClientState, ProxyMode};
use tauri::{AppHandle, Manager, State};
use uuid::Uuid;

async fn run_blocking<T, F>(task: F) -> Result<T, ClientError>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, ClientError> + Send + 'static,
{
    tauri::async_runtime::spawn_blocking(task)
        .await
        .map_err(|_| {
            ClientError::internal(
                "background_task_failed",
                "The background operation could not be completed.",
            )
        })?
}

#[tauri::command]
fn client_get_state(supervisor: State<'_, XraySupervisor>) -> Result<ClientState, ClientError> {
    supervisor.snapshot()
}

#[tauri::command]
async fn client_start(
    profile_id: String,
    mode: ProxyMode,
    app: AppHandle,
    profiles: State<'_, ProfileRepository>,
    supervisor: State<'_, XraySupervisor>,
) -> Result<ClientState, ClientError> {
    let repository = profiles.inner().clone();
    let id_for_load = profile_id.clone();
    let profile = run_blocking(move || repository.load_connection(&id_for_load)).await?;
    supervisor.start(&app, profile_id, profile, mode).await
}

#[tauri::command]
fn client_stop(supervisor: State<'_, XraySupervisor>) -> Result<ClientState, ClientError> {
    supervisor.stop()
}

#[tauri::command]
fn client_preview_invitation(invitation: String) -> Result<InvitationPreview, ClientError> {
    parse_invitation(&invitation).map(|profile| {
        // Build once during validation so an accepted invitation is guaranteed to map to the
        // runtime configuration shape without exposing that configuration to the renderer.
        let _config = build_xray_config(&profile, DEFAULT_SOCKS_PORT, DEFAULT_HTTP_PORT);
        InvitationPreview::from(&profile)
    })
}

#[tauri::command]
async fn client_list_profiles(
    profiles: State<'_, ProfileRepository>,
) -> Result<Vec<StoredProfile>, ClientError> {
    let profiles = profiles.inner().clone();
    run_blocking(move || profiles.list()).await
}

#[tauri::command]
async fn client_import_profile(
    invitation: String,
    name: Option<String>,
    profiles: State<'_, ProfileRepository>,
) -> Result<StoredProfile, ClientError> {
    let profiles = profiles.inner().clone();
    run_blocking(move || profiles.import(&invitation, name.as_deref())).await
}

#[tauri::command]
async fn client_rename_profile(
    profile_id: String,
    name: String,
    profiles: State<'_, ProfileRepository>,
) -> Result<StoredProfile, ClientError> {
    let profiles = profiles.inner().clone();
    run_blocking(move || profiles.rename(&profile_id, &name)).await
}

#[tauri::command]
async fn client_delete_profile(
    profile_id: String,
    profiles: State<'_, ProfileRepository>,
) -> Result<(), ClientError> {
    let profiles = profiles.inner().clone();
    run_blocking(move || profiles.delete(&profile_id)).await
}

#[tauri::command]
async fn client_preview_profile(
    profile_id: String,
    profiles: State<'_, ProfileRepository>,
) -> Result<InvitationPreview, ClientError> {
    let profiles = profiles.inner().clone();
    run_blocking(move || {
        profiles
            .load_connection(&profile_id)
            .map(|profile| InvitationPreview::from(&profile))
    })
    .await
}

#[tauri::command]
fn connect_begin_setup(
    input: String,
    setups: State<'_, SetupSessionStore>,
) -> Result<MemberSetupSession, ClientError> {
    setups.begin(&input)
}

#[tauri::command]
async fn connect_cancel_setup(
    session_id: Uuid,
    setups: State<'_, SetupSessionStore>,
    runtime: State<'_, ConnectRuntimeRegistry>,
) -> Result<bool, ClientError> {
    runtime.cancel_setup(&setups, session_id).await
}

#[tauri::command]
async fn connect_confirm_setup(
    session_id: Uuid,
    device_name: String,
    setups: State<'_, SetupSessionStore>,
    runtime: State<'_, ConnectRuntimeRegistry>,
) -> Result<connect_service::ConnectSnapshot, ClientError> {
    runtime
        .confirm_setup(
            &setups,
            session_id,
            DeviceMetadata {
                display_name: device_name,
                client_version: env!("CARGO_PKG_VERSION").to_string(),
                platform: format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH),
            },
        )
        .await
}

#[tauri::command]
async fn connect_get_snapshot(
    runtime: State<'_, ConnectRuntimeRegistry>,
) -> Result<Option<connect_service::ConnectSnapshot>, ClientError> {
    runtime.snapshot().await
}

#[tauri::command]
async fn connect_refresh_bundle(
    app: AppHandle,
    runtime: State<'_, ConnectRuntimeRegistry>,
) -> Result<connect_service::ConnectSnapshot, ClientError> {
    runtime.refresh_bundle(&app).await
}

#[tauri::command]
async fn connect_probe_nodes(
    runtime: State<'_, ConnectRuntimeRegistry>,
) -> Result<connect_service::ConnectSnapshot, ClientError> {
    runtime.probe_nodes().await
}

#[tauri::command]
async fn connect_set_selection(
    selection: SelectionMode,
    runtime: State<'_, ConnectRuntimeRegistry>,
) -> Result<connect_service::ConnectSnapshot, ClientError> {
    runtime.set_selection(selection).await
}

#[tauri::command]
async fn connect_start(
    mode: ProxyMode,
    app: AppHandle,
    runtime: State<'_, ConnectRuntimeRegistry>,
) -> Result<connect_service::ConnectSnapshot, ClientError> {
    runtime.connect(&app, mode).await
}

#[tauri::command]
async fn connect_stop(
    runtime: State<'_, ConnectRuntimeRegistry>,
) -> Result<connect_service::ConnectSnapshot, ClientError> {
    runtime.stop().await
}

#[tauri::command]
async fn connect_logout(
    runtime: State<'_, ConnectRuntimeRegistry>,
) -> Result<connect_service::ConnectSnapshot, ClientError> {
    runtime.logout().await
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let app = tauri::Builder::default()
        .setup(|app| {
            let app_data_dir = app.path().app_data_dir()?;
            let profiles = ProfileRepository::native(app_data_dir.clone())
                .map_err(|error| std::io::Error::other(error.message))?;
            app.manage(profiles);
            let supervisor = XraySupervisor::new(app_data_dir.clone())
                .map_err(|error| std::io::Error::other(error.message))?;
            app.manage(supervisor.clone());
            app.manage(SetupSessionStore::new());
            app.manage(ConnectRuntimeRegistry::new(app_data_dir, supervisor));
            tauri::async_runtime::spawn(runtime::run_background_maintenance(app.handle().clone()));
            Ok(())
        })
        .plugin(tauri_plugin_shell::init())
        .invoke_handler(tauri::generate_handler![
            client_get_state,
            client_start,
            client_stop,
            client_preview_invitation,
            client_list_profiles,
            client_import_profile,
            client_rename_profile,
            client_delete_profile,
            client_preview_profile,
            connect_begin_setup,
            connect_cancel_setup,
            connect_confirm_setup,
            connect_get_snapshot,
            connect_refresh_bundle,
            connect_probe_nodes,
            connect_set_selection,
            connect_start,
            connect_stop,
            connect_logout
        ])
        .build(tauri::generate_context!())
        .expect("error while building Reality Client");

    app.run(|app, event| {
        if matches!(
            event,
            tauri::RunEvent::ExitRequested { .. } | tauri::RunEvent::Exit
        ) {
            let _ = app.state::<XraySupervisor>().stop();
        }
    });
}
