mod state;

use state::{ClientRuntime, ClientState};
use tauri::State;

#[tauri::command]
fn client_get_state(runtime: State<'_, ClientRuntime>) -> Result<ClientState, String> {
    runtime.snapshot()
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .manage(ClientRuntime::default())
        .invoke_handler(tauri::generate_handler![client_get_state])
        .run(tauri::generate_context!())
        .expect("error while running Reality Client");
}
