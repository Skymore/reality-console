use serde::Serialize;
use std::sync::Mutex;

const DEFAULT_SOCKS_ENDPOINT: &str = "127.0.0.1:10808";
const DEFAULT_HTTP_ENDPOINT: &str = "127.0.0.1:10809";

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalProxyEndpoints {
    socks: String,
    http: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ClientState {
    phase: ClientPhase,
    active_profile_id: Option<String>,
    mode: Option<ProxyMode>,
    endpoints: LocalProxyEndpoints,
    error_code: Option<String>,
    error_message: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
enum ClientPhase {
    Disconnected,
    Starting,
    Connected,
    Stopping,
    Failed,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
enum ProxyMode {
    Manual,
    System,
}

pub struct ClientRuntime {
    state: Mutex<ClientState>,
}

impl Default for ClientRuntime {
    fn default() -> Self {
        Self {
            state: Mutex::new(ClientState {
                phase: ClientPhase::Disconnected,
                active_profile_id: None,
                mode: None,
                endpoints: LocalProxyEndpoints {
                    socks: DEFAULT_SOCKS_ENDPOINT.to_string(),
                    http: DEFAULT_HTTP_ENDPOINT.to_string(),
                },
                error_code: None,
                error_message: None,
            }),
        }
    }
}

impl ClientRuntime {
    pub fn snapshot(&self) -> Result<ClientState, String> {
        self.state
            .lock()
            .map(|state| state.clone())
            .map_err(|_| "client_state_unavailable".to_string())
    }
}
