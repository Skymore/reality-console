use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalProxyEndpoints {
    pub socks: String,
    pub http: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ClientState {
    pub phase: ClientPhase,
    pub active_profile_id: Option<String>,
    pub mode: Option<ProxyMode>,
    pub endpoints: LocalProxyEndpoints,
    pub error_code: Option<String>,
    pub error_message: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ClientPhase {
    Disconnected,
    Starting,
    Connected,
    Stopping,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ProxyMode {
    Manual,
    System,
}

impl ClientState {
    pub fn disconnected(socks_port: u16, http_port: u16) -> Self {
        Self {
            phase: ClientPhase::Disconnected,
            active_profile_id: None,
            mode: None,
            endpoints: LocalProxyEndpoints {
                socks: format!("127.0.0.1:{socks_port}"),
                http: format!("127.0.0.1:{http_port}"),
            },
            error_code: None,
            error_message: None,
        }
    }
}
