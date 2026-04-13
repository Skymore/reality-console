use serde::Serialize;
use serde_json::Value;
use std::fs;
use std::path::Path;
use std::process::Command;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct XraySnapshot {
    installed: bool,
    binary_path: Option<String>,
    version: Option<String>,
    running: bool,
    pid: Option<u32>,
    config_path: Option<String>,
    public_ipv4: Option<String>,
    lan_ip: Option<String>,
    listen_port: Option<u16>,
    user_count: Option<usize>,
    reality_target: Option<String>,
    server_name: Option<String>,
    notes: Vec<String>,
}

#[tauri::command]
fn get_xray_snapshot() -> XraySnapshot {
    let mut notes = Vec::new();

    let binary_path = command_output("which", &["xray"]);
    let installed = binary_path.is_some();

    let version = if installed {
        command_output("xray", &["version"])
            .and_then(|output| output.lines().next().map(|line| line.trim().to_string()))
    } else {
        notes.push("`xray` was not found in PATH.".to_string());
        None
    };

    let (running, pid) = brew_service_status("xray")
        .or_else(|| pgrep_status("xray"))
        .unwrap_or_else(|| {
            notes.push("Could not determine process state from brew services or pgrep.".to_string());
            (false, None)
        });

    let config_path = detect_config_path();
    let public_ipv4 = command_output("curl", &["-4", "-fsS", "https://api.ipify.org"]).or_else(|| {
        notes.push("Public IPv4 lookup failed.".to_string());
        None
    });
    let lan_ip = detect_lan_ip().or_else(|| {
        notes.push("LAN IP detection failed.".to_string());
        None
    });

    let mut listen_port = None;
    let mut user_count = None;
    let mut reality_target = None;
    let mut server_name = None;

    if let Some(path) = config_path.as_deref() {
        match inspect_config(path) {
            Some(inspected) => {
                listen_port = inspected.listen_port;
                user_count = inspected.user_count;
                reality_target = inspected.reality_target;
                server_name = inspected.server_name;
            }
            None => notes.push("Config file was found but could not be parsed.".to_string()),
        }
    } else {
        notes.push("No known Xray config path was found.".to_string());
    }

    XraySnapshot {
        installed,
        binary_path,
        version,
        running,
        pid,
        config_path,
        public_ipv4,
        lan_ip,
        listen_port,
        user_count,
        reality_target,
        server_name,
        notes,
    }
}

#[derive(Default)]
struct ConfigInspection {
    listen_port: Option<u16>,
    user_count: Option<usize>,
    reality_target: Option<String>,
    server_name: Option<String>,
}

fn inspect_config(path: &str) -> Option<ConfigInspection> {
    let contents = fs::read_to_string(path).ok()?;
    let root: Value = serde_json::from_str(&contents).ok()?;
    let inbound = root.get("inbounds")?.as_array()?.first()?;

    let listen_port = inbound
        .get("port")
        .and_then(Value::as_u64)
        .and_then(|port| u16::try_from(port).ok());

    let user_count = inbound
        .get("settings")
        .and_then(|settings| settings.get("clients"))
        .and_then(Value::as_array)
        .map(|clients| clients.len());

    let reality_settings = inbound
        .get("streamSettings")
        .and_then(|settings| settings.get("realitySettings"));

    let reality_target = reality_settings
        .and_then(|settings| settings.get("target"))
        .and_then(Value::as_str)
        .map(ToString::to_string);

    let server_name = reality_settings
        .and_then(|settings| settings.get("serverNames"))
        .and_then(Value::as_array)
        .and_then(|names| names.first())
        .and_then(Value::as_str)
        .map(ToString::to_string);

    Some(ConfigInspection {
        listen_port,
        user_count,
        reality_target,
        server_name,
    })
}

fn detect_config_path() -> Option<String> {
    let candidates = [
        "/opt/homebrew/etc/xray/config.json",
        "/usr/local/etc/xray/config.json",
        "/etc/xray/config.json",
    ];

    candidates
        .iter()
        .find(|candidate| Path::new(candidate).exists())
        .map(|candidate| candidate.to_string())
}

fn detect_lan_ip() -> Option<String> {
    let route_output = command_output("route", &["-n", "get", "default"])?;
    let interface = route_output
        .lines()
        .find(|line| line.trim_start().starts_with("interface:"))
        .and_then(|line| line.split(':').nth(1))
        .map(str::trim)?
        .to_string();

    command_output("ipconfig", &["getifaddr", interface.as_str()])
}

fn brew_service_status(service: &str) -> Option<(bool, Option<u32>)> {
    let output = command_output("brew", &["services", "info", service])?;
    let running = output
        .lines()
        .find(|line| line.trim_start().starts_with("Running:"))
        .map(|line| line.contains("true"))?;

    let pid = output
        .lines()
        .find(|line| line.trim_start().starts_with("PID:"))
        .and_then(|line| line.split(':').nth(1))
        .and_then(|value| value.trim().parse::<u32>().ok());

    Some((running, pid))
}

fn pgrep_status(process: &str) -> Option<(bool, Option<u32>)> {
    let output = command_output("pgrep", &["-x", process])?;
    let pid = output.lines().next()?.trim().parse::<u32>().ok()?;
    Some((true, Some(pid)))
}

fn command_output(program: &str, args: &[&str]) -> Option<String> {
    let output = Command::new(program).args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if stdout.is_empty() {
        None
    } else {
        Some(stdout)
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![get_xray_snapshot])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
