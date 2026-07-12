//! Crash-safe ownership of the operating-system proxy settings.

use crate::error::ClientError;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

const JOURNAL_VERSION: u32 = 1;
const JOURNAL_FILE: &str = "system-proxy-recovery-v1.json";
const MAX_JOURNAL_BYTES: u64 = 1024 * 1024;

pub(crate) trait SystemProxyAdapter: Send + Sync {
    fn platform(&self) -> &'static str;
    fn capture(&self) -> Result<Value, ClientError>;
    fn apply(&self, snapshot: &Value, socks_port: u16, http_port: u16) -> Result<(), ClientError>;
    fn restore(&self, snapshot: &Value) -> Result<(), ClientError>;
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RecoveryJournal {
    version: u32,
    platform: String,
    snapshot: Value,
}

struct ProxyManagerInner {
    adapter: Arc<dyn SystemProxyAdapter>,
    journal_path: PathBuf,
    operation: Mutex<()>,
}

/// Serializes system-proxy mutations and keeps the pre-mutation state durable until restoration.
#[derive(Clone)]
pub(crate) struct SystemProxyManager {
    inner: Arc<ProxyManagerInner>,
}

impl SystemProxyManager {
    pub(crate) fn new(app_data_dir: &Path) -> Result<Self, ClientError> {
        let adapter = native_adapter()?;
        Self::new_with_adapter(app_data_dir, adapter)
    }

    pub(crate) fn new_with_adapter(
        app_data_dir: &Path,
        adapter: Arc<dyn SystemProxyAdapter>,
    ) -> Result<Self, ClientError> {
        let recovery_dir = app_data_dir.join("recovery");
        fs::create_dir_all(&recovery_dir)
            .map_err(|_| proxy_error("system_proxy_recovery_directory_failed"))?;
        Ok(Self {
            inner: Arc::new(ProxyManagerInner {
                adapter,
                journal_path: recovery_dir.join(JOURNAL_FILE),
                operation: Mutex::new(()),
            }),
        })
    }

    /// Captures and journals the exact prior state before applying Connect's loopback endpoints.
    pub(crate) fn apply(&self, socks_port: u16, http_port: u16) -> Result<(), ClientError> {
        let _operation = self
            .inner
            .operation
            .lock()
            .map_err(|_| proxy_error("system_proxy_state_unavailable"))?;
        self.restore_locked()?;
        let snapshot = self.inner.adapter.capture()?;
        let journal = RecoveryJournal {
            version: JOURNAL_VERSION,
            platform: self.inner.adapter.platform().to_owned(),
            snapshot,
        };
        write_journal(&self.inner.journal_path, &journal)?;
        if let Err(apply_error) = self
            .inner
            .adapter
            .apply(&journal.snapshot, socks_port, http_port)
        {
            // Keep the journal if rollback fails so the next launch can retry safely.
            return match self.restore_locked() {
                Ok(()) => Err(apply_error),
                Err(_) => Err(proxy_error("system_proxy_apply_rollback_failed")),
            };
        }
        Ok(())
    }

    /// Restores a pending journal. It is safe to call repeatedly and while manual mode is active.
    pub(crate) fn restore_pending(&self) -> Result<(), ClientError> {
        let _operation = self
            .inner
            .operation
            .lock()
            .map_err(|_| proxy_error("system_proxy_state_unavailable"))?;
        self.restore_locked()
    }

    fn restore_locked(&self) -> Result<(), ClientError> {
        let Some(journal) = read_journal(&self.inner.journal_path)? else {
            return Ok(());
        };
        if journal.version != JOURNAL_VERSION || journal.platform != self.inner.adapter.platform() {
            return Err(proxy_error("system_proxy_recovery_incompatible"));
        }
        self.inner.adapter.restore(&journal.snapshot)?;
        remove_journal(&self.inner.journal_path)
    }
}

fn write_journal(path: &Path, journal: &RecoveryJournal) -> Result<(), ClientError> {
    let parent = path
        .parent()
        .ok_or_else(|| proxy_error("system_proxy_recovery_directory_failed"))?;
    let bytes = serde_json::to_vec(journal)
        .map_err(|_| proxy_error("system_proxy_recovery_write_failed"))?;
    if u64::try_from(bytes.len()).map_or(true, |length| length > MAX_JOURNAL_BYTES) {
        return Err(proxy_error("system_proxy_recovery_write_failed"));
    }
    let mut temporary = tempfile::NamedTempFile::new_in(parent)
        .map_err(|_| proxy_error("system_proxy_recovery_write_failed"))?;
    temporary
        .write_all(&bytes)
        .and_then(|_| temporary.as_file().sync_all())
        .map_err(|_| proxy_error("system_proxy_recovery_write_failed"))?;
    set_owner_only(temporary.path())?;
    temporary
        .persist(path)
        .map_err(|_| proxy_error("system_proxy_recovery_write_failed"))?;
    sync_parent(parent)?;
    Ok(())
}

fn read_journal(path: &Path) -> Result<Option<RecoveryJournal>, ClientError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(proxy_error("system_proxy_recovery_read_failed")),
    };
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > MAX_JOURNAL_BYTES
    {
        return Err(proxy_error("system_proxy_recovery_corrupt"));
    }
    match fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|_| proxy_error("system_proxy_recovery_corrupt")),
        Err(_) => Err(proxy_error("system_proxy_recovery_read_failed")),
    }
}

fn remove_journal(path: &Path) -> Result<(), ClientError> {
    match fs::remove_file(path) {
        Ok(()) => {
            if let Some(parent) = path.parent() {
                sync_parent(parent)?;
            }
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(proxy_error("system_proxy_recovery_clear_failed")),
    }
}

#[cfg(unix)]
fn set_owner_only(path: &Path) -> Result<(), ClientError> {
    use std::os::unix::fs::PermissionsExt as _;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .map_err(|_| proxy_error("system_proxy_recovery_permissions_failed"))
}

#[cfg(not(unix))]
fn set_owner_only(_path: &Path) -> Result<(), ClientError> {
    Ok(())
}

#[cfg(unix)]
fn sync_parent(path: &Path) -> Result<(), ClientError> {
    fs::File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| proxy_error("system_proxy_recovery_sync_failed"))
}

#[cfg(not(unix))]
fn sync_parent(_path: &Path) -> Result<(), ClientError> {
    Ok(())
}

#[cfg(target_os = "macos")]
fn native_adapter() -> Result<Arc<dyn SystemProxyAdapter>, ClientError> {
    Ok(Arc::new(macos::MacOsProxyAdapter::native()))
}

#[cfg(windows)]
fn native_adapter() -> Result<Arc<dyn SystemProxyAdapter>, ClientError> {
    Ok(Arc::new(windows::WindowsProxyAdapter))
}

#[cfg(not(any(target_os = "macos", windows)))]
fn native_adapter() -> Result<Arc<dyn SystemProxyAdapter>, ClientError> {
    Err(proxy_error("system_proxy_platform_unsupported"))
}

fn proxy_error(code: &str) -> ClientError {
    ClientError::internal(code, "The operating-system proxy operation failed.")
}

#[cfg(any(windows, test))]
fn windows_proxy_server(socks_port: u16, http_port: u16) -> String {
    format!("http=127.0.0.1:{http_port};https=127.0.0.1:{http_port};socks=127.0.0.1:{socks_port}")
}

#[cfg(target_os = "macos")]
mod macos {
    use super::{proxy_error, SystemProxyAdapter};
    use crate::error::ClientError;
    use serde::{Deserialize, Serialize};
    use serde_json::Value;
    use std::io::Read as _;
    use std::process::{Command, Stdio};
    use std::sync::Arc;
    use std::thread;
    use std::time::{Duration, Instant};

    const NETWORK_SETUP: &str = "/usr/sbin/networksetup";
    const COMMAND_TIMEOUT: Duration = Duration::from_secs(5);
    const MAX_OUTPUT_BYTES: u64 = 256 * 1024;

    trait CommandRunner: Send + Sync {
        fn run(&self, args: &[String]) -> Result<String, ClientError>;
    }

    struct BoundedCommandRunner;

    impl CommandRunner for BoundedCommandRunner {
        fn run(&self, args: &[String]) -> Result<String, ClientError> {
            let mut child = Command::new(NETWORK_SETUP)
                .args(args)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .map_err(|_| proxy_error("system_proxy_command_start_failed"))?;
            let stdout = child
                .stdout
                .take()
                .ok_or_else(|| proxy_error("system_proxy_command_output_failed"))?;
            let stderr = child
                .stderr
                .take()
                .ok_or_else(|| proxy_error("system_proxy_command_output_failed"))?;
            let stdout_reader = thread::spawn(move || read_bounded(stdout));
            let stderr_reader = thread::spawn(move || read_bounded(stderr));
            let deadline = Instant::now() + COMMAND_TIMEOUT;
            let status = loop {
                match child.try_wait() {
                    Ok(Some(status)) => break status,
                    Ok(None) if Instant::now() < deadline => {
                        thread::sleep(Duration::from_millis(20));
                    }
                    Ok(None) => {
                        let _ = child.kill();
                        let _ = child.wait();
                        return Err(proxy_error("system_proxy_command_timeout"));
                    }
                    Err(_) => {
                        let _ = child.kill();
                        let _ = child.wait();
                        return Err(proxy_error("system_proxy_command_wait_failed"));
                    }
                }
            };
            let stdout = stdout_reader
                .join()
                .map_err(|_| proxy_error("system_proxy_command_output_failed"))??;
            let stderr = stderr_reader
                .join()
                .map_err(|_| proxy_error("system_proxy_command_output_failed"))??;
            if !status.success() {
                let _ = stderr;
                return Err(proxy_error("system_proxy_command_failed"));
            }
            String::from_utf8(stdout)
                .map_err(|_| proxy_error("system_proxy_command_output_invalid"))
        }
    }

    fn read_bounded(mut reader: impl std::io::Read) -> Result<Vec<u8>, ClientError> {
        let mut output = Vec::new();
        reader
            .by_ref()
            .take(MAX_OUTPUT_BYTES + 1)
            .read_to_end(&mut output)
            .map_err(|_| proxy_error("system_proxy_command_output_failed"))?;
        if output.len() as u64 > MAX_OUTPUT_BYTES {
            return Err(proxy_error("system_proxy_command_output_too_large"));
        }
        Ok(output)
    }

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct MacSnapshot {
        services: Vec<ServiceSnapshot>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct ServiceSnapshot {
        name: String,
        web: ProxySnapshot,
        secure_web: ProxySnapshot,
        socks: ProxySnapshot,
        auto_proxy: AutoProxySnapshot,
        auto_discovery: bool,
        bypass_domains: Vec<String>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct ProxySnapshot {
        enabled: bool,
        server: String,
        port: u16,
        authenticated: bool,
    }

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct AutoProxySnapshot {
        enabled: bool,
        url: Option<String>,
    }

    pub(super) struct MacOsProxyAdapter {
        runner: Arc<dyn CommandRunner>,
    }

    impl MacOsProxyAdapter {
        pub(super) fn native() -> Self {
            Self {
                runner: Arc::new(BoundedCommandRunner),
            }
        }

        fn command(&self, args: &[&str]) -> Result<String, ClientError> {
            self.runner.run(
                &args
                    .iter()
                    .map(|value| (*value).to_owned())
                    .collect::<Vec<_>>(),
            )
        }

        fn capture_typed(&self) -> Result<MacSnapshot, ClientError> {
            let services = parse_services(&self.command(&["-listallnetworkservices"])?)?;
            if services.is_empty() {
                return Err(proxy_error("system_proxy_no_network_services"));
            }
            let mut snapshots = Vec::with_capacity(services.len());
            for service in services {
                let web = parse_proxy(&self.command(&["-getwebproxy", &service])?)?;
                let secure_web = parse_proxy(&self.command(&["-getsecurewebproxy", &service])?)?;
                let socks = parse_proxy(&self.command(&["-getsocksfirewallproxy", &service])?)?;
                if web.authenticated || secure_web.authenticated || socks.authenticated {
                    return Err(proxy_error("system_proxy_authenticated_proxy_unsupported"));
                }
                snapshots.push(ServiceSnapshot {
                    name: service.clone(),
                    web,
                    secure_web,
                    socks,
                    auto_proxy: parse_auto_proxy(&self.command(&["-getautoproxyurl", &service])?)?,
                    auto_discovery: parse_auto_discovery(
                        &self.command(&["-getproxyautodiscovery", &service])?,
                    )?,
                    bypass_domains: parse_bypass_domains(
                        &self.command(&["-getproxybypassdomains", &service])?,
                    ),
                });
            }
            Ok(MacSnapshot {
                services: snapshots,
            })
        }

        fn run_mutation(&self, args: &[&str], first_error: &mut Option<ClientError>) {
            if let Err(error) = self.command(args) {
                if first_error.is_none() {
                    *first_error = Some(error);
                }
            }
        }

        fn restore_service(
            &self,
            service: &ServiceSnapshot,
            first_error: &mut Option<ClientError>,
        ) {
            self.restore_proxy(
                "-setwebproxy",
                "-setwebproxystate",
                &service.name,
                &service.web,
                first_error,
            );
            self.restore_proxy(
                "-setsecurewebproxy",
                "-setsecurewebproxystate",
                &service.name,
                &service.secure_web,
                first_error,
            );
            self.restore_proxy(
                "-setsocksfirewallproxy",
                "-setsocksfirewallproxystate",
                &service.name,
                &service.socks,
                first_error,
            );
            if let Some(url) = service.auto_proxy.url.as_deref() {
                self.run_mutation(&["-setautoproxyurl", &service.name, url], first_error);
            }
            self.run_mutation(
                &[
                    "-setautoproxystate",
                    &service.name,
                    on_off(service.auto_proxy.enabled),
                ],
                first_error,
            );
            self.run_mutation(
                &[
                    "-setproxyautodiscovery",
                    &service.name,
                    on_off(service.auto_discovery),
                ],
                first_error,
            );
            let mut bypass = vec!["-setproxybypassdomains", service.name.as_str()];
            if service.bypass_domains.is_empty() {
                bypass.push("Empty");
            } else {
                bypass.extend(service.bypass_domains.iter().map(String::as_str));
            }
            self.run_mutation(&bypass, first_error);
        }

        fn restore_proxy(
            &self,
            setter: &str,
            state_setter: &str,
            service: &str,
            snapshot: &ProxySnapshot,
            first_error: &mut Option<ClientError>,
        ) {
            if !snapshot.server.is_empty() && snapshot.port != 0 {
                self.run_mutation(
                    &[
                        setter,
                        service,
                        &snapshot.server,
                        &snapshot.port.to_string(),
                        "off",
                    ],
                    first_error,
                );
            } else if snapshot.enabled && first_error.is_none() {
                *first_error = Some(proxy_error("system_proxy_recovery_corrupt"));
            }
            self.run_mutation(
                &[state_setter, service, on_off(snapshot.enabled)],
                first_error,
            );
        }
    }

    impl SystemProxyAdapter for MacOsProxyAdapter {
        fn platform(&self) -> &'static str {
            "macos"
        }

        fn capture(&self) -> Result<Value, ClientError> {
            serde_json::to_value(self.capture_typed()?)
                .map_err(|_| proxy_error("system_proxy_snapshot_failed"))
        }

        fn apply(
            &self,
            snapshot: &Value,
            socks_port: u16,
            http_port: u16,
        ) -> Result<(), ClientError> {
            let snapshot: MacSnapshot = serde_json::from_value(snapshot.clone())
                .map_err(|_| proxy_error("system_proxy_snapshot_invalid"))?;
            let socks_port = socks_port.to_string();
            let http_port = http_port.to_string();
            for service in snapshot.services {
                self.command(&[
                    "-setwebproxy",
                    &service.name,
                    "127.0.0.1",
                    &http_port,
                    "off",
                ])?;
                self.command(&[
                    "-setsecurewebproxy",
                    &service.name,
                    "127.0.0.1",
                    &http_port,
                    "off",
                ])?;
                self.command(&[
                    "-setsocksfirewallproxy",
                    &service.name,
                    "127.0.0.1",
                    &socks_port,
                    "off",
                ])?;
                self.command(&["-setwebproxystate", &service.name, "on"])?;
                self.command(&["-setsecurewebproxystate", &service.name, "on"])?;
                self.command(&["-setsocksfirewallproxystate", &service.name, "on"])?;
                self.command(&["-setautoproxystate", &service.name, "off"])?;
                self.command(&["-setproxyautodiscovery", &service.name, "off"])?;
                self.command(&[
                    "-setproxybypassdomains",
                    &service.name,
                    "localhost",
                    "127.0.0.1",
                    "::1",
                ])?;
            }
            Ok(())
        }

        fn restore(&self, snapshot: &Value) -> Result<(), ClientError> {
            let snapshot: MacSnapshot = serde_json::from_value(snapshot.clone())
                .map_err(|_| proxy_error("system_proxy_recovery_corrupt"))?;
            let mut first_error = None;
            for service in &snapshot.services {
                self.restore_service(service, &mut first_error);
            }
            first_error.map_or(Ok(()), Err)
        }
    }

    fn parse_services(output: &str) -> Result<Vec<String>, ClientError> {
        let services: Vec<_> = output
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .filter(|line| !line.starts_with("An asterisk"))
            .filter(|line| !line.starts_with('*'))
            .map(str::to_owned)
            .collect();
        if services.iter().any(|service| service.len() > 256) {
            return Err(proxy_error("system_proxy_snapshot_invalid"));
        }
        Ok(services)
    }

    fn parse_proxy(output: &str) -> Result<ProxySnapshot, ClientError> {
        Ok(ProxySnapshot {
            enabled: parse_bool(required_field(output, "Enabled")?)?,
            server: required_field(output, "Server")?.to_owned(),
            port: required_field(output, "Port")?
                .parse()
                .map_err(|_| proxy_error("system_proxy_snapshot_invalid"))?,
            authenticated: parse_bool(required_field(output, "Authenticated Proxy Enabled")?)?,
        })
    }

    fn parse_auto_proxy(output: &str) -> Result<AutoProxySnapshot, ClientError> {
        let url = required_field(output, "URL")?;
        Ok(AutoProxySnapshot {
            enabled: parse_bool(required_field(output, "Enabled")?)?,
            url: (!url.is_empty() && url != "(null)").then(|| url.to_owned()),
        })
    }

    fn parse_auto_discovery(output: &str) -> Result<bool, ClientError> {
        parse_bool(required_field(output, "Auto Proxy Discovery")?)
    }

    fn parse_bypass_domains(output: &str) -> Vec<String> {
        if output.contains("There aren't any") {
            return Vec::new();
        }
        output
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(str::to_owned)
            .collect()
    }

    fn required_field<'a>(output: &'a str, name: &str) -> Result<&'a str, ClientError> {
        output
            .lines()
            .find_map(|line| line.strip_prefix(name)?.strip_prefix(':'))
            .map(str::trim)
            .ok_or_else(|| proxy_error("system_proxy_snapshot_invalid"))
    }

    fn parse_bool(value: &str) -> Result<bool, ClientError> {
        match value.to_ascii_lowercase().as_str() {
            "yes" | "on" | "1" => Ok(true),
            "no" | "off" | "0" => Ok(false),
            _ => Err(proxy_error("system_proxy_snapshot_invalid")),
        }
    }

    fn on_off(value: bool) -> &'static str {
        if value {
            "on"
        } else {
            "off"
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::collections::VecDeque;
        use std::sync::Mutex;

        struct MockRunner {
            replies: Mutex<VecDeque<Result<String, ClientError>>>,
            calls: Mutex<Vec<Vec<String>>>,
        }

        impl MockRunner {
            fn new(replies: Vec<String>) -> Self {
                Self {
                    replies: Mutex::new(replies.into_iter().map(Ok).collect()),
                    calls: Mutex::new(Vec::new()),
                }
            }
        }

        impl CommandRunner for MockRunner {
            fn run(&self, args: &[String]) -> Result<String, ClientError> {
                self.calls.lock().unwrap().push(args.to_vec());
                self.replies.lock().unwrap().pop_front().unwrap()
            }
        }

        fn disabled_proxy() -> String {
            "Enabled: No\nServer: old.proxy\nPort: 3128\nAuthenticated Proxy Enabled: 0\n"
                .to_owned()
        }

        #[test]
        fn capture_parses_every_mutated_setting_and_skips_disabled_services() {
            let runner = Arc::new(MockRunner::new(vec![
                "An asterisk (*) denotes that a network service is disabled.\nWi-Fi\n*USB LAN\n"
                    .to_owned(),
                disabled_proxy(),
                disabled_proxy(),
                disabled_proxy(),
                "URL: http://pac.example/proxy.pac\nEnabled: Yes\n".to_owned(),
                "Auto Proxy Discovery: Off\n".to_owned(),
                "example.test\n.internal\n".to_owned(),
            ]));
            let adapter = MacOsProxyAdapter { runner };
            let snapshot = adapter.capture_typed().unwrap();
            assert_eq!(snapshot.services.len(), 1);
            assert_eq!(snapshot.services[0].name, "Wi-Fi");
            assert_eq!(
                snapshot.services[0].bypass_domains,
                ["example.test", ".internal"]
            );
            assert_eq!(
                snapshot.services[0].auto_proxy.url.as_deref(),
                Some("http://pac.example/proxy.pac")
            );
        }

        #[test]
        fn authenticated_proxy_is_rejected_before_any_mutation() {
            let runner = Arc::new(MockRunner::new(vec![
                "Wi-Fi\n".to_owned(),
                "Enabled: Yes\nServer: corp.proxy\nPort: 8080\nAuthenticated Proxy Enabled: 1\n"
                    .to_owned(),
                disabled_proxy(),
                disabled_proxy(),
            ]));
            let adapter = MacOsProxyAdapter {
                runner: runner.clone(),
            };
            let error = adapter.capture_typed().unwrap_err();
            assert_eq!(error.code, "system_proxy_authenticated_proxy_unsupported");
            assert!(runner
                .calls
                .lock()
                .unwrap()
                .iter()
                .all(|call| { !call.first().is_some_and(|arg| arg.starts_with("-set")) }));
        }

        #[test]
        fn restore_of_empty_disabled_proxy_only_restores_its_state() {
            let runner = Arc::new(MockRunner::new(vec![String::new()]));
            let adapter = MacOsProxyAdapter {
                runner: runner.clone(),
            };
            let mut first_error = None;
            adapter.restore_proxy(
                "-setwebproxy",
                "-setwebproxystate",
                "Wi-Fi",
                &ProxySnapshot {
                    enabled: false,
                    server: String::new(),
                    port: 0,
                    authenticated: false,
                },
                &mut first_error,
            );

            assert!(first_error.is_none());
            assert_eq!(
                *runner.calls.lock().unwrap(),
                vec![vec![
                    "-setwebproxystate".to_string(),
                    "Wi-Fi".to_string(),
                    "off".to_string(),
                ]]
            );
        }
    }
}

#[cfg(windows)]
mod windows {
    use super::{proxy_error, windows_proxy_server, SystemProxyAdapter};
    use crate::error::ClientError;
    use serde::{Deserialize, Serialize};
    use serde_json::Value;
    use std::ffi::c_void;
    use std::mem::size_of;
    use std::ptr::{null, null_mut};
    use windows_sys::Win32::Foundation::GlobalFree;
    use windows_sys::Win32::Networking::WinInet::{
        InternetQueryOptionW, InternetSetOptionW, INTERNET_OPTION_PER_CONNECTION_OPTION,
        INTERNET_OPTION_REFRESH, INTERNET_OPTION_SETTINGS_CHANGED,
        INTERNET_PER_CONN_AUTOCONFIG_URL, INTERNET_PER_CONN_AUTODISCOVERY_FLAGS,
        INTERNET_PER_CONN_FLAGS, INTERNET_PER_CONN_FLAGS_UI, INTERNET_PER_CONN_OPTIONW,
        INTERNET_PER_CONN_OPTIONW_0, INTERNET_PER_CONN_OPTION_LISTW,
        INTERNET_PER_CONN_PROXY_BYPASS, INTERNET_PER_CONN_PROXY_SERVER, PROXY_TYPE_DIRECT,
        PROXY_TYPE_PROXY,
    };

    const MAXIMUM_OPTION_CHARS: usize = 32 * 1024;

    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct WindowsSnapshot {
        flags: u32,
        proxy_server: Option<String>,
        proxy_override: Option<String>,
        auto_config_url: Option<String>,
        auto_discovery_flags: u32,
    }

    pub(super) struct WindowsProxyAdapter;

    impl WindowsProxyAdapter {
        fn notify() -> Result<(), ClientError> {
            // SAFETY: WinINet accepts a null session handle and null buffer for these global notices.
            let changed =
                unsafe { InternetSetOptionW(null(), INTERNET_OPTION_SETTINGS_CHANGED, null(), 0) };
            let refreshed =
                unsafe { InternetSetOptionW(null(), INTERNET_OPTION_REFRESH, null(), 0) };
            if changed == 0 || refreshed == 0 {
                return Err(proxy_error("system_proxy_notify_failed"));
            }
            Ok(())
        }

        fn query() -> Result<WindowsSnapshot, ClientError> {
            let mut options = [
                query_option(INTERNET_PER_CONN_FLAGS_UI),
                query_option(INTERNET_PER_CONN_PROXY_SERVER),
                query_option(INTERNET_PER_CONN_PROXY_BYPASS),
                query_option(INTERNET_PER_CONN_AUTOCONFIG_URL),
                query_option(INTERNET_PER_CONN_AUTODISCOVERY_FLAGS),
            ];
            let mut list = option_list(&mut options);
            let mut buffer_size = size_of::<INTERNET_PER_CONN_OPTION_LISTW>() as u32;
            // SAFETY: list and its option array remain alive and writable for the call.
            let success = unsafe {
                InternetQueryOptionW(
                    null(),
                    INTERNET_OPTION_PER_CONNECTION_OPTION,
                    (&raw mut list).cast::<c_void>(),
                    &raw mut buffer_size,
                )
            };
            let proxy_server = GlobalWide::new(unsafe { options[1].Value.pszValue });
            let proxy_override = GlobalWide::new(unsafe { options[2].Value.pszValue });
            let auto_config_url = GlobalWide::new(unsafe { options[3].Value.pszValue });
            if success == 0 {
                return Err(proxy_error("system_proxy_windows_query_failed"));
            }
            Ok(WindowsSnapshot {
                flags: unsafe { options[0].Value.dwValue },
                proxy_server: proxy_server.to_string()?,
                proxy_override: proxy_override.to_string()?,
                auto_config_url: auto_config_url.to_string()?,
                auto_discovery_flags: unsafe { options[4].Value.dwValue },
            })
        }

        fn set(options: &mut [INTERNET_PER_CONN_OPTIONW]) -> Result<(), ClientError> {
            let list = option_list(options);
            // SAFETY: list points at option values and UTF-16 buffers that outlive the call.
            let success = unsafe {
                InternetSetOptionW(
                    null(),
                    INTERNET_OPTION_PER_CONNECTION_OPTION,
                    (&raw const list).cast::<c_void>(),
                    size_of::<INTERNET_PER_CONN_OPTION_LISTW>() as u32,
                )
            };
            if success == 0 {
                return Err(proxy_error("system_proxy_windows_set_failed"));
            }
            Self::notify()
        }
    }

    impl SystemProxyAdapter for WindowsProxyAdapter {
        fn platform(&self) -> &'static str {
            "windows"
        }

        fn capture(&self) -> Result<Value, ClientError> {
            serde_json::to_value(Self::query()?)
                .map_err(|_| proxy_error("system_proxy_snapshot_failed"))
        }

        fn apply(
            &self,
            _snapshot: &Value,
            socks_port: u16,
            http_port: u16,
        ) -> Result<(), ClientError> {
            let mut server = wide(&windows_proxy_server(socks_port, http_port))?;
            let mut bypass = wide("<local>;localhost;127.*;[::1]")?;
            let mut options = [
                dword_option(
                    INTERNET_PER_CONN_FLAGS,
                    PROXY_TYPE_DIRECT | PROXY_TYPE_PROXY,
                ),
                string_option(INTERNET_PER_CONN_PROXY_SERVER, &mut server),
                string_option(INTERNET_PER_CONN_PROXY_BYPASS, &mut bypass),
            ];
            Self::set(&mut options)
        }

        fn restore(&self, snapshot: &Value) -> Result<(), ClientError> {
            let snapshot: WindowsSnapshot = serde_json::from_value(snapshot.clone())
                .map_err(|_| proxy_error("system_proxy_recovery_corrupt"))?;
            let mut server = optional_wide(snapshot.proxy_server.as_deref())?;
            let mut bypass = optional_wide(snapshot.proxy_override.as_deref())?;
            let mut auto_config = optional_wide(snapshot.auto_config_url.as_deref())?;
            let mut options = [
                dword_option(INTERNET_PER_CONN_FLAGS, snapshot.flags),
                optional_string_option(INTERNET_PER_CONN_PROXY_SERVER, &mut server),
                optional_string_option(INTERNET_PER_CONN_PROXY_BYPASS, &mut bypass),
                optional_string_option(INTERNET_PER_CONN_AUTOCONFIG_URL, &mut auto_config),
                dword_option(
                    INTERNET_PER_CONN_AUTODISCOVERY_FLAGS,
                    snapshot.auto_discovery_flags,
                ),
            ];
            Self::set(&mut options)
        }
    }

    fn query_option(kind: u32) -> INTERNET_PER_CONN_OPTIONW {
        INTERNET_PER_CONN_OPTIONW {
            dwOption: kind,
            Value: INTERNET_PER_CONN_OPTIONW_0 { dwValue: 0 },
        }
    }

    fn dword_option(kind: u32, value: u32) -> INTERNET_PER_CONN_OPTIONW {
        INTERNET_PER_CONN_OPTIONW {
            dwOption: kind,
            Value: INTERNET_PER_CONN_OPTIONW_0 { dwValue: value },
        }
    }

    fn string_option(kind: u32, value: &mut [u16]) -> INTERNET_PER_CONN_OPTIONW {
        INTERNET_PER_CONN_OPTIONW {
            dwOption: kind,
            Value: INTERNET_PER_CONN_OPTIONW_0 {
                pszValue: value.as_mut_ptr(),
            },
        }
    }

    fn optional_string_option(
        kind: u32,
        value: &mut Option<Vec<u16>>,
    ) -> INTERNET_PER_CONN_OPTIONW {
        INTERNET_PER_CONN_OPTIONW {
            dwOption: kind,
            Value: INTERNET_PER_CONN_OPTIONW_0 {
                pszValue: value
                    .as_mut()
                    .map_or(null_mut(), |units| units.as_mut_ptr()),
            },
        }
    }

    fn option_list(options: &mut [INTERNET_PER_CONN_OPTIONW]) -> INTERNET_PER_CONN_OPTION_LISTW {
        INTERNET_PER_CONN_OPTION_LISTW {
            dwSize: size_of::<INTERNET_PER_CONN_OPTION_LISTW>() as u32,
            pszConnection: null_mut(),
            dwOptionCount: options.len() as u32,
            dwOptionError: 0,
            pOptions: options.as_mut_ptr(),
        }
    }

    fn wide(value: &str) -> Result<Vec<u16>, ClientError> {
        if value.encode_utf16().any(|unit| unit == 0) {
            return Err(proxy_error("system_proxy_windows_value_invalid"));
        }
        Ok(value.encode_utf16().chain(Some(0)).collect())
    }

    fn optional_wide(value: Option<&str>) -> Result<Option<Vec<u16>>, ClientError> {
        value.map(wide).transpose()
    }

    struct GlobalWide(*mut u16);

    impl GlobalWide {
        const fn new(value: *mut u16) -> Self {
            Self(value)
        }

        fn to_string(&self) -> Result<Option<String>, ClientError> {
            if self.0.is_null() {
                return Ok(None);
            }
            let mut length = 0;
            // SAFETY: WinINet returned a NUL-terminated GlobalAlloc string for this queried option.
            while length < MAXIMUM_OPTION_CHARS && unsafe { *self.0.add(length) } != 0 {
                length += 1;
            }
            if length == MAXIMUM_OPTION_CHARS {
                return Err(proxy_error("system_proxy_windows_value_invalid"));
            }
            // SAFETY: the scan above established a readable NUL-terminated prefix of this length.
            let units = unsafe { std::slice::from_raw_parts(self.0, length) };
            String::from_utf16(units)
                .map(Some)
                .map_err(|_| proxy_error("system_proxy_windows_value_invalid"))
        }
    }

    impl Drop for GlobalWide {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: WinINet documents GlobalFree for queried per-connection option strings.
                unsafe {
                    GlobalFree(self.0.cast::<c_void>());
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct FakeAdapter {
        state: Mutex<Value>,
        captures: AtomicUsize,
        applies: AtomicUsize,
        restores: AtomicUsize,
        fail_apply: bool,
        fail_restore: bool,
    }

    impl FakeAdapter {
        fn new(initial: Value) -> Self {
            Self {
                state: Mutex::new(initial),
                captures: AtomicUsize::new(0),
                applies: AtomicUsize::new(0),
                restores: AtomicUsize::new(0),
                fail_apply: false,
                fail_restore: false,
            }
        }
    }

    impl SystemProxyAdapter for FakeAdapter {
        fn platform(&self) -> &'static str {
            "test"
        }

        fn capture(&self) -> Result<Value, ClientError> {
            self.captures.fetch_add(1, Ordering::SeqCst);
            Ok(self.state.lock().unwrap().clone())
        }

        fn apply(
            &self,
            _snapshot: &Value,
            socks_port: u16,
            http_port: u16,
        ) -> Result<(), ClientError> {
            self.applies.fetch_add(1, Ordering::SeqCst);
            *self.state.lock().unwrap() = serde_json::json!({
                "socks": socks_port,
                "http": http_port,
            });
            if self.fail_apply {
                Err(proxy_error("fake_apply_failed"))
            } else {
                Ok(())
            }
        }

        fn restore(&self, snapshot: &Value) -> Result<(), ClientError> {
            self.restores.fetch_add(1, Ordering::SeqCst);
            if self.fail_restore {
                return Err(proxy_error("fake_restore_failed"));
            }
            *self.state.lock().unwrap() = snapshot.clone();
            Ok(())
        }
    }

    #[test]
    fn journal_survives_restart_and_recovers_before_new_use() {
        let directory = tempfile::tempdir().unwrap();
        let adapter = Arc::new(FakeAdapter::new(serde_json::json!({ "prior": true })));
        let manager =
            SystemProxyManager::new_with_adapter(directory.path(), adapter.clone()).unwrap();
        manager.apply(10808, 10809).unwrap();
        assert!(manager.inner.journal_path.exists());
        drop(manager);

        let rebuilt =
            SystemProxyManager::new_with_adapter(directory.path(), adapter.clone()).unwrap();
        assert_eq!(adapter.restores.load(Ordering::SeqCst), 0);
        assert_ne!(
            *adapter.state.lock().unwrap(),
            serde_json::json!({ "prior": true })
        );
        rebuilt.restore_pending().unwrap();
        assert_eq!(
            *adapter.state.lock().unwrap(),
            serde_json::json!({ "prior": true })
        );
        assert!(!rebuilt.inner.journal_path.exists());
        assert_eq!(adapter.restores.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn apply_failure_rolls_back_and_clears_the_journal() {
        let directory = tempfile::tempdir().unwrap();
        let adapter = Arc::new(FakeAdapter {
            fail_apply: true,
            ..FakeAdapter::new(serde_json::json!({ "prior": 7 }))
        });
        let manager =
            SystemProxyManager::new_with_adapter(directory.path(), adapter.clone()).unwrap();
        let error = manager.apply(10808, 10809).unwrap_err();
        assert_eq!(error.code, "fake_apply_failed");
        assert_eq!(
            *adapter.state.lock().unwrap(),
            serde_json::json!({ "prior": 7 })
        );
        assert!(!manager.inner.journal_path.exists());
    }

    #[test]
    fn failed_restore_retains_recovery_intent_for_the_next_launch() {
        let directory = tempfile::tempdir().unwrap();
        let adapter = Arc::new(FakeAdapter {
            fail_restore: true,
            ..FakeAdapter::new(serde_json::json!({ "prior": true }))
        });
        let manager = SystemProxyManager::new_with_adapter(directory.path(), adapter).unwrap();
        manager.apply(10808, 10809).unwrap();
        let error = manager.restore_pending().unwrap_err();
        assert_eq!(error.code, "fake_restore_failed");
        assert!(manager.inner.journal_path.exists());
    }

    #[test]
    fn manual_restore_without_a_journal_is_a_noop() {
        let directory = tempfile::tempdir().unwrap();
        let adapter = Arc::new(FakeAdapter::new(serde_json::json!({ "prior": true })));
        let manager =
            SystemProxyManager::new_with_adapter(directory.path(), adapter.clone()).unwrap();
        manager.restore_pending().unwrap();
        assert_eq!(adapter.restores.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn oversized_recovery_journal_is_rejected_before_parsing() {
        let directory = tempfile::tempdir().unwrap();
        let adapter = Arc::new(FakeAdapter::new(serde_json::json!({ "prior": true })));
        let manager =
            SystemProxyManager::new_with_adapter(directory.path(), adapter.clone()).unwrap();
        fs::write(
            &manager.inner.journal_path,
            vec![b' '; usize::try_from(MAX_JOURNAL_BYTES + 1).unwrap()],
        )
        .unwrap();

        let error = manager.restore_pending().unwrap_err();
        assert_eq!(error.code, "system_proxy_recovery_corrupt");
        assert_eq!(adapter.restores.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn windows_proxy_mapping_uses_http_for_web_and_socks_for_socks() {
        assert_eq!(
            windows_proxy_server(10_808, 10_809),
            "http=127.0.0.1:10809;https=127.0.0.1:10809;socks=127.0.0.1:10808"
        );
    }
}
