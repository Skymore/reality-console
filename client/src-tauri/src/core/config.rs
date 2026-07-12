use super::connection::ConnectionProfile;
use serde_json::{json, Value};

pub const DEFAULT_SOCKS_PORT: u16 = 10808;
pub const DEFAULT_HTTP_PORT: u16 = 10809;

pub fn build_xray_config(profile: &ConnectionProfile, socks_port: u16, http_port: u16) -> Value {
    json!({
        "log": {
            "loglevel": "warning"
        },
        "inbounds": [
            {
                "tag": "socks-in",
                "listen": "127.0.0.1",
                "port": socks_port,
                "protocol": "socks",
                "settings": {
                    "udp": true
                }
            },
            {
                "tag": "http-in",
                "listen": "127.0.0.1",
                "port": http_port,
                "protocol": "http"
            }
        ],
        "outbounds": [
            {
                "tag": "proxy",
                "protocol": "vless",
                "settings": {
                    "address": profile.server_address,
                    "port": profile.server_port,
                    "id": profile.user_id.to_string(),
                    "encryption": "none",
                    "flow": profile.flow
                },
                "streamSettings": {
                    "network": "raw",
                    "security": "reality",
                    "realitySettings": {
                        "serverName": profile.server_name,
                        "fingerprint": profile.fingerprint,
                        "password": profile.reality_password,
                        "shortId": profile.short_id,
                        "spiderX": profile.spider_x
                    }
                }
            }
        ]
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::invite::parse_invitation;
    use std::fs;
    use std::process::Command;

    const VALID_INVITATION: &str = "vless://11111111-1111-4111-8111-111111111111@203.0.113.10:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.example.com&fp=chrome&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sid=753bd0a1&type=tcp&headerType=none#Friend";

    #[test]
    fn generates_loopback_only_current_xray_config() {
        let profile = parse_invitation(VALID_INVITATION).expect("valid invitation");
        let config = build_xray_config(&profile, DEFAULT_SOCKS_PORT, DEFAULT_HTTP_PORT);

        assert_eq!(
            config.pointer("/inbounds/0/listen"),
            Some(&json!("127.0.0.1"))
        );
        assert_eq!(
            config.pointer("/inbounds/1/listen"),
            Some(&json!("127.0.0.1"))
        );
        assert_eq!(config.pointer("/inbounds/0/port"), Some(&json!(10808)));
        assert_eq!(
            config.pointer("/outbounds/0/streamSettings/network"),
            Some(&json!("raw"))
        );
        assert_eq!(
            config.pointer("/outbounds/0/streamSettings/realitySettings/password"),
            Some(&json!("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"))
        );
        assert!(config
            .pointer("/outbounds/0/streamSettings/realitySettings/publicKey")
            .is_none());
    }

    #[test]
    #[ignore = "requires xray on PATH"]
    fn generated_config_passes_xray_validation() {
        let profile = parse_invitation(VALID_INVITATION).expect("valid invitation");
        let config = build_xray_config(&profile, DEFAULT_SOCKS_PORT, DEFAULT_HTTP_PORT);
        let path = std::env::temp_dir().join(format!(
            "reality-client-config-test-{}.json",
            std::process::id()
        ));
        fs::write(
            &path,
            serde_json::to_vec_pretty(&config).expect("serialize config"),
        )
        .expect("write config");

        let output = Command::new("xray")
            .args(["run", "-test", "-config"])
            .arg(&path)
            .output()
            .expect("xray must be installed");
        let _ = fs::remove_file(&path);

        assert!(
            output.status.success(),
            "xray rejected config: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
