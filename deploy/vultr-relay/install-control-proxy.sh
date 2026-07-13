#!/usr/bin/env bash
set -euo pipefail

CADDY_VERSION="2.11.4"
CADDY_LINUX_AMD64_SHA256="527fbf917c39189a1e3b31d34fa955601680b2d5c8055d2a87b8b9588dec7bb9"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONTROL_HOST="${1:-}"

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run this installer as root." >&2
  exit 1
fi
if [[ ! "${CONTROL_HOST}" =~ ^[a-zA-Z0-9.-]+$ ]] || [[ "${CONTROL_HOST}" != *.* ]]; then
  echo "Usage: $0 control.example.com" >&2
  exit 1
fi
if [[ "$(uname -m)" != "x86_64" ]]; then
  echo "Unsupported VPS architecture: $(uname -m)" >&2
  exit 1
fi

work_dir="$(mktemp -d)"
trap 'rm -rf "${work_dir}"' EXIT
archive="${work_dir}/caddy.tar.gz"
url="https://github.com/caddyserver/caddy/releases/download/v${CADDY_VERSION}/caddy_${CADDY_VERSION}_linux_amd64.tar.gz"

curl -fsSL "${url}" -o "${archive}"
printf '%s  %s\n' "${CADDY_LINUX_AMD64_SHA256}" "${archive}" | sha256sum --check --status
tar -xzf "${archive}" -C "${work_dir}" caddy
install -m 0755 "${work_dir}/caddy" /usr/local/bin/caddy

id caddy >/dev/null 2>&1 || useradd --system --home-dir /var/lib/caddy --shell /usr/sbin/nologin caddy
install -d -o root -g caddy -m 0750 /etc/caddy
install -d -o caddy -g caddy -m 0750 /var/lib/caddy /var/log/caddy
sed "s/CONTROL_HOST/${CONTROL_HOST}/g" "${SCRIPT_DIR}/Caddyfile.example" > /etc/caddy/Caddyfile
chown root:caddy /etc/caddy/Caddyfile
chmod 0640 /etc/caddy/Caddyfile
/usr/local/bin/caddy validate --config /etc/caddy/Caddyfile

install -m 0644 "${SCRIPT_DIR}/caddy.service" /etc/systemd/system/caddy.service
systemctl daemon-reload
systemctl enable --now caddy
ufw allow 80/tcp
ufw allow 8443/tcp

echo "Control HTTPS gateway installed for https://${CONTROL_HOST}:8443"
