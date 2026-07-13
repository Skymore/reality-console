#!/usr/bin/env bash
set -euo pipefail

FRP_VERSION="0.70.0"
FRP_LINUX_AMD64_SHA256="281cb31e6b915113179c6ebb65b5977a5d9d7fb96f9a70867be83dee3b657721"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run this installer as root." >&2
  exit 1
fi

case "$(uname -m)" in
  x86_64)
    archive_arch="linux_amd64"
    archive_sha256="${FRP_LINUX_AMD64_SHA256}"
    ;;
  *)
    echo "Unsupported VPS architecture: $(uname -m)" >&2
    exit 1
    ;;
esac

work_dir="$(mktemp -d)"
trap 'rm -rf "${work_dir}"' EXIT
archive="${work_dir}/frp.tar.gz"
url="https://github.com/fatedier/frp/releases/download/v${FRP_VERSION}/frp_${FRP_VERSION}_${archive_arch}.tar.gz"

curl -fsSL "${url}" -o "${archive}"
printf '%s  %s\n' "${archive_sha256}" "${archive}" | sha256sum --check --status
tar -xzf "${archive}" -C "${work_dir}"

install -m 0755 "${work_dir}/frp_${FRP_VERSION}_${archive_arch}/frps" /usr/local/bin/frps
id frp >/dev/null 2>&1 || useradd --system --home-dir /var/lib/frp --shell /usr/sbin/nologin frp
install -d -o frp -g frp -m 0750 /etc/frp /var/lib/frp
install -o root -g frp -m 0640 "${SCRIPT_DIR}/frps.toml" /etc/frp/frps.toml

if [[ ! -s /etc/frp/token ]]; then
  umask 0077
  openssl rand -hex 32 > /etc/frp/token
fi
chown root:frp /etc/frp/token
chmod 0640 /etc/frp/token

/usr/local/bin/frps verify -c /etc/frp/frps.toml
install -m 0644 "${SCRIPT_DIR}/frps.service" /etc/systemd/system/frps.service
systemctl daemon-reload
systemctl enable --now frps

ufw allow 443/tcp
ufw allow 7000/tcp

install -m 0644 "${SCRIPT_DIR}/99-relay-hardening.conf" /etc/ssh/sshd_config.d/99-relay-hardening.conf
sshd -t
systemctl restart ssh

echo "FRP relay installed successfully."
