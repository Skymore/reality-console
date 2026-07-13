#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import plistlib
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
from urllib.parse import urlsplit
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


LABEL = "com.private-network.control-service"
SCHEMA_VERSION = 1
DEFAULT_BIND = "127.0.0.1:8787"
DEFAULT_ORIGIN = "http://127.0.0.1:8787"
ROOT = Path(__file__).resolve().parents[2]


class ProductError(Exception):
    pass


def default_data_dir() -> Path:
    return Path.home() / "Library/Application Support/Private Network/Control Service"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def ensure_private_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    metadata = path.lstat()
    if path.is_symlink() or not path.is_dir():
        raise ProductError(f"unsafe directory: {path}")
    os.chmod(path, 0o700)
    if metadata.st_uid != os.getuid():
        raise ProductError(f"directory is not owned by the current user: {path}")


def validate_bind(value: str) -> tuple[str, int]:
    host, separator, raw_port = value.rpartition(":")
    if separator != ":" or host not in {"127.0.0.1", "localhost"}:
        raise ProductError("MVP Control Service must bind to loopback")
    try:
        port = int(raw_port)
    except ValueError as error:
        raise ProductError("bind port is invalid") from error
    if not 1 <= port <= 65535:
        raise ProductError("bind port is invalid")
    return host, port


def validate_origin(value: str) -> str:
    parsed = urlsplit(value)
    loopback = parsed.hostname in {"127.0.0.1", "::1", "localhost"}
    if (
        parsed.scheme not in ({"http", "https"} if loopback else {"https"})
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise ProductError("public origin must be a clean HTTPS origin or loopback HTTP origin")
    port = f":{parsed.port}" if parsed.port is not None else ""
    return f"{parsed.scheme}://{parsed.hostname}{port}"


def resolve_xray(value: str | None) -> Path:
    candidate = Path(value).expanduser() if value else None
    if candidate is None:
        discovered = shutil.which("xray")
        candidate = Path(discovered) if discovered else None
    if candidate is None:
        for known in (Path("/opt/homebrew/bin/xray"), Path("/usr/local/bin/xray")):
            if known.is_file():
                candidate = known
                break
    if candidate is None:
        raise ProductError("Xray was not found; install it or pass --xray-path")
    candidate = candidate.resolve()
    if not candidate.is_file() or not os.access(candidate, os.X_OK):
        raise ProductError("Xray path is not an executable file")
    return candidate


def read_existing_config(path: Path) -> dict[str, object] | None:
    if not path.exists():
        return None
    if path.is_symlink() or not path.is_file() or path.stat().st_uid != os.getuid():
        raise ProductError("existing Control Service config path is unsafe")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ProductError("existing Control Service config is invalid") from error
    if not isinstance(value, dict) or not isinstance(value.get("bootstrapToken"), str):
        raise ProductError("existing Control Service config is invalid")
    return value


def read_private_secret(path: Path) -> str:
    path = path.expanduser().absolute()
    metadata = path.lstat()
    if path.is_symlink() or not path.is_file() or metadata.st_uid != os.getuid():
        raise ProductError("probe token file is unsafe")
    if metadata.st_mode & 0o077:
        raise ProductError("probe token file must be owner-only")
    value = path.read_text(encoding="utf-8").strip()
    if not 32 <= len(value) <= 512 or not value.isascii() or any(character.isspace() for character in value):
        raise ProductError("probe token must contain 32 to 512 visible ASCII bytes")
    return value


def probe_config(
    mode: str | None,
    url: str | None,
    token_file: Path | None,
    existing: dict[str, object] | None,
) -> tuple[str, str | None, str | None]:
    selected = mode or (str(existing.get("probeMode")) if existing else "disabled")
    if selected not in {"disabled", "local-tcp", "remote-http"}:
        raise ProductError("probe mode is invalid")
    if selected != "remote-http":
        if url is not None or token_file is not None:
            raise ProductError("probe URL and token file require remote-http mode")
        return selected, None, None
    selected_url = url or (str(existing.get("tcpProbeUrl")) if existing and existing.get("tcpProbeUrl") else None)
    selected_token = (
        read_private_secret(token_file)
        if token_file is not None
        else str(existing.get("tcpProbeToken"))
        if existing and existing.get("tcpProbeToken")
        else None
    )
    if selected_url is None or selected_token is None:
        raise ProductError("remote-http mode requires a probe URL and owner-only token file")
    parsed = urlsplit(selected_url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.path != "/v1/tcp-probe" or parsed.query or parsed.fragment:
        raise ProductError("probe URL must be an HTTPS /v1/tcp-probe endpoint")
    return selected, selected_url, selected_token


def build_config(
    data_dir: Path,
    bind_address: str | None,
    public_origin: str | None,
    network_name: str | None,
    xray: Path,
    existing: dict[str, object] | None,
    probe_mode: str | None = None,
    tcp_probe_url: str | None = None,
    tcp_probe_token_file: Path | None = None,
) -> dict[str, object]:
    bind_address = bind_address or (
        str(existing.get("bindAddress")) if existing else DEFAULT_BIND
    )
    public_origin = public_origin or (
        str(existing.get("publicOrigin")) if existing else DEFAULT_ORIGIN
    )
    network_name = network_name or (
        str(existing.get("networkName")) if existing else "Friends Network"
    )
    validate_bind(bind_address)
    public_origin = validate_origin(public_origin)
    if not network_name or network_name.strip() != network_name or len(network_name) > 128:
        raise ProductError("network name must contain 1 to 128 trimmed characters")
    token = existing.get("bootstrapToken") if existing else secrets.token_urlsafe(48)
    if not isinstance(token, str) or len(token) < 32:
        raise ProductError("existing bootstrap token is invalid")
    probe_mode, tcp_probe_url, tcp_probe_token = probe_config(
        probe_mode, tcp_probe_url, tcp_probe_token_file, existing
    )
    return {
        "schemaVersion": SCHEMA_VERSION,
        "bindAddress": bind_address,
        "databasePath": str((data_dir / "state/control-service.sqlite3").resolve()),
        "networkName": network_name,
        "bootstrapToken": token,
        "publicOrigin": public_origin,
        "requestTimeoutSeconds": 10,
        "probeMode": probe_mode,
        "tcpProbeUrl": tcp_probe_url,
        "tcpProbeToken": tcp_probe_token,
        "protocolCanaryXrayPath": str(xray),
        "protocolCanaryXraySha256": sha256_file(xray),
    }


def atomic_json(path: Path, value: dict[str, object]) -> None:
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            json.dump(value, output, indent=2, sort_keys=True)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600)
    finally:
        temporary.unlink(missing_ok=True)


def build_plist(binary: Path, config: Path, logs: Path) -> dict[str, object]:
    return {
        "Label": LABEL,
        "ProgramArguments": [str(binary), "serve", "--config", str(config)],
        "RunAtLoad": True,
        "KeepAlive": {"SuccessfulExit": False},
        "ThrottleInterval": 10,
        "StandardOutPath": str(logs / "control-service.log"),
        "StandardErrorPath": str(logs / "control-service.error.log"),
        "ProcessType": "Background",
    }


def write_plist(path: Path, value: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = plistlib.dumps(value, fmt=plistlib.FMT_XML, sort_keys=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_bytes(data)
    os.chmod(temporary, 0o644)
    os.replace(temporary, path)


def launch_domain() -> str:
    return f"gui/{os.getuid()}"


def run_launchctl(*arguments: str, check: bool = True) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        ["/bin/launchctl", *arguments],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=check,
    )


def bootout() -> None:
    run_launchctl("bootout", f"{launch_domain()}/{LABEL}", check=False)


def start_service(plist: Path) -> None:
    bootout()
    service = f"{launch_domain()}/{LABEL}"
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        if run_launchctl("print", service, check=False).returncode != 0:
            break
        time.sleep(0.05)
    result = None
    for attempt in range(3):
        result = run_launchctl("bootstrap", launch_domain(), str(plist), check=False)
        if result.returncode == 0 or run_launchctl("print", service, check=False).returncode == 0:
            break
        if attempt < 2:
            time.sleep(0.25 * (attempt + 1))
    if result is None or (result.returncode != 0 and run_launchctl("print", service, check=False).returncode != 0):
        message = result.stderr.decode(errors="replace").strip() if result is not None else ""
        raise ProductError(message or "launchctl bootstrap failed")
    run_launchctl("enable", service)
    run_launchctl("kickstart", "-k", service)


def health_url(config: dict[str, object]) -> str:
    host, port = validate_bind(str(config["bindAddress"]))
    return f"http://{host}:{port}/healthz"


def wait_healthy(config: dict[str, object], timeout: float = 30.0) -> None:
    deadline = time.monotonic() + timeout
    url = health_url(config)
    while time.monotonic() < deadline:
        try:
            with urlopen(url, timeout=2) as response:
                if response.status == 200:
                    value = json.loads(response.read())
                    if value.get("status") == "ok":
                        return
        except Exception:
            time.sleep(0.25)
    raise ProductError("Control Service did not become healthy; inspect the error log")


def install(args: argparse.Namespace) -> None:
    if sys.platform != "darwin":
        raise ProductError("background installation currently supports macOS")
    data_dir = args.data_dir.expanduser().resolve()
    for directory in (data_dir, data_dir / "bin", data_dir / "state", data_dir / "logs"):
        ensure_private_directory(directory)
    config_path = data_dir / "control-service.json"
    existing = read_existing_config(config_path)
    xray = resolve_xray(args.xray_path)
    config = build_config(
        data_dir,
        args.bind_address,
        args.public_origin,
        args.network_name,
        xray,
        existing,
        args.probe_mode,
        args.tcp_probe_url,
        args.tcp_probe_token_file,
    )
    atomic_json(config_path, config)

    subprocess.run(
        [
            "cargo",
            "build",
            "--release",
            "--locked",
            "--manifest-path",
            str(ROOT / "control-server/Cargo.toml"),
        ],
        cwd=ROOT,
        check=True,
    )
    built = ROOT / "control-server/target/release/control-server"
    installed = data_dir / "bin/control-server"
    temporary = installed.with_name(f".{installed.name}.{os.getpid()}.tmp")
    shutil.copyfile(built, temporary)
    os.chmod(temporary, 0o700)
    os.replace(temporary, installed)

    plist = Path.home() / f"Library/LaunchAgents/{LABEL}.plist"
    write_plist(plist, build_plist(installed, config_path, data_dir / "logs"))
    start_service(plist)
    wait_healthy(config)
    print(f"Control Service is running at {health_url(config).removesuffix('/healthz')}")
    print(f"Public origin: {config['publicOrigin']}")
    print("Admin token remains owner-only. Use the admin-token command when needed.")


def load_config(data_dir: Path) -> dict[str, object]:
    value = read_existing_config(data_dir.expanduser().resolve() / "control-service.json")
    if value is None:
        raise ProductError("Control Service is not initialized")
    return value


def status(args: argparse.Namespace) -> None:
    config = load_config(args.data_dir)
    launch = run_launchctl("print", f"{launch_domain()}/{LABEL}", check=False)
    running = launch.returncode == 0
    healthy = False
    try:
        wait_healthy(config, timeout=1.5)
        healthy = True
    except ProductError:
        pass
    print(json.dumps({"installed": True, "launchdLoaded": running, "healthy": healthy, "origin": config["publicOrigin"]}))
    if not healthy:
        raise ProductError("Control Service is not healthy")


def start(args: argparse.Namespace) -> None:
    config = load_config(args.data_dir)
    plist = Path.home() / f"Library/LaunchAgents/{LABEL}.plist"
    if not plist.is_file():
        raise ProductError("Control Service LaunchAgent is missing; run install")
    start_service(plist)
    wait_healthy(config)
    print("Control Service started")


def stop(_: argparse.Namespace) -> None:
    bootout()
    print("Control Service stopped")


def admin_token(args: argparse.Namespace) -> None:
    config = load_config(args.data_dir)
    print(config["bootstrapToken"])


def admin_request(
    config: dict[str, object],
    method: str,
    path: str,
    body: dict[str, object] | None = None,
    idempotency_key: str | None = None,
) -> object:
    host, port = validate_bind(str(config["bindAddress"]))
    origin = f"http://{host}:{port}"
    headers = {"Authorization": f"Bearer {config['bootstrapToken']}"}
    data = None
    if body is not None:
        data = json.dumps(body, separators=(",", ":")).encode()
        headers["Content-Type"] = "application/json"
    if idempotency_key is not None:
        headers["Idempotency-Key"] = idempotency_key
    request = Request(f"{origin}{path}", data=data, headers=headers, method=method)
    try:
        with urlopen(request, timeout=10) as response:
            payload = response.read()
            return json.loads(payload) if payload else None
    except HTTPError as error:
        raise ProductError(f"Control Service rejected the request with HTTP {error.code}") from error
    except (URLError, TimeoutError) as error:
        raise ProductError("Control Service is unavailable") from error


def node_invitation_body(args: argparse.Namespace) -> dict[str, object]:
    return {
        "displayName": args.display_name,
        "expiresInSeconds": args.expires_in_seconds,
        "initialConfiguration": {
            "minAgentVersion": "0.1.0",
            "xray": {
                "listenPort": args.listen_port,
                "publicPort": args.public_port,
                "serverNames": [args.server_name],
                "target": args.target or f"{args.server_name}:443",
            },
        },
    }


def create_node(args: argparse.Namespace) -> None:
    config = load_config(args.data_dir)
    value = admin_request(
        config,
        "POST",
        "/v1/admin/node-invitations",
        node_invitation_body(args),
        args.idempotency_key or str(uuid.uuid4()),
    )
    if not isinstance(value, dict) or not isinstance(value.get("setupCode"), str):
        raise ProductError("Control Service returned an invalid node setup response")
    print(json.dumps(value, indent=2))


def nodes(args: argparse.Namespace) -> None:
    config = load_config(args.data_dir)
    print(json.dumps(admin_request(config, "GET", "/v1/admin/nodes"), indent=2))


def set_node_status(args: argparse.Namespace) -> None:
    config = load_config(args.data_dir)
    admin_request(
        config,
        "POST",
        f"/v1/admin/nodes/{args.node_id}/{args.status}",
    )
    print(json.dumps({"nodeId": args.node_id, "status": args.status}, indent=2))


def create_account(args: argparse.Namespace) -> None:
    config = load_config(args.data_dir)
    value = admin_request(
        config,
        "POST",
        "/v1/admin/accounts",
        {"displayName": args.display_name},
        args.idempotency_key or str(uuid.uuid4()),
    )
    print(json.dumps(value, indent=2))


def accounts(args: argparse.Namespace) -> None:
    config = load_config(args.data_dir)
    print(json.dumps(admin_request(config, "GET", "/v1/admin/accounts"), indent=2))


def assign_account(args: argparse.Namespace) -> None:
    config = load_config(args.data_dir)
    node_ids = list(dict.fromkeys(args.node_id))
    if len(node_ids) != len(args.node_id):
        raise ProductError("node IDs must not be repeated")
    value = admin_request(
        config,
        "PUT",
        f"/v1/admin/accounts/{args.user_id}/nodes",
        {"nodeIds": node_ids},
    )
    print(json.dumps(value, indent=2))


def set_account_status(args: argparse.Namespace) -> None:
    config = load_config(args.data_dir)
    value = admin_request(
        config,
        "PUT",
        f"/v1/admin/accounts/{args.user_id}/status",
        {"status": args.status},
    )
    print(json.dumps(value, indent=2))


def create_connect_code(args: argparse.Namespace) -> None:
    config = load_config(args.data_dir)
    value = admin_request(
        config,
        "POST",
        f"/v1/admin/accounts/{args.user_id}/device-activations",
        {"expiresInSeconds": args.expires_in_seconds},
        args.idempotency_key or str(uuid.uuid4()),
    )
    if not isinstance(value, dict) or not isinstance(value.get("setupCode"), str):
        raise ProductError("Control Service returned an invalid Connect setup response")
    print(json.dumps(value, indent=2))


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser()
    commands = root.add_subparsers(dest="command", required=True)
    install_parser = commands.add_parser("install")
    install_parser.add_argument("--data-dir", type=Path, default=default_data_dir())
    install_parser.add_argument("--bind-address")
    install_parser.add_argument("--public-origin")
    install_parser.add_argument("--network-name")
    install_parser.add_argument("--xray-path")
    install_parser.add_argument("--probe-mode", choices=("disabled", "local-tcp", "remote-http"))
    install_parser.add_argument("--tcp-probe-url")
    install_parser.add_argument("--tcp-probe-token-file", type=Path)
    for name in ("status", "start", "admin-token"):
        command = commands.add_parser(name)
        command.add_argument("--data-dir", type=Path, default=default_data_dir())
    commands.add_parser("stop")
    create_node_parser = commands.add_parser("create-node")
    create_node_parser.add_argument("--data-dir", type=Path, default=default_data_dir())
    create_node_parser.add_argument("--display-name", required=True)
    create_node_parser.add_argument("--expires-in-seconds", type=int, default=3600)
    create_node_parser.add_argument("--listen-port", type=int, default=10443)
    create_node_parser.add_argument("--public-port", type=int, default=443)
    create_node_parser.add_argument("--server-name", default="www.microsoft.com")
    create_node_parser.add_argument("--target")
    create_node_parser.add_argument("--idempotency-key")
    nodes_parser = commands.add_parser("nodes")
    nodes_parser.add_argument("--data-dir", type=Path, default=default_data_dir())
    node_status_parser = commands.add_parser("set-node-status")
    node_status_parser.add_argument("--data-dir", type=Path, default=default_data_dir())
    node_status_parser.add_argument("--node-id", required=True)
    node_status_parser.add_argument("--status", choices=("approve", "disable", "revoke"), required=True)
    create_account_parser = commands.add_parser("create-account")
    create_account_parser.add_argument("--data-dir", type=Path, default=default_data_dir())
    create_account_parser.add_argument("--display-name", required=True)
    create_account_parser.add_argument("--idempotency-key")
    accounts_parser = commands.add_parser("accounts")
    accounts_parser.add_argument("--data-dir", type=Path, default=default_data_dir())
    assign_parser = commands.add_parser("assign-account")
    assign_parser.add_argument("--data-dir", type=Path, default=default_data_dir())
    assign_parser.add_argument("--user-id", required=True)
    assign_parser.add_argument("--node-id", action="append", default=[])
    account_status_parser = commands.add_parser("set-account-status")
    account_status_parser.add_argument("--data-dir", type=Path, default=default_data_dir())
    account_status_parser.add_argument("--user-id", required=True)
    account_status_parser.add_argument("--status", choices=("active", "disabled", "deleted"), required=True)
    connect_parser = commands.add_parser("create-connect-code")
    connect_parser.add_argument("--data-dir", type=Path, default=default_data_dir())
    connect_parser.add_argument("--user-id", required=True)
    connect_parser.add_argument("--expires-in-seconds", type=int, default=900)
    connect_parser.add_argument("--idempotency-key")
    return root


def main() -> int:
    args = parser().parse_args()
    try:
        if args.command == "install":
            install(args)
        elif args.command == "status":
            status(args)
        elif args.command == "start":
            start(args)
        elif args.command == "stop":
            stop(args)
        elif args.command == "admin-token":
            admin_token(args)
        elif args.command == "create-node":
            create_node(args)
        elif args.command == "nodes":
            nodes(args)
        elif args.command == "set-node-status":
            set_node_status(args)
        elif args.command == "create-account":
            create_account(args)
        elif args.command == "accounts":
            accounts(args)
        elif args.command == "assign-account":
            assign_account(args)
        elif args.command == "set-account-status":
            set_account_status(args)
        else:
            create_connect_code(args)
    except (ProductError, OSError, subprocess.CalledProcessError, ValueError) as error:
        print(f"control-service: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
