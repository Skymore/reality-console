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


def build_config(
    data_dir: Path,
    bind_address: str,
    public_origin: str,
    network_name: str,
    xray: Path,
    existing: dict[str, object] | None,
) -> dict[str, object]:
    validate_bind(bind_address)
    public_origin = validate_origin(public_origin)
    if not network_name or network_name.strip() != network_name or len(network_name) > 128:
        raise ProductError("network name must contain 1 to 128 trimmed characters")
    token = existing.get("bootstrapToken") if existing else secrets.token_urlsafe(48)
    if not isinstance(token, str) or len(token) < 32:
        raise ProductError("existing bootstrap token is invalid")
    return {
        "schemaVersion": SCHEMA_VERSION,
        "bindAddress": bind_address,
        "databasePath": str((data_dir / "state/control-service.sqlite3").resolve()),
        "networkName": network_name,
        "bootstrapToken": token,
        "publicOrigin": public_origin,
        "requestTimeoutSeconds": 10,
        "probeMode": "disabled",
        "tcpProbeUrl": None,
        "tcpProbeToken": None,
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
    result = run_launchctl("bootstrap", launch_domain(), str(plist), check=False)
    if result.returncode != 0:
        raise ProductError(result.stderr.decode(errors="replace").strip() or "launchctl bootstrap failed")
    run_launchctl("enable", f"{launch_domain()}/{LABEL}")
    run_launchctl("kickstart", "-k", f"{launch_domain()}/{LABEL}")


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
) -> object:
    host, port = validate_bind(str(config["bindAddress"]))
    origin = f"http://{host}:{port}"
    headers = {"Authorization": f"Bearer {config['bootstrapToken']}"}
    data = None
    if body is not None:
        data = json.dumps(body, separators=(",", ":")).encode()
        headers["Content-Type"] = "application/json"
        headers["Idempotency-Key"] = str(uuid.uuid4())
    request = Request(f"{origin}{path}", data=data, headers=headers, method=method)
    try:
        with urlopen(request, timeout=10) as response:
            return json.loads(response.read())
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
    value = admin_request(config, "POST", "/v1/admin/node-invitations", node_invitation_body(args))
    if not isinstance(value, dict) or not isinstance(value.get("setupCode"), str):
        raise ProductError("Control Service returned an invalid node setup response")
    print(json.dumps(value, indent=2))


def nodes(args: argparse.Namespace) -> None:
    config = load_config(args.data_dir)
    print(json.dumps(admin_request(config, "GET", "/v1/admin/nodes"), indent=2))


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser()
    commands = root.add_subparsers(dest="command", required=True)
    install_parser = commands.add_parser("install")
    install_parser.add_argument("--data-dir", type=Path, default=default_data_dir())
    install_parser.add_argument("--bind-address", default=DEFAULT_BIND)
    install_parser.add_argument("--public-origin", default=DEFAULT_ORIGIN)
    install_parser.add_argument("--network-name", default="Friends Network")
    install_parser.add_argument("--xray-path")
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
    nodes_parser = commands.add_parser("nodes")
    nodes_parser.add_argument("--data-dir", type=Path, default=default_data_dir())
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
        else:
            nodes(args)
    except (ProductError, OSError, subprocess.CalledProcessError, ValueError) as error:
        print(f"control-service: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
