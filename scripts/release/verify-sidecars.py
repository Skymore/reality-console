#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import platform
import subprocess


ROOT = Path(__file__).resolve().parents[2]


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def checked_version(binary: Path, expected_prefix: str) -> str:
    result = subprocess.run(
        [binary, "version" if expected_prefix == "Xray " else "--version"],
        capture_output=True,
        check=True,
        text=True,
        timeout=10,
    )
    first_line = (result.stdout or result.stderr).splitlines()[0]
    if not first_line.startswith(expected_prefix):
        raise ValueError(f"unexpected sidecar version output: {first_line}")
    return first_line


def native_target(target: str) -> bool:
    machine = platform.machine().lower()
    if target.startswith("aarch64-"):
        return machine in {"arm64", "aarch64"}
    if target.startswith("x86_64-"):
        return machine in {"x86_64", "amd64"}
    return False


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True)
    parser.add_argument("--xray", type=Path, required=True)
    parser.add_argument("--node-host", type=Path)
    parser.add_argument("--node-host-version")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    config = json.loads((ROOT / "packaging/release-config.json").read_text(encoding="utf-8"))
    xray = config["xray"]
    expected = xray["assets"][args.target]["binarySha256"]
    actual = sha256(args.xray)
    if actual != expected:
        raise ValueError("packaged Xray executable SHA-256 mismatch")
    version_line = None
    if native_target(args.target):
        version_line = checked_version(args.xray, "Xray ")
        if not version_line.startswith(f"Xray {xray['version']} "):
            raise ValueError("packaged Xray version mismatch")
    components = [{
        "name": "xray",
        "version": xray["version"],
        "target": args.target,
        "sha256": actual,
        "size": args.xray.stat().st_size,
        "versionOutput": version_line,
    }]
    if args.node_host:
        if not args.node_host_version:
            raise ValueError("Node Host version is required with its sidecar")
        components.append({
            "name": "node-host",
            "version": args.node_host_version,
            "target": args.target,
            "sha256": sha256(args.node_host),
            "size": args.node_host.stat().st_size,
            "versionOutput": None,
        })
    document = {"schemaVersion": 1, "components": components}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
