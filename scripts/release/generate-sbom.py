#!/usr/bin/env python3
"""Generate a deterministic CycloneDX inventory from committed lock files."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import tomllib
import uuid


NAMESPACE = uuid.UUID("29b85d15-da98-48af-ae1d-bbb51e6d626a")


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def cargo_components(path: Path) -> list[dict]:
    lock = tomllib.loads(path.read_text(encoding="utf-8"))
    output = []
    for package in lock.get("package", []):
        name, version = package["name"], package["version"]
        component = {
            "type": "library",
            "name": name,
            "version": version,
            "purl": f"pkg:cargo/{name}@{version}",
        }
        checksum = package.get("checksum")
        if checksum:
            component["hashes"] = [{"alg": "SHA-256", "content": checksum}]
        output.append(component)
    return output


def npm_components(path: Path) -> list[dict]:
    lock = json.loads(path.read_text(encoding="utf-8"))
    output = []
    for location, package in lock.get("packages", {}).items():
        if not location or not location.startswith("node_modules/") or not package.get("version"):
            continue
        name = location.removeprefix("node_modules/")
        version = package["version"]
        output.append({
            "type": "library",
            "name": name,
            "version": version,
            "purl": f"pkg:npm/{name}@{version}",
        })
    return output


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--product", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--cargo-lock", type=Path, action="append", default=[])
    parser.add_argument("--npm-lock", type=Path, action="append", default=[])
    parser.add_argument("--xray-version", required=True)
    parser.add_argument("--xray-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    components = []
    lock_hashes = []
    for path in args.cargo_lock:
        components.extend(cargo_components(path))
        lock_hashes.append({"name": str(path), "sha256": sha256(path)})
    for path in args.npm_lock:
        components.extend(npm_components(path))
        lock_hashes.append({"name": str(path), "sha256": sha256(path)})
    components.append({
        "type": "application",
        "name": "xray",
        "version": args.xray_version,
        "hashes": [{"alg": "SHA-256", "content": args.xray_sha256}],
    })
    unique = {component.get("purl", f"xray@{args.xray_version}"): component for component in components}
    components = [unique[key] for key in sorted(unique)]
    identity = f"{args.product}:{args.version}:{args.target}:" + ":".join(
        item["sha256"] for item in sorted(lock_hashes, key=lambda item: item["name"])
    )
    document = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid5(NAMESPACE, identity)}",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "name": args.product,
                "version": args.version,
                "properties": [{"name": "private-network:target", "value": args.target}],
            },
            "properties": [
                {"name": f"private-network:lock:{item['name']}", "value": item["sha256"]}
                for item in sorted(lock_hashes, key=lambda item: item["name"])
            ],
        },
        "components": components,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
