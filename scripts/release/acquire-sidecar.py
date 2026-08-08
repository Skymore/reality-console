#!/usr/bin/env python3
"""Acquire one pinned Xray sidecar without trusting archive paths."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import tempfile
import urllib.request
import zipfile


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CONFIG = ROOT / "packaging" / "release-config.json"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def checked_config(path: Path, target: str) -> tuple[dict, dict]:
    config = json.loads(path.read_text(encoding="utf-8"))
    if config.get("schemaVersion") != 1:
        raise ValueError("unsupported release config schema")
    xray = config.get("xray", {})
    asset = xray.get("assets", {}).get(target)
    if not asset:
        raise ValueError(f"unsupported Xray target: {target}")
    for field in ("archive", "archiveSha256", "binary", "binarySha256"):
        if not isinstance(asset.get(field), str) or not asset[field]:
            raise ValueError(f"missing Xray asset field: {field}")
    for field in ("archiveSha256", "binarySha256"):
        value = asset[field]
        if len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
            raise ValueError(f"invalid {field}")
    return xray, asset


def download(url: str, destination: Path) -> None:
    request = urllib.request.Request(url, headers={"User-Agent": "private-network-release/1"})
    with urllib.request.urlopen(request, timeout=120) as response, destination.open("wb") as output:
        if response.geturl().split("?", 1)[0].rsplit("/", 1)[-1] == "":
            raise ValueError("download resolved to an invalid URL")
        shutil.copyfileobj(response, output, length=1024 * 1024)


def extract_exact(archive: Path, member_name: str, destination: Path) -> None:
    with zipfile.ZipFile(archive) as bundle:
        matches = [entry for entry in bundle.infolist() if entry.filename == member_name]
        if len(matches) != 1 or matches[0].is_dir():
            raise ValueError(f"archive must contain exactly one {member_name}")
        entry = matches[0]
        if entry.file_size > 128 * 1024 * 1024:
            raise ValueError("Xray sidecar exceeds the extraction limit")
        with bundle.open(entry) as source, destination.open("wb") as output:
            shutil.copyfileobj(source, output, length=1024 * 1024)


def install_verified_binary(source: Path, output: Path) -> None:
    """Atomically install a verified binary, including across Windows drives."""
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        dir=output.parent,
        prefix=f".{output.name}.",
        delete=False,
    ) as staged_file:
        staged = Path(staged_file.name)
    try:
        shutil.copyfile(source, staged)
        os.chmod(staged, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
        os.replace(staged, output)
    finally:
        staged.unlink(missing_ok=True)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--target", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--archive", type=Path, help="verify and use a pre-fetched archive")
    args = parser.parse_args()

    xray, asset = checked_config(args.config, args.target)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="xray-sidecar-") as temporary:
        archive = Path(temporary) / asset["archive"]
        if args.archive:
            shutil.copyfile(args.archive, archive)
        else:
            base = xray["releaseBaseUrl"].rstrip("/")
            download(f"{base}/{asset['archive']}", archive)
        if sha256(archive) != asset["archiveSha256"]:
            raise ValueError("Xray archive SHA-256 mismatch")
        extracted = Path(temporary) / "xray"
        extract_exact(archive, asset["binary"], extracted)
        if sha256(extracted) != asset["binarySha256"]:
            raise ValueError("Xray executable SHA-256 mismatch")
        install_verified_binary(extracted, args.output)

    print(json.dumps({
        "component": "xray",
        "version": xray["version"],
        "target": args.target,
        "sha256": asset["binarySha256"],
        "output": str(args.output),
    }, sort_keys=True))


if __name__ == "__main__":
    main()
