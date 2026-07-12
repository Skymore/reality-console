#!/usr/bin/env python3
"""Fail closed on malformed release config and partial signing credentials."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[2]
HEX_256 = re.compile(r"^[0-9a-f]{64}$")
TARGETS = {
    "connect-macos-aarch64": ("connect", "aarch64-apple-darwin", "macos"),
    "connect-macos-x86_64": ("connect", "x86_64-apple-darwin", "macos"),
    "connect-windows-x86_64": ("connect", "x86_64-pc-windows-msvc", "windows"),
    "node-host-macos-aarch64": ("nodeHost", "aarch64-apple-darwin", "macos"),
    "node-host-macos-x86_64": ("nodeHost", "x86_64-apple-darwin", "macos"),
}


def group_state(name: str, variables: tuple[str, ...]) -> bool:
    present = [bool(os.environ.get(variable)) for variable in variables]
    if any(present) and not all(present):
        missing = [variable for variable, exists in zip(variables, present) if not exists]
        raise ValueError(f"{name} signing credentials are partial; missing {', '.join(missing)}")
    return all(present)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, default=ROOT / "packaging/release-config.json")
    parser.add_argument("--target", choices=sorted(TARGETS), required=True)
    parser.add_argument("--mode", choices=("validation", "release"), default="validation")
    parser.add_argument("--scope", choices=("all", "artifact", "manifest"), default="all")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    config = json.loads(args.config.read_text(encoding="utf-8"))
    trust = json.loads((ROOT / "packaging/release-trust.json").read_text(encoding="utf-8"))
    if config.get("schemaVersion") != 1:
        raise ValueError("unsupported release config schema")
    product, triple, platform = TARGETS[args.target]
    product_config = config["products"][product]
    if triple not in product_config["targets"]:
        raise ValueError("release target is not declared by its product")
    xray = config["xray"]
    asset = xray["assets"][triple]
    if not xray["releaseBaseUrl"].startswith("https://github.com/XTLS/Xray-core/releases/download/"):
        raise ValueError("Xray release origin is not the approved upstream")
    if not xray["releaseBaseUrl"].endswith(f"/v{xray['version']}"):
        raise ValueError("Xray version and release URL disagree")
    for field in ("archiveSha256", "binarySha256"):
        if not HEX_256.fullmatch(asset[field]):
            raise ValueError(f"invalid Xray {field}")

    release_key = None
    if args.scope in {"all", "manifest"}:
        release_key = group_state(
            "release manifest",
            ("RELEASE_SIGNING_KEY_ID", "RELEASE_SIGNING_PRIVATE_KEY"),
        )
    if trust.get("schemaVersion") != 1 or not trust.get("releaseKeys") or not trust.get("rollbackKeys"):
        raise ValueError("pinned release trust is incomplete")
    pinned_release_ids = {item["keyId"] for item in trust["releaseKeys"]}
    if release_key and os.environ["RELEASE_SIGNING_KEY_ID"] not in pinned_release_ids:
        raise ValueError("release signing key ID is not pinned by release-trust.json")
    artifact_signing = False
    notarization = False
    if args.scope in {"all", "artifact"} and platform == "macos":
        artifact_signing = group_state(
            "macOS application",
            ("APPLE_CERTIFICATE", "APPLE_CERTIFICATE_PASSWORD", "APPLE_SIGNING_IDENTITY"),
        )
        notarization = group_state(
            "macOS notarization",
            ("APPLE_ID", "APPLE_PASSWORD", "APPLE_TEAM_ID"),
        )
        if product == "nodeHost":
            artifact_signing = artifact_signing and group_state(
                "macOS installer", ("MACOS_INSTALLER_IDENTITY",)
            )
    elif args.scope in {"all", "artifact"}:
        artifact_signing = group_state(
            "Windows application",
            ("WINDOWS_SIGNING_PFX_BASE64", "WINDOWS_SIGNING_PFX_PASSWORD"),
        )

    if args.scope == "manifest":
        configured = bool(release_key)
    elif args.scope == "artifact":
        configured = artifact_signing and (platform != "macos" or notarization)
    else:
        configured = bool(release_key) and artifact_signing and (platform != "macos" or notarization)
    if args.mode == "release" and not configured:
        raise ValueError("release mode credentials are incomplete for the selected signing scope")
    if args.mode == "release" and args.scope in {"all", "manifest"} and not trust.get("productionReady"):
        raise ValueError("release-trust.json is not marked production-ready")

    output = {
        "schemaVersion": 1,
        "target": args.target,
        "mode": args.mode,
        "releaseManifestCredentialsConfigured": release_key,
        "artifactSigningCredentialsConfigured": artifact_signing if args.scope != "manifest" else None,
        "notarizationCredentialsConfigured": notarization if args.scope != "manifest" and platform == "macos" else None,
        "artifactStatus": "pending-signed-release" if configured else "unsigned-validation",
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(output, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(output, sort_keys=True))


if __name__ == "__main__":
    main()
