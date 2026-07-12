#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
from typing import Any


COMMIT = re.compile(r"[0-9a-f]{40}(?:[0-9a-f]{24})?")
SCENARIOS = {
    "clean-install-signature",
    "activation-enrollment",
    "direct-path",
    "relay-path-isolation",
    "offline-restart",
    "sleep-wake-service-restart",
    "state-preserving-upgrade",
    "failed-upgrade-rollback",
    "logout-removal-cleanup",
    "uninstall-retention-choice",
}
LOCAL_RESULTS = {"clean-install-signature", "uninstall-retention-choice"}
CONNECT_TARGETS = {
    "connect-macos-aarch64",
    "connect-macos-x86_64",
    "connect-windows-x86_64",
}
NODE_HOST_TARGETS = {"node-host-macos-aarch64", "node-host-macos-x86_64"}
SHA256 = re.compile(r"[0-9a-f]{64}")
NETWORK_CHECKS = {
    "online": {"activationEnrollment", "directResponseSha256", "relayResponseSha256"},
    "offline": {
        "offlineRefreshFailedClosed",
        "directResponseSha256",
        "relayResponseSha256",
        "offlineRestart",
    },
    "logout": {"logoutRemovalCleanup"},
    "direct-failed": {"directPathUnavailable", "relayResponseSha256"},
    "relay-failed": {"relayPathUnavailable", "directResponseSha256"},
}
NETWORK_RESULTS = {
    "online": {"activation-enrollment", "direct-path"},
    "offline": {"offline-restart"},
    "logout": {"logout-removal-cleanup"},
    "direct-failed": set(),
    "relay-failed": set(),
}
NODE_HOST_CHECKS = {
    "online": {"activationEnrollment", "directProtocolVerified", "relayProtocolVerified"},
    "offline-restart": {
        "controlUnavailableDuringRestart",
        "serviceInstanceChanged",
        "lastKnownGoodPreserved",
    },
    "isolation": {"directFailureIsolated", "relayFailureIsolated"},
    "logout": {"logoutRemovalCleanup"},
}
NODE_HOST_RESULTS = {
    "online": {"activation-enrollment", "direct-path"},
    "offline-restart": {"offline-restart", "sleep-wake-service-restart"},
    "isolation": {"relay-path-isolation"},
    "logout": {"logout-removal-cleanup"},
}


def artifact_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def verify_real_package(path: Path) -> None:
    if not path.is_file() or path.stat().st_size < 512:
        raise ValueError("lifecycle evidence requires a non-empty real package")
    suffix = path.suffix.lower()
    with path.open("rb") as source:
        prefix = source.read(4)
        source.seek(-512, 2)
        trailer = source.read(4)
    valid = (
        (suffix == ".exe" and prefix[:2] == b"MZ")
        or (suffix == ".pkg" and prefix == b"xar!")
        or (suffix == ".dmg" and trailer == b"koly")
    )
    if not valid:
        raise ValueError(f"artifact bytes do not match a supported release package: {path.name}")


def exact(value: Any, fields: set[str], context: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError(f"{context} fields are invalid")
    return value


def validate_ci(value: Any, expected: tuple[str, str, str, int], context: str) -> dict[str, Any]:
    ci = exact(value, {"repository", "workflow", "runId", "runAttempt", "job"}, context)
    if (
        not all(isinstance(ci[field], str) and ci[field] for field in ("repository", "workflow", "runId", "job"))
        or not isinstance(ci["runAttempt"], int)
        or ci["runAttempt"] < 1
    ):
        raise ValueError(f"{context} is invalid")
    if (ci["repository"], ci["workflow"], ci["runId"], ci["runAttempt"]) != expected:
        raise ValueError(f"{context} belongs to another CI run or attempt")
    return ci


def import_network_proof(
    path: Path,
    target: str,
    artifact: Path,
    source_commit: str,
    expected_ci: tuple[str, str, str, int],
    expected_binary_sha256: str,
) -> tuple[str, set[str], dict[str, str]]:
    try:
        value = exact(
            json.loads(path.read_text(encoding="utf-8")),
            {
                "schemaVersion",
                "kind",
                "mode",
                "target",
                "sourceCommit",
                "artifact",
                "binarySha256",
                "ci",
                "status",
                "checks",
                "errorCode",
            },
            path.name,
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(f"network proof is unreadable: {path.name}") from error
    mode = value["mode"]
    if (
        value["schemaVersion"] != 1
        or value["kind"] != "connect-network-scenario"
        or mode not in NETWORK_CHECKS
        or value["target"] != target
        or value["sourceCommit"] != source_commit
        or value["status"] != "passed"
        or value["errorCode"] is not None
    ):
        raise ValueError(f"network proof identity or outcome is invalid: {path.name}")
    if target not in CONNECT_TARGETS:
        raise ValueError("Connect network proof cannot satisfy a Node Host lifecycle")
    proof_artifact = exact(value["artifact"], {"name", "sha256"}, f"{path.name} artifact")
    if (
        proof_artifact["name"] != artifact.name
        or proof_artifact["sha256"] != artifact_sha256(artifact)
        or value["binarySha256"] != expected_binary_sha256
    ):
        raise ValueError(f"network proof belongs to another package: {path.name}")
    ci = validate_ci(value["ci"], expected_ci, f"{path.name} CI identity")
    if ci["job"] != f"connect-network-scenario ({target})":
        raise ValueError(f"{path.name} CI job identity is invalid")
    checks = exact(value["checks"], NETWORK_CHECKS[mode], f"{path.name} checks")
    for name, result in checks.items():
        if name.endswith("ResponseSha256"):
            if not isinstance(result, str) or not SHA256.fullmatch(result):
                raise ValueError(f"network proof response digest is invalid: {path.name}/{name}")
        elif result is not True:
            raise ValueError(f"network proof check did not pass: {path.name}/{name}")
    source = {
        "kind": "connect-network-scenario",
        "mode": mode,
        "name": path.name,
        "sha256": artifact_sha256(path),
    }
    return mode, NETWORK_RESULTS[mode], source


def import_node_host_proof(
    path: Path,
    target: str,
    artifact: Path,
    source_commit: str,
    expected_ci: tuple[str, str, str, int],
    expected_binary_sha256: str,
) -> tuple[str, set[str], dict[str, str]]:
    try:
        value = exact(
            json.loads(path.read_text(encoding="utf-8")),
            {
                "schemaVersion",
                "kind",
                "mode",
                "target",
                "sourceCommit",
                "artifact",
                "binarySha256",
                "hooksSha256",
                "ci",
                "status",
                "checks",
                "errorCode",
            },
            path.name,
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(f"Node Host proof is unreadable: {path.name}") from error
    mode = value["mode"]
    if (
        value["schemaVersion"] != 1
        or value["kind"] != "node-host-network-scenario"
        or mode not in NODE_HOST_CHECKS
        or value["target"] != target
        or value["sourceCommit"] != source_commit
        or value["status"] != "passed"
        or value["errorCode"] is not None
        or target not in NODE_HOST_TARGETS
        or not SHA256.fullmatch(value["hooksSha256"])
    ):
        raise ValueError(f"Node Host proof identity or outcome is invalid: {path.name}")
    proof_artifact = exact(value["artifact"], {"name", "sha256"}, f"{path.name} artifact")
    if (
        proof_artifact["name"] != artifact.name
        or proof_artifact["sha256"] != artifact_sha256(artifact)
        or value["binarySha256"] != expected_binary_sha256
    ):
        raise ValueError(f"Node Host proof belongs to another package: {path.name}")
    ci = validate_ci(value["ci"], expected_ci, f"{path.name} CI identity")
    if ci["job"] != f"node-host-network-scenario ({target})":
        raise ValueError(f"{path.name} CI job identity is invalid")
    checks = exact(value["checks"], NODE_HOST_CHECKS[mode], f"{path.name} checks")
    if any(result is not True for result in checks.values()):
        raise ValueError(f"Node Host proof check did not pass: {path.name}")
    source = {
        "kind": "node-host-network-scenario",
        "mode": mode,
        "name": path.name,
        "sha256": artifact_sha256(path),
    }
    return mode, NODE_HOST_RESULTS[mode], source


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--result", action="append", default=[])
    parser.add_argument("--network-proof", action="append", type=Path, default=[])
    parser.add_argument("--connect-binary-sha256")
    parser.add_argument("--node-host-proof", action="append", type=Path, default=[])
    parser.add_argument("--node-host-binary-sha256")
    parser.add_argument("--repository", required=True)
    parser.add_argument("--workflow", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--run-attempt", type=int, required=True)
    parser.add_argument("--job", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not COMMIT.fullmatch(args.source_commit):
        raise ValueError("source commit must be a lowercase Git object ID")
    verify_real_package(args.artifact)
    results = {scenario: "incomplete" for scenario in SCENARIOS}
    sources: list[dict[str, str]] = []
    for item in args.result:
        scenario, separator, status = item.partition("=")
        if separator != "=" or scenario not in LOCAL_RESULTS or status not in {"passed", "failed", "incomplete"}:
            raise ValueError(f"invalid lifecycle result: {item}")
        results[scenario] = status
    expected_ci = (args.repository, args.workflow, args.run_id, args.run_attempt)
    if args.network_proof and (
        not isinstance(args.connect_binary_sha256, str)
        or not SHA256.fullmatch(args.connect_binary_sha256)
    ):
        raise ValueError("Connect network proofs require the packaged main-binary SHA-256")
    if args.node_host_proof and (
        not isinstance(args.node_host_binary_sha256, str)
        or not SHA256.fullmatch(args.node_host_binary_sha256)
    ):
        raise ValueError("Node Host proofs require the packaged agent SHA-256")
    proof_modes: set[str] = set()
    for proof in args.network_proof:
        mode, imported_results, source = import_network_proof(
            proof,
            args.target,
            args.artifact,
            args.source_commit,
            expected_ci,
            args.connect_binary_sha256,
        )
        if mode in proof_modes:
            raise ValueError(f"duplicate Connect network proof mode: {mode}")
        proof_modes.add(mode)
        sources.append(source)
        for scenario in imported_results:
            results[scenario] = "passed"
    if {"direct-failed", "relay-failed"} <= proof_modes:
        results["relay-path-isolation"] = "passed"
    node_proof_modes: set[str] = set()
    for proof in args.node_host_proof:
        mode, imported_results, source = import_node_host_proof(
            proof,
            args.target,
            args.artifact,
            args.source_commit,
            expected_ci,
            args.node_host_binary_sha256,
        )
        if mode in node_proof_modes:
            raise ValueError(f"duplicate Node Host proof mode: {mode}")
        node_proof_modes.add(mode)
        sources.append(source)
        for scenario in imported_results:
            results[scenario] = "passed"
    evidence = {
        "schemaVersion": 1,
        "kind": "package-lifecycle",
        "evidenceType": "actual-package",
        "sourceCommit": args.source_commit,
        "target": args.target,
        "artifact": {"name": args.artifact.name, "sha256": artifact_sha256(args.artifact)},
        "results": results,
        "sources": sorted(sources, key=lambda item: item["name"]),
        "ci": {
            "repository": args.repository,
            "workflow": args.workflow,
            "runId": args.run_id,
            "runAttempt": args.run_attempt,
            "job": args.job,
        },
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
