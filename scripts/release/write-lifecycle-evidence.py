#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re


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


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--result", action="append", default=[])
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
    for item in args.result:
        scenario, separator, status = item.partition("=")
        if separator != "=" or scenario not in SCENARIOS or status not in {"passed", "failed", "incomplete"}:
            raise ValueError(f"invalid lifecycle result: {item}")
        results[scenario] = status
    evidence = {
        "schemaVersion": 1,
        "kind": "package-lifecycle",
        "evidenceType": "actual-package",
        "sourceCommit": args.source_commit,
        "target": args.target,
        "artifact": {"name": args.artifact.name, "sha256": artifact_sha256(args.artifact)},
        "results": results,
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
