#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re


COMMIT = re.compile(r"[0-9a-f]{40}(?:[0-9a-f]{24})?")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--name", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--checks", nargs="+", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--workflow", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--run-attempt", type=int, required=True)
    parser.add_argument("--job", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not COMMIT.fullmatch(args.source_commit):
        raise ValueError("source commit must be a lowercase Git object ID")
    if len(set(args.checks)) != len(args.checks):
        raise ValueError("component checks must be unique")
    evidence = {
        "schemaVersion": 1,
        "kind": "component-gate",
        "name": args.name,
        "version": args.version,
        "sourceCommit": args.source_commit,
        "requiredChecks": args.checks,
        "checks": {check: "passed" for check in args.checks},
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
