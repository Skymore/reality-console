#!/usr/bin/env python3
"""Print Cargo's effective target directory for one manifest."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[2]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("manifest", type=Path)
    args = parser.parse_args()
    manifest = args.manifest.expanduser().resolve()
    if not manifest.is_file() or manifest.name != "Cargo.toml":
        parser.error(f"Cargo manifest does not exist: {manifest}")

    result = subprocess.run(
        [
            "cargo",
            "metadata",
            "--format-version",
            "1",
            "--no-deps",
            "--manifest-path",
            str(manifest),
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    metadata = json.loads(result.stdout)
    target_directory = Path(metadata["target_directory"])
    if not target_directory.is_absolute():
        raise ValueError("Cargo returned a non-absolute target directory")
    print(target_directory)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
