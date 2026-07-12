#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("artifacts", type=Path, nargs="+")
    args = parser.parse_args()
    records = []
    for artifact in args.artifacts:
        if not artifact.is_file():
            raise ValueError(f"artifact is not a regular file: {artifact}")
        records.append((artifact.name, hashlib.sha256(artifact.read_bytes()).hexdigest()))
    if len({name for name, _ in records}) != len(records):
        raise ValueError("artifact basenames must be unique")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        "".join(f"{digest}  {name}\n" for name, digest in sorted(records)),
        encoding="ascii",
    )


if __name__ == "__main__":
    main()
