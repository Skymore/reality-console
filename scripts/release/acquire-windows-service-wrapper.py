#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import tempfile
import urllib.request


ROOT = Path(__file__).resolve().parents[2]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    config = json.loads((ROOT / "packaging/release-config.json").read_text(encoding="utf-8"))
    wrapper = config["windowsServiceWrapper"]
    request = urllib.request.Request(wrapper["url"], headers={"User-Agent": "private-network-release/1"})
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=args.output.parent, delete=False) as temporary:
        temporary_path = Path(temporary.name)
        try:
            with urllib.request.urlopen(request, timeout=120) as response:
                while chunk := response.read(1024 * 1024):
                    temporary.write(chunk)
            temporary.flush()
            digest = hashlib.sha256(temporary_path.read_bytes()).hexdigest()
            if digest != wrapper["sha256"]:
                raise ValueError("WinSW SHA-256 mismatch")
            os.replace(temporary_path, args.output)
        finally:
            temporary_path.unlink(missing_ok=True)
    print(json.dumps({"component": "winsw", "version": wrapper["version"], "sha256": wrapper["sha256"]}, sort_keys=True))


if __name__ == "__main__":
    main()
