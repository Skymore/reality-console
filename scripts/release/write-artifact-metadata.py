#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--product", choices=("connect", "nodeHost"), required=True)
    parser.add_argument("--platform", choices=("macos", "windows", "linux"), required=True)
    parser.add_argument("--architecture", choices=("aarch64", "x86_64"), required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--sbom", type=Path, required=True)
    parser.add_argument("--xray-version", required=True)
    parser.add_argument("--signature-status", choices=("signed", "unsigned-validation"), required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    for path in (args.artifact, args.sbom):
        if not path.is_file():
            raise ValueError(f"release input is not a file: {path}")
    metadata = {
        "product": args.product,
        "platform": args.platform,
        "architecture": args.architecture,
        "version": args.version,
        "path": args.artifact.name,
        "sbomPath": args.sbom.name,
        "minimumConfigurationSchema": 1,
        "maximumConfigurationSchema": 1,
        "xrayVersion": args.xray_version,
        "signatureStatus": args.signature_status,
    }
    args.output.write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
