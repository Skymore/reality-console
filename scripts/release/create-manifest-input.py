#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
import time
import uuid


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--release-id")
    parser.add_argument("--issued-at", type=int)
    parser.add_argument("--release-notes-url")
    parser.add_argument("--expected-version")
    parser.add_argument("--require-signed", action="store_true")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    artifacts = []
    metadata_files = sorted(args.artifacts.glob("*.artifact.json"))
    if not metadata_files:
        raise ValueError("release artifact metadata is empty")
    for metadata_path in metadata_files:
        item = json.loads(metadata_path.read_text(encoding="utf-8"))
        status = item.pop("signatureStatus")
        if args.require_signed and status != "signed":
            raise ValueError(f"release artifact is not signed: {metadata_path.name}")
        if args.expected_version and item["version"] != args.expected_version:
            raise ValueError(f"artifact version does not match release tag: {metadata_path.name}")
        for field in ("path", "sbomPath"):
            name = item[field]
            if Path(name).name != name or not (args.artifacts / name).is_file():
                raise ValueError(f"unsafe or missing release input: {name}")
            item[field] = str((args.artifacts / name).resolve())
        artifacts.append(item)
    release_identity = args.source_commit + ":" + ":".join(path.name for path in metadata_files)
    document = {
        "releaseId": args.release_id or str(uuid.uuid5(uuid.NAMESPACE_URL, release_identity)),
        "sourceCommit": args.source_commit,
        "issuedAt": args.issued_at or int(time.time()),
        "releaseNotesUrl": args.release_notes_url,
        "artifacts": artifacts,
    }
    args.output.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
