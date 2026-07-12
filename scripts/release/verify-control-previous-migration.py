#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import re
import sqlite3
import struct
import subprocess
import tempfile
import time


SCHEMA_VERSION = re.compile(r"pub const SCHEMA_VERSION: i64 = (\d+);")
SQL_CONSTANT = re.compile(r'const MIGRATION_(\d+)_SQL: &str = r"(.*?)";', re.DOTALL)
MIGRATION = re.compile(
    r'Migration \{\s*version: (\d+),\s*name: "([^"]+)",\s*sql: MIGRATION_(\d+)_SQL,\s*\}',
    re.DOTALL,
)


def checksum(version: int, name: str, sql: str) -> str:
    digest = hashlib.sha256()
    digest.update(struct.pack(">q", version))
    digest.update(name.encode())
    digest.update(sql.encode())
    return digest.hexdigest()


def migrations(source: str) -> tuple[int, list[tuple[int, str, str]]]:
    version_match = SCHEMA_VERSION.search(source)
    if not version_match:
        raise ValueError("Control schema version constant was not found")
    current = int(version_match.group(1))
    sql = {int(number): value for number, value in SQL_CONSTANT.findall(source)}
    records = []
    for version_text, name, sql_number_text in MIGRATION.findall(source):
        version = int(version_text)
        sql_number = int(sql_number_text)
        if version != sql_number or version not in sql:
            raise ValueError(f"migration declaration is inconsistent at version {version}")
        records.append((version, name, sql[version]))
    if [record[0] for record in records] != list(range(1, current + 1)):
        raise ValueError("Control migrations are not a contiguous authoritative sequence")
    return current, records


def create_previous_database(path: Path, records: list[tuple[int, str, str]]) -> None:
    connection = sqlite3.connect(path)
    try:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute(
            "CREATE TABLE schema_migrations ("
            "version INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE, "
            "checksum TEXT NOT NULL, applied_at INTEGER NOT NULL) STRICT"
        )
        for version, name, sql in records:
            connection.executescript(sql)
            connection.execute(
                "INSERT INTO schema_migrations(version, name, checksum, applied_at) VALUES (?, ?, ?, ?)",
                (version, name, checksum(version, name, sql), 1_700_000_000 + version),
            )
            connection.execute(f"PRAGMA user_version = {version}")
        connection.commit()
    finally:
        connection.close()


def run_migration(binary: Path, database: Path, current: int) -> None:
    environment = os.environ.copy()
    environment.update({
        "CONTROL_DATABASE_PATH": str(database),
        "CONTROL_BIND_ADDRESS": "127.0.0.1:0",
        "CONTROL_BOOTSTRAP_TOKEN": "previous-migration-gate-token-with-more-than-32-bytes",
        "CONTROL_PUBLIC_ORIGIN": "http://127.0.0.1",
        "CONTROL_PROBE_MODE": "disabled",
    })
    process = subprocess.Popen(
        [str(binary), "serve"],
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    try:
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if process.poll() is not None:
                output = process.stdout.read() if process.stdout else ""
                raise RuntimeError(f"Control exited during previous-schema migration:\n{output}")
            try:
                connection = sqlite3.connect(database)
                version = connection.execute("PRAGMA user_version").fetchone()[0]
                connection.close()
                if version == current:
                    return
            except sqlite3.Error:
                pass
            time.sleep(0.1)
        raise TimeoutError("Control did not migrate the previous schema before the deadline")
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def verify_database(path: Path, current: int) -> None:
    connection = sqlite3.connect(path)
    try:
        version = connection.execute("PRAGMA user_version").fetchone()[0]
        highest, count = connection.execute("SELECT MAX(version), COUNT(*) FROM schema_migrations").fetchone()
        quick = connection.execute("PRAGMA quick_check").fetchone()[0]
        foreign_keys = connection.execute("PRAGMA foreign_key_check").fetchall()
    finally:
        connection.close()
    if (version, highest, count, quick, foreign_keys) != (current, current, current, "ok", []):
        raise ValueError("migrated database failed schema mirror, integrity, or foreign-key verification")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, default=Path("control-server/src/db.rs"))
    parser.add_argument("--binary", type=Path, default=Path("control-server/target/debug/control-server"))
    args = parser.parse_args()
    if not args.binary.is_file():
        raise ValueError(f"built Control binary is missing: {args.binary}")
    current, records = migrations(args.source.read_text(encoding="utf-8"))
    if current < 2:
        raise ValueError("previous-schema migration gate requires at least two schema versions")
    with tempfile.TemporaryDirectory(prefix="control-previous-migration-") as temporary:
        database = Path(temporary) / "control.sqlite3"
        create_previous_database(database, records[:-1])
        run_migration(args.binary.resolve(), database, current)
        verify_database(database, current)
    print(f"control previous-schema migration: {current - 1} -> {current} passed")


if __name__ == "__main__":
    main()
