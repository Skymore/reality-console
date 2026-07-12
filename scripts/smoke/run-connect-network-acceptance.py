#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
from typing import Any


HOOK_NAMES = {
    "ready",
    "stopControl",
    "startControl",
    "disableDirect",
    "enableDirect",
    "disableRelay",
    "enableRelay",
    "cleanup",
}
MODES = ("online", "offline", "direct-failed", "relay-failed", "logout")


class CoordinatorError(Exception):
    pass


def exact(value: Any, fields: set[str], context: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise CoordinatorError(f"{context}_invalid")
    return value


def load_hooks(path: Path) -> tuple[int, dict[str, list[str]]]:
    try:
        value = exact(
            json.loads(path.read_text(encoding="utf-8")),
            {"schemaVersion", "hookTimeoutSeconds", "hooks"},
            "coordinator_config",
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise CoordinatorError("coordinator_config_invalid") from error
    if value["schemaVersion"] != 1:
        raise CoordinatorError("coordinator_schema_unsupported")
    timeout = value["hookTimeoutSeconds"]
    if not isinstance(timeout, int) or not 5 <= timeout <= 300:
        raise CoordinatorError("coordinator_hook_timeout_invalid")
    hooks = exact(value["hooks"], HOOK_NAMES, "coordinator_hooks")
    for name, command in hooks.items():
        if (
            not isinstance(command, list)
            or not 1 <= len(command) <= 16
            or not all(
                isinstance(argument, str)
                and 1 <= len(argument.encode()) <= 1_024
                and "\0" not in argument
                for argument in command
            )
        ):
            raise CoordinatorError(f"coordinator_hook_invalid_{name}")
    return timeout, hooks


def run_hook(name: str, hooks: dict[str, list[str]], timeout: int) -> None:
    try:
        result = subprocess.run(
            hooks[name],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise CoordinatorError(f"coordinator_hook_failed_{name}") from error
    if result.returncode != 0:
        raise CoordinatorError(f"coordinator_hook_failed_{name}")


def scenario_command(args: argparse.Namespace, mode: str, output: Path) -> list[str]:
    driver = Path(__file__).with_name("run-connect-network-scenario.py")
    return [
        sys.executable,
        str(driver),
        mode,
        "--binary",
        str(args.binary),
        "--artifact",
        str(args.artifact),
        "--target",
        args.target,
        "--source-commit",
        args.source_commit,
        "--repository",
        args.repository,
        "--workflow",
        args.workflow,
        "--run-id",
        args.run_id,
        "--run-attempt",
        str(args.run_attempt),
        "--job",
        f"connect-network-scenario ({args.target})",
        "--config",
        str(args.scenario_config),
        "--output",
        str(output),
    ]


def run_scenario(args: argparse.Namespace, mode: str, setup_code: bytes | bytearray = b"") -> None:
    output = args.proof_dir / f"{args.target}.{mode}.network.json"
    try:
        result = subprocess.run(
            scenario_command(args, mode, output),
            input=setup_code,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=900,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise CoordinatorError(f"coordinator_scenario_failed_{mode}") from error
    if result.returncode != 0:
        raise CoordinatorError(f"coordinator_scenario_failed_{mode}")


def read_setup_code() -> bytearray:
    value = bytearray(sys.stdin.buffer.read(8_193))
    if not value or len(value) > 8_192:
        raise CoordinatorError("coordinator_setup_code_invalid")
    return value


def erase(value: bytearray) -> None:
    value[:] = b"\0" * len(value)
    value.clear()


def run(args: argparse.Namespace) -> None:
    if not args.proof_dir.is_absolute() or args.proof_dir.exists():
        raise CoordinatorError("coordinator_proof_directory_invalid")
    timeout, hooks = load_hooks(args.hooks)
    args.proof_dir.mkdir(mode=0o700)
    setup_code = read_setup_code()
    failure: BaseException | None = None
    try:
        run_hook("ready", hooks, timeout)
        run_scenario(args, "online", setup_code)
        erase(setup_code)

        run_hook("stopControl", hooks, timeout)
        try:
            run_scenario(args, "offline")
        finally:
            run_hook("startControl", hooks, timeout)
        run_hook("ready", hooks, timeout)

        run_hook("disableDirect", hooks, timeout)
        try:
            run_scenario(args, "direct-failed")
        finally:
            run_hook("enableDirect", hooks, timeout)
        run_hook("ready", hooks, timeout)

        run_hook("disableRelay", hooks, timeout)
        try:
            run_scenario(args, "relay-failed")
        finally:
            run_hook("enableRelay", hooks, timeout)
        run_hook("ready", hooks, timeout)
        run_scenario(args, "logout")
    except BaseException as error:
        failure = error
    finally:
        erase(setup_code)
        try:
            run_hook("cleanup", hooks, timeout)
        except CoordinatorError as cleanup_error:
            if failure is None:
                failure = cleanup_error
    if failure is not None:
        raise failure


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--workflow", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--run-attempt", type=int, required=True)
    parser.add_argument("--scenario-config", type=Path, required=True)
    parser.add_argument("--hooks", type=Path, required=True)
    parser.add_argument("--proof-dir", type=Path, required=True)
    args = parser.parse_args()
    try:
        run(args)
    except CoordinatorError as error:
        print(f"Connect network acceptance failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
