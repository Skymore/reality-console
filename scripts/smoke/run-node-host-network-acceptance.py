#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
from typing import Any


COMMIT = re.compile(r"[0-9a-f]{40}(?:[0-9a-f]{24})?")
NODE_ID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}")
TARGETS = {"node-host-macos-aarch64", "node-host-macos-x86_64"}
HOOK_NAMES = {
    "ready",
    "stopControl",
    "startControl",
    "restartService",
    "disableDirect",
    "enableDirect",
    "assertDirectUnavailable",
    "assertRelayAvailable",
    "disableRelay",
    "enableRelay",
    "assertRelayUnavailable",
    "assertDirectAvailable",
    "cleanup",
}
STATUS_FIELDS = {
    "phase",
    "packageVerified",
    "nodeId",
    "appliedRevision",
    "lastSyncAt",
    "providerPolicy",
    "serviceInstanceId",
    "runtimeState",
    "setupPhase",
    "directVerification",
    "relayVerification",
    "relayConnection",
}


class ScenarioError(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def exact(value: Any, fields: set[str], context: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise ScenarioError(f"{context}_invalid")
    return value


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def load_hooks(path: Path) -> tuple[int, dict[str, list[str]]]:
    try:
        value = exact(
            json.loads(path.read_text(encoding="utf-8")),
            {"schemaVersion", "hookTimeoutSeconds", "hooks"},
            "node_hooks",
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ScenarioError("node_hooks_invalid") from error
    if value["schemaVersion"] != 1:
        raise ScenarioError("node_hooks_schema_unsupported")
    timeout = value["hookTimeoutSeconds"]
    if not isinstance(timeout, int) or not 5 <= timeout <= 300:
        raise ScenarioError("node_hook_timeout_invalid")
    hooks = exact(value["hooks"], HOOK_NAMES, "node_hooks_commands")
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
            raise ScenarioError(f"node_hook_invalid_{name}")
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
        raise ScenarioError(f"node_hook_failed_{name}") from error
    if result.returncode != 0:
        raise ScenarioError(f"node_hook_failed_{name}")


def parse_response(stdout: bytes, expected_kind: str) -> dict[str, Any]:
    try:
        response = exact(
            json.loads(stdout),
            {"schemaVersion", "requestId", "outcome"},
            "node_response",
        )
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ScenarioError("node_response_invalid") from error
    if response["schemaVersion"] != 1:
        raise ScenarioError("node_response_schema_unsupported")
    outcome = exact(response["outcome"], {"status", "result"}, "node_outcome")
    if outcome["status"] != "success":
        raise ScenarioError("node_operation_failed")
    result = outcome["result"]
    if not isinstance(result, dict) or result.get("kind") != expected_kind:
        raise ScenarioError("node_result_invalid")
    return result


def invoke(
    binary: Path,
    arguments: list[str],
    expected_kind: str,
    stdin: bytes | bytearray = b"",
) -> dict[str, Any]:
    try:
        result = subprocess.run(
            [str(binary), "system-control", *arguments],
            input=stdin,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=120,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ScenarioError("node_process_failed") from error
    if result.returncode != 0:
        raise ScenarioError("node_process_failed")
    return parse_response(result.stdout, expected_kind)


def parse_status(result: dict[str, Any]) -> dict[str, Any]:
    status = exact(result.get("status"), STATUS_FIELDS, "node_status")
    node_id = status["nodeId"]
    instance_id = status["serviceInstanceId"]
    if node_id is not None and (not isinstance(node_id, str) or not NODE_ID.fullmatch(node_id)):
        raise ScenarioError("node_status_identity_invalid")
    if instance_id is not None and (
        not isinstance(instance_id, str) or not NODE_ID.fullmatch(instance_id)
    ):
        raise ScenarioError("node_status_instance_invalid")
    return status


def query_status(binary: Path) -> dict[str, Any]:
    return parse_status(invoke(binary, ["status"], "status"))


def ready_status(status: dict[str, Any]) -> bool:
    return (
        status["phase"] == "ready"
        and status["packageVerified"] is True
        and isinstance(status["nodeId"], str)
        and NODE_ID.fullmatch(status["nodeId"]) is not None
        and isinstance(status["serviceInstanceId"], str)
        and NODE_ID.fullmatch(status["serviceInstanceId"]) is not None
        and isinstance(status["appliedRevision"], int)
        and status["appliedRevision"] > 0
        and status["runtimeState"] == "serving"
        and status["setupPhase"] == "ready"
        and status["directVerification"] == "verified"
        and status["relayVerification"] == "verified"
        and status["relayConnection"] == "registered"
    )


def wait_ready(binary: Path, timeout_seconds: int) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        try:
            status = query_status(binary)
            if ready_status(status):
                return status
        except ScenarioError:
            pass
        time.sleep(1)
    raise ScenarioError("node_readiness_timeout")


def write_proof(
    path: Path,
    mode: str,
    args: argparse.Namespace,
    hooks_sha256: str,
    checks: dict[str, bool],
    error: str | None,
) -> None:
    value = {
        "schemaVersion": 1,
        "kind": "node-host-network-scenario",
        "mode": mode,
        "target": args.target,
        "sourceCommit": args.source_commit,
        "artifact": {"name": args.artifact.name, "sha256": file_sha256(args.artifact)},
        "binarySha256": file_sha256(args.binary),
        "hooksSha256": hooks_sha256,
        "ci": {
            "repository": args.repository,
            "workflow": args.workflow,
            "runId": args.run_id,
            "runAttempt": args.run_attempt,
            "job": f"node-host-network-scenario ({args.target})",
        },
        "status": "passed" if error is None else "failed",
        "checks": checks,
        "errorCode": error,
    }
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as output:
        json.dump(value, output, indent=2, sort_keys=True)
        output.write("\n")
        output.flush()
        os.fsync(output.fileno())


def record(
    args: argparse.Namespace,
    hooks_sha256: str,
    mode: str,
    operation: Any,
) -> Any:
    checks: dict[str, bool] = {}
    error: str | None = None
    try:
        result, checks = operation()
        return result
    except ScenarioError as failure:
        error = failure.code
        raise
    finally:
        write_proof(
            args.proof_dir / f"{args.target}.{mode}.node.json",
            mode,
            args,
            hooks_sha256,
            checks,
            error,
        )


def erase(value: bytearray) -> None:
    value[:] = b"\0" * len(value)
    value.clear()


def run(args: argparse.Namespace) -> None:
    if args.target not in TARGETS or not COMMIT.fullmatch(args.source_commit):
        raise ScenarioError("node_candidate_identity_invalid")
    if not args.binary.is_file() or not os.access(args.binary, os.X_OK):
        raise ScenarioError("node_binary_invalid")
    if not args.artifact.is_file() or args.artifact.stat().st_size < 512:
        raise ScenarioError("node_artifact_invalid")
    if not args.policy.is_file() or args.policy.stat().st_size > 64 * 1024:
        raise ScenarioError("node_policy_invalid")
    if not args.proof_dir.is_absolute() or args.proof_dir.exists():
        raise ScenarioError("node_proof_directory_invalid")
    if not 30 <= args.readiness_timeout_seconds <= 900:
        raise ScenarioError("node_readiness_timeout_invalid")
    timeout, hooks = load_hooks(args.hooks)
    hooks_sha256 = file_sha256(args.hooks)
    args.proof_dir.mkdir(mode=0o700)
    invitation = bytearray(sys.stdin.buffer.read(32 * 1024 + 1))
    if not invitation or len(invitation) > 32 * 1024:
        erase(invitation)
        raise ScenarioError("node_invitation_invalid")
    failure: BaseException | None = None
    node_id: str | None = None
    try:
        run_hook("ready", hooks, timeout)

        def online() -> tuple[dict[str, Any], dict[str, bool]]:
            invoke(
                args.binary,
                [
                    "confirm-setup",
                    "--provider-policy-file",
                    str(args.policy),
                    "--accept-host-owner",
                    "--accept-exit-ip",
                    "--accept-router-mapping",
                    "--accept-relay",
                ],
                "setupComplete",
                invitation,
            )
            status = wait_ready(args.binary, args.readiness_timeout_seconds)
            return status, {
                "activationEnrollment": True,
                "directProtocolVerified": True,
                "relayProtocolVerified": True,
            }

        online_status = record(args, hooks_sha256, "online", online)
        erase(invitation)
        node_id = online_status["nodeId"]

        def offline_restart() -> tuple[dict[str, Any], dict[str, bool]]:
            before = query_status(args.binary)
            run_hook("stopControl", hooks, timeout)
            try:
                run_hook("restartService", hooks, timeout)
                after = wait_ready(args.binary, args.readiness_timeout_seconds)
            finally:
                run_hook("startControl", hooks, timeout)
            if (
                before["serviceInstanceId"] == after["serviceInstanceId"]
                or before["nodeId"] != after["nodeId"]
                or before["appliedRevision"] != after["appliedRevision"]
            ):
                raise ScenarioError("node_restart_state_invalid")
            return after, {
                "controlUnavailableDuringRestart": True,
                "serviceInstanceChanged": True,
                "lastKnownGoodPreserved": True,
            }

        record(args, hooks_sha256, "offline-restart", offline_restart)
        run_hook("ready", hooks, timeout)

        def isolation() -> tuple[None, dict[str, bool]]:
            run_hook("disableDirect", hooks, timeout)
            try:
                run_hook("assertDirectUnavailable", hooks, timeout)
                run_hook("assertRelayAvailable", hooks, timeout)
            finally:
                run_hook("enableDirect", hooks, timeout)
            run_hook("ready", hooks, timeout)
            run_hook("disableRelay", hooks, timeout)
            try:
                run_hook("assertRelayUnavailable", hooks, timeout)
                run_hook("assertDirectAvailable", hooks, timeout)
            finally:
                run_hook("enableRelay", hooks, timeout)
            return None, {"directFailureIsolated": True, "relayFailureIsolated": True}

        record(args, hooks_sha256, "isolation", isolation)
        run_hook("ready", hooks, timeout)

        def logout() -> tuple[dict[str, Any], dict[str, bool]]:
            result = invoke(
                args.binary,
                ["unpair", "--confirm-node-id", str(node_id)],
                "unpaired",
            )
            status = parse_status(result)
            if (
                status["phase"] != "unpaired"
                or status["nodeId"] is not None
                or status["serviceInstanceId"] is not None
            ):
                raise ScenarioError("node_unpair_cleanup_invalid")
            return status, {"logoutRemovalCleanup": True}

        record(args, hooks_sha256, "logout", logout)
    except BaseException as error:
        failure = error
    finally:
        erase(invitation)
        try:
            run_hook("cleanup", hooks, timeout)
        except ScenarioError as cleanup_error:
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
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--hooks", type=Path, required=True)
    parser.add_argument("--proof-dir", type=Path, required=True)
    parser.add_argument("--readiness-timeout-seconds", type=int, default=300)
    args = parser.parse_args()
    try:
        run(args)
    except ScenarioError as error:
        print(f"Node Host network acceptance failed: {error.code}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
