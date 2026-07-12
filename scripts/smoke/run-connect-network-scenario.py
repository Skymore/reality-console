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
import tempfile
import time
from urllib.parse import urlsplit


SHA256 = re.compile(r"[0-9a-f]{64}")
COMMIT = re.compile(r"[0-9a-f]{40}(?:[0-9a-f]{24})?")
NODE_ID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}")
HTTP_PROXY = "http://127.0.0.1:10809"
CONNECT_TARGETS = {
    "connect-macos-aarch64",
    "connect-macos-x86_64",
    "connect-windows-x86_64",
}


class ScenarioError(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def exact(value: object, fields: set[str], context: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != fields:
        raise ScenarioError(f"{context}_invalid")
    return value


def load_config(path: Path) -> dict[str, object]:
    try:
        value = exact(
            json.loads(path.read_text(encoding="utf-8")),
            {
                "schemaVersion",
                "deviceName",
                "directNodeId",
                "relayNodeId",
                "testUrl",
                "expectedResponseSha256",
                "holdSeconds",
                "readinessTimeoutSeconds",
            },
            "scenario_config",
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ScenarioError("scenario_config_invalid") from error
    if value["schemaVersion"] != 1:
        raise ScenarioError("scenario_config_schema_unsupported")
    if not isinstance(value["deviceName"], str) or not 1 <= len(value["deviceName"].encode()) <= 128:
        raise ScenarioError("scenario_device_name_invalid")
    for field in ("directNodeId", "relayNodeId"):
        if not isinstance(value[field], str) or not NODE_ID.fullmatch(value[field]):
            raise ScenarioError("scenario_node_id_invalid")
    if value["directNodeId"] == value["relayNodeId"]:
        raise ScenarioError("scenario_nodes_not_distinct")
    if not isinstance(value["expectedResponseSha256"], str) or not SHA256.fullmatch(
        value["expectedResponseSha256"]
    ):
        raise ScenarioError("scenario_response_digest_invalid")
    if not isinstance(value["holdSeconds"], int) or not 5 <= value["holdSeconds"] <= 300:
        raise ScenarioError("scenario_hold_invalid")
    if not isinstance(value["readinessTimeoutSeconds"], int) or not 5 <= value["readinessTimeoutSeconds"] <= 60:
        raise ScenarioError("scenario_readiness_timeout_invalid")
    if not isinstance(value["testUrl"], str):
        raise ScenarioError("scenario_test_url_invalid")
    parsed = urlsplit(value["testUrl"])
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise ScenarioError("scenario_test_url_invalid")
    return value


def read_response(path: Path) -> dict[str, object]:
    try:
        return exact(
            json.loads(path.read_text(encoding="utf-8")),
            {"schemaVersion", "complete", "outcome"},
            "headless_response",
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ScenarioError("headless_response_invalid") from error


def require_success(path: Path, complete: bool) -> dict[str, object]:
    value = read_response(path)
    if value["schemaVersion"] != 1 or value["complete"] is not complete:
        raise ScenarioError("headless_response_state_invalid")
    outcome = exact(value["outcome"], {"status", "snapshot"}, "headless_outcome")
    if outcome["status"] != "success":
        raise ScenarioError("headless_operation_failed")
    if not isinstance(outcome["snapshot"], (dict, type(None))):
        raise ScenarioError("headless_snapshot_invalid")
    return outcome


def invoke(binary: Path, work: Path, name: str, operation: dict[str, object]) -> dict[str, object]:
    output = work / f"{name}.json"
    result = subprocess.run(
        [str(binary), "headless", "--output", str(output)],
        input=(json.dumps({"schemaVersion": 1, "operation": operation}) + "\n").encode(),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
        timeout=90,
    )
    if result.returncode != 0:
        try:
            value = read_response(output)
            outcome = value.get("outcome")
            if isinstance(outcome, dict) and isinstance(outcome.get("code"), str):
                raise ScenarioError(outcome["code"])
        except ScenarioError as error:
            if error.code != "headless_response_invalid":
                raise
        raise ScenarioError("headless_process_failed")
    return require_success(output, True)


def wait_ready(path: Path, process: subprocess.Popen[bytes], timeout_seconds: int) -> dict[str, object]:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if path.is_file():
            try:
                value = read_response(path)
                if value.get("complete") is False:
                    return require_success(path, False)
                if value.get("complete") is True:
                    raise ScenarioError("connect_completed_before_probe")
            except ScenarioError as error:
                if error.code != "headless_response_invalid":
                    raise
        if process.poll() is not None:
            raise ScenarioError("connect_exited_before_ready")
        time.sleep(0.1)
    raise ScenarioError("connect_readiness_timeout")


def connect_path(
    binary: Path,
    work: Path,
    name: str,
    node_id: str,
    config: dict[str, object],
    expect_available: bool = True,
) -> str:
    output = work / f"connect-{name}.json"
    request = {
        "schemaVersion": 1,
        "operation": {
            "method": "connect",
            "selection": {"kind": "manual", "nodes": node_id},
            "proxyMode": "manual",
            "refreshFirst": False,
            "holdSeconds": config["holdSeconds"],
        },
    }
    process = subprocess.Popen(
        [str(binary), "headless", "--output", str(output)],
        stdin=subprocess.PIPE,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        assert process.stdin is not None
        process.stdin.write((json.dumps(request) + "\n").encode())
        process.stdin.close()
        ready = wait_ready(output, process, int(config["readinessTimeoutSeconds"]))
        snapshot = ready["snapshot"]
        if snapshot.get("selectedNodeId") != node_id or snapshot.get("runtime", {}).get("phase") != "connected":
            raise ScenarioError("connect_selected_node_mismatch")
        response = subprocess.run(
            [
                "curl",
                "--fail",
                "--silent",
                "--show-error",
                "--max-time",
                "20",
                "--proxy",
                HTTP_PROXY,
                str(config["testUrl"]),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=30,
        )
        digest = hashlib.sha256(response.stdout).hexdigest()
        response_matches = response.returncode == 0 and digest == config["expectedResponseSha256"]
        if expect_available and not response_matches:
            raise ScenarioError(f"{name}_path_response_invalid")
        if not expect_available and response_matches:
            raise ScenarioError(f"{name}_path_unexpectedly_available")
        try:
            return_code = process.wait(timeout=int(config["holdSeconds"]) + 20)
        except subprocess.TimeoutExpired as error:
            raise ScenarioError("connect_cleanup_timeout") from error
        if return_code != 0:
            raise ScenarioError("connect_cleanup_failed")
        complete = require_success(output, True)["snapshot"]
        if complete.get("runtime", {}).get("phase") != "disconnected":
            raise ScenarioError("connect_runtime_not_stopped")
        return digest
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


def assert_bundle(snapshot: dict[str, object], config: dict[str, object]) -> None:
    bundle = snapshot.get("bundle")
    if not isinstance(bundle, dict) or not isinstance(bundle.get("nodes"), list):
        raise ScenarioError("bundle_missing")
    modes = {
        item.get("nodeId"): item.get("endpointMode")
        for item in bundle["nodes"]
        if isinstance(item, dict)
    }
    if modes.get(config["directNodeId"]) != "direct" or modes.get(config["relayNodeId"]) != "relay":
        raise ScenarioError("bundle_topology_invalid")


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def write_proof(
    path: Path,
    mode: str,
    target: str,
    artifact: Path,
    binary: Path,
    source_commit: str,
    ci: dict[str, object],
    checks: dict[str, object],
    error: str | None,
) -> None:
    value = {
        "schemaVersion": 1,
        "kind": "connect-network-scenario",
        "mode": mode,
        "target": target,
        "sourceCommit": source_commit,
        "artifact": {"name": artifact.name, "sha256": file_sha256(artifact)},
        "binarySha256": file_sha256(binary),
        "ci": ci,
        "status": "passed" if error is None else "failed",
        "checks": checks,
        "errorCode": error,
    }
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor = os.open(path, flags, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as output:
        json.dump(value, output, indent=2, sort_keys=True)
        output.write("\n")
        output.flush()
        os.fsync(output.fileno())


def run(args: argparse.Namespace) -> None:
    binary = args.binary.resolve()
    artifact = args.artifact.resolve()
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise ScenarioError("scenario_binary_invalid")
    if not artifact.is_file() or artifact.stat().st_size < 512:
        raise ScenarioError("scenario_artifact_invalid")
    if args.target not in CONNECT_TARGETS:
        raise ScenarioError("scenario_target_invalid")
    if not COMMIT.fullmatch(args.source_commit):
        raise ScenarioError("scenario_source_commit_invalid")
    ci = {
        "repository": args.repository,
        "workflow": args.workflow,
        "runId": args.run_id,
        "runAttempt": args.run_attempt,
        "job": args.job,
    }
    if (
        not all(isinstance(ci[field], str) and ci[field] for field in ("repository", "workflow", "runId", "job"))
        or not isinstance(ci["runAttempt"], int)
        or ci["runAttempt"] < 1
        or ci["job"] != f"connect-network-scenario ({args.target})"
    ):
        raise ScenarioError("scenario_ci_identity_invalid")
    config = load_config(args.config)
    checks: dict[str, object] = {}
    error: str | None = None
    try:
        with tempfile.TemporaryDirectory(prefix="connect-network-scenario-") as temporary:
            work = Path(temporary)
            if args.mode == "online":
                setup_code = sys.stdin.buffer.read(8_193)
                if not setup_code or len(setup_code) > 8_192:
                    raise ScenarioError("scenario_setup_code_invalid")
                try:
                    setup_text = setup_code.decode()
                except UnicodeDecodeError as failure:
                    raise ScenarioError("scenario_setup_code_invalid") from failure
                setup = invoke(
                    binary,
                    work,
                    "setup",
                    {
                        "method": "setup",
                        "setupCode": setup_text.rstrip("\r\n"),
                        "deviceName": config["deviceName"],
                    },
                )["snapshot"]
                setup_text = ""
                setup_code = b""
                assert_bundle(setup, config)
                checks["activationEnrollment"] = True
            elif args.mode == "offline":
                if sys.stdin.buffer.read(1):
                    raise ScenarioError("scenario_offline_stdin_not_empty")
                status = invoke(binary, work, "status", {"method": "status"})["snapshot"]
                if not isinstance(status, dict):
                    raise ScenarioError("offline_state_missing")
                assert_bundle(status, config)
                failed_refresh = work / "offline-refresh.json"
                refresh = subprocess.run(
                    [str(binary), "headless", "--output", str(failed_refresh)],
                    input=b'{"schemaVersion":1,"operation":{"method":"refresh"}}\n',
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    check=False,
                    timeout=45,
                )
                if refresh.returncode == 0:
                    raise ScenarioError("offline_refresh_unexpectedly_succeeded")
                response = read_response(failed_refresh)
                outcome = response.get("outcome")
                if not isinstance(outcome, dict) or outcome.get("code") != "control_api_unavailable":
                    raise ScenarioError("offline_refresh_error_invalid")
                checks["offlineRefreshFailedClosed"] = True
            elif args.mode == "logout":
                if sys.stdin.buffer.read(1):
                    raise ScenarioError("scenario_logout_stdin_not_empty")
                logout = invoke(binary, work, "logout", {"method": "logout"})["snapshot"]
                if (
                    logout.get("session", {}).get("phase") != "signedOut"
                    or logout.get("bundle") is not None
                    or logout.get("runtime", {}).get("phase") != "disconnected"
                ):
                    raise ScenarioError("logout_cleanup_invalid")
                status = invoke(binary, work, "post-logout-status", {"method": "status"})["snapshot"]
                if status is not None:
                    raise ScenarioError("logout_installed_record_retained")
                checks["logoutRemovalCleanup"] = True
                return
            else:
                if sys.stdin.buffer.read(1):
                    raise ScenarioError("scenario_isolation_stdin_not_empty")
                status = invoke(binary, work, "status", {"method": "status"})["snapshot"]
                if not isinstance(status, dict):
                    raise ScenarioError("isolation_state_missing")
                assert_bundle(status, config)
            if args.mode == "direct-failed":
                connect_path(
                    binary,
                    work,
                    "direct",
                    str(config["directNodeId"]),
                    config,
                    expect_available=False,
                )
                checks["directPathUnavailable"] = True
                checks["relayResponseSha256"] = connect_path(
                    binary, work, "relay", str(config["relayNodeId"]), config
                )
            elif args.mode == "relay-failed":
                connect_path(
                    binary,
                    work,
                    "relay",
                    str(config["relayNodeId"]),
                    config,
                    expect_available=False,
                )
                checks["relayPathUnavailable"] = True
                checks["directResponseSha256"] = connect_path(
                    binary, work, "direct", str(config["directNodeId"]), config
                )
            else:
                checks["directResponseSha256"] = connect_path(
                    binary, work, "direct", str(config["directNodeId"]), config
                )
                checks["relayResponseSha256"] = connect_path(
                    binary, work, "relay", str(config["relayNodeId"]), config
                )
            if args.mode == "offline":
                checks["offlineRestart"] = True
    except ScenarioError as failure:
        error = failure.code
        raise
    except Exception as failure:
        error = "scenario_internal_failure"
        raise ScenarioError(error) from failure
    finally:
        write_proof(
            args.output,
            args.mode,
            args.target,
            artifact,
            binary,
            args.source_commit,
            ci,
            checks,
            error,
        )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "mode",
        choices=("online", "offline", "direct-failed", "relay-failed", "logout"),
    )
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--workflow", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--run-attempt", type=int, required=True)
    parser.add_argument("--job", required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not args.output.is_absolute():
        print("scenario output path must be absolute", file=sys.stderr)
        return 64
    try:
        run(args)
    except ScenarioError as error:
        print(f"Connect network scenario failed: {error.code}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
