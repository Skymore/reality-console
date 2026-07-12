#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Any
from uuid import UUID


EXPECTED_COMPONENTS = {
    "control",
    "protocol",
    "xray-runtime",
    "node-host",
    "relay",
    "relay-provisioning",
    "connect",
    "control-app",
    "node-host-app",
    "probe-worker",
}
REQUIRED_COMPONENT_CHECKS = {
    "control": {
        "format",
        "build",
        "test",
        "clippy",
        "rustdoc",
        "migration-empty",
        "migration-previous",
        "product-bootstrap",
    },
    "protocol": {"format", "build", "test", "clippy", "rustdoc"},
    "xray-runtime": {"format", "build", "test", "clippy", "rustdoc"},
    "node-host": {"format", "build", "test", "clippy", "rustdoc", "migration-empty", "migration-previous"},
    "relay": {"format", "build", "test", "clippy", "rustdoc"},
    "relay-provisioning": {"format", "build", "test", "clippy", "rustdoc"},
    "connect": {
        "format",
        "build",
        "test",
        "clippy",
        "rustdoc",
        "headless-smoke",
        "sidecar-test",
        "typecheck",
        "production-build",
    },
    "control-app": {"format", "build", "test", "clippy", "rustdoc", "typecheck", "production-build"},
    "node-host-app": {"format", "build", "test", "clippy", "rustdoc", "package-frontend"},
    "probe-worker": {"test", "typecheck", "production-build"},
}
EXPECTED_TARGETS = {
    "connect-macos-aarch64",
    "connect-macos-x86_64",
    "connect-windows-x86_64",
    "node-host-macos-aarch64",
    "node-host-macos-x86_64",
}
EXPECTED_SCENARIOS = {
    "clean-install-signature",
    "activation-enrollment",
    "direct-path",
    "relay-path-isolation",
    "offline-restart",
    "sleep-wake-service-restart",
    "state-preserving-upgrade",
    "failed-upgrade-rollback",
    "logout-removal-cleanup",
    "uninstall-retention-choice",
}
NETWORK_PROOF_SCENARIOS = {
    "online": {"activation-enrollment", "direct-path"},
    "offline": {"offline-restart"},
    "logout": {"logout-removal-cleanup"},
    "direct-failed": set(),
    "relay-failed": set(),
}
NETWORK_PROOF_CHECKS = {
    "online": {"activationEnrollment", "directResponseSha256", "relayResponseSha256"},
    "offline": {
        "offlineRefreshFailedClosed",
        "directResponseSha256",
        "relayResponseSha256",
        "offlineRestart",
    },
    "logout": {"logoutRemovalCleanup"},
    "direct-failed": {"directPathUnavailable", "relayResponseSha256"},
    "relay-failed": {"relayPathUnavailable", "directResponseSha256"},
}
NETWORK_SCENARIO_REQUIREMENTS = {
    "activation-enrollment": {"online"},
    "direct-path": {"online"},
    "relay-path-isolation": {"direct-failed", "relay-failed"},
    "offline-restart": {"offline"},
    "logout-removal-cleanup": {"logout"},
}
NODE_HOST_PROOF_CHECKS = {
    "online": {"activationEnrollment", "directProtocolVerified", "relayProtocolVerified"},
    "offline-restart": {
        "controlUnavailableDuringRestart",
        "serviceInstanceChanged",
        "lastKnownGoodPreserved",
    },
    "isolation": {"directFailureIsolated", "relayFailureIsolated"},
    "logout": {"logoutRemovalCleanup"},
}
NODE_HOST_SCENARIO_REQUIREMENTS = {
    "activation-enrollment": {"online"},
    "direct-path": {"online"},
    "relay-path-isolation": {"isolation"},
    "offline-restart": {"offline-restart"},
    "sleep-wake-service-restart": {"offline-restart"},
    "logout-removal-cleanup": {"logout"},
}
COMMIT = re.compile(r"[0-9a-f]{40}(?:[0-9a-f]{24})?")
SHA256 = re.compile(r"[0-9a-f]{64}")
TARGET_BY_COORDINATE = {
    ("connect", "macos", "aarch64"): "connect-macos-aarch64",
    ("connect", "macos", "x86_64"): "connect-macos-x86_64",
    ("connect", "windows", "x86_64"): "connect-windows-x86_64",
    ("nodeHost", "macos", "aarch64"): "node-host-macos-aarch64",
    ("nodeHost", "macos", "x86_64"): "node-host-macos-x86_64",
}


class EvidenceError(ValueError):
    pass


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def canonical_digest(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def require_exact(value: dict[str, Any], fields: set[str], context: str) -> None:
    actual = set(value)
    if actual != fields:
        raise EvidenceError(f"{context} fields differ: missing={sorted(fields - actual)} unknown={sorted(actual - fields)}")


def ci_run(value: Any, context: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise EvidenceError(f"{context} CI identity is not an object")
    require_exact(value, {"repository", "workflow", "runId", "runAttempt", "job"}, context)
    if not all(isinstance(value[key], str) and value[key] for key in ("repository", "workflow", "runId", "job")):
        raise EvidenceError(f"{context} CI identity is incomplete")
    if not isinstance(value["runAttempt"], int) or value["runAttempt"] < 1:
        raise EvidenceError(f"{context} CI run attempt is invalid")
    return value


def require_current_ci(runs: list[dict[str, Any]], args: argparse.Namespace, context: str) -> None:
    expected = (args.repository, args.workflow, args.run_id, args.run_attempt)
    for run in runs:
        actual = (run["repository"], run["workflow"], run["runId"], run["runAttempt"])
        if actual != expected:
            raise EvidenceError(f"{context} belongs to another CI run or attempt")


def component_records(directory: Path, source_commit: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    records: dict[str, dict[str, Any]] = {}
    runs: list[dict[str, Any]] = []
    if directory.is_dir():
        paths = sorted(directory.rglob("*.component.json"))
    else:
        paths = []
    for path in paths:
        value = read_json(path)
        require_exact(
            value,
            {"schemaVersion", "kind", "name", "version", "sourceCommit", "requiredChecks", "checks", "ci"},
            path.name,
        )
        if value["schemaVersion"] != 1 or value["kind"] != "component-gate":
            raise EvidenceError(f"unsupported component evidence: {path.name}")
        name = value["name"]
        if name not in EXPECTED_COMPONENTS or name in records:
            raise EvidenceError(f"unexpected or duplicate component: {name}")
        if value["sourceCommit"] != source_commit:
            raise EvidenceError(f"component {name} belongs to a different source commit")
        required = value["requiredChecks"]
        checks = value["checks"]
        if not isinstance(required, list) or set(required) != REQUIRED_COMPONENT_CHECKS[name] or len(required) != len(set(required)):
            raise EvidenceError(f"component {name} required checks are invalid")
        if not isinstance(checks, dict) or set(checks) != set(required):
            raise EvidenceError(f"component {name} checks do not match required checks")
        if any(status not in {"passed", "failed", "incomplete"} for status in checks.values()):
            raise EvidenceError(f"component {name} has an invalid check result")
        run = ci_run(value["ci"], f"component {name}")
        runs.append(run)
        records[name] = {key: value[key] for key in ("name", "version", "sourceCommit", "requiredChecks", "checks", "ci")}
    return [records[name] for name in sorted(records)], runs


def artifact_records(directory: Path, source_commit: str) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    if not directory.is_dir():
        return records
    for metadata_path in sorted(directory.rglob("*.artifact.json")):
        metadata = read_json(metadata_path)
        required = {
            "product", "platform", "architecture", "version", "path", "sbomPath",
            "minimumConfigurationSchema", "maximumConfigurationSchema", "xrayVersion", "signatureStatus",
        }
        require_exact(metadata, required, metadata_path.name)
        coordinate = (metadata["product"], metadata["platform"], metadata["architecture"])
        target = TARGET_BY_COORDINATE.get(coordinate)
        if target is None:
            raise EvidenceError(f"artifact has an unsupported coordinate: {coordinate}")
        artifact = metadata_path.parent / metadata["path"]
        sbom = metadata_path.parent / metadata["sbomPath"]
        if Path(metadata["path"]).name != metadata["path"] or not artifact.is_file():
            raise EvidenceError(f"artifact bytes are missing for {target}")
        if Path(metadata["sbomPath"]).name != metadata["sbomPath"] or not sbom.is_file():
            raise EvidenceError(f"SBOM bytes are missing for {target}")
        records.append({
            "target": target,
            "name": artifact.name,
            "sha256": sha256_file(artifact),
            "sbomName": sbom.name,
            "sbomSha256": sha256_file(sbom),
            "metadataName": metadata_path.name,
            "metadataSha256": sha256_file(metadata_path),
            "sourceCommit": source_commit,
            "signatureStatus": metadata["signatureStatus"],
        })
    targets = [record["target"] for record in records]
    if len(targets) != len(set(targets)):
        raise EvidenceError("release artifact coordinates are duplicated")
    return sorted(records, key=lambda item: item["target"])


def signing_records(directory: Path, release_key_id: str | None) -> list[dict[str, Any]]:
    records: dict[str, dict[str, Any]] = {}
    if directory.is_dir():
        paths = sorted(directory.rglob("*.signature-verification.json"))
    else:
        paths = []
    for path in paths:
        value = read_json(path)
        require_exact(
            value,
            {"schemaVersion", "kind", "target", "artifact", "artifactSigner", "installerSigner", "status"},
            path.name,
        )
        target = value["target"]
        if value["schemaVersion"] != 1 or value["kind"] != "signature-verification":
            raise EvidenceError(f"unsupported signature evidence: {path.name}")
        if target not in EXPECTED_TARGETS or target in records:
            raise EvidenceError(f"unexpected or duplicate signing target: {target}")
        if value["status"] not in {"verified", "failed", "incomplete", "unsigned-validation"}:
            raise EvidenceError(f"invalid signing status for {target}")
        artifact = value["artifact"]
        require_exact(artifact, {"name", "sha256"}, f"{path.name} artifact")
        if Path(artifact["name"]).name != artifact["name"] or not SHA256.fullmatch(artifact["sha256"]):
            raise EvidenceError(f"invalid signature evidence artifact for {target}")
        records[target] = {
            "target": target,
            "artifactName": artifact["name"],
            "artifactSha256": artifact["sha256"],
            "artifactSigner": value["artifactSigner"],
            "installerSigner": value["installerSigner"],
            "releaseManifestKeyId": release_key_id,
            "status": value["status"],
            "evidenceArtifact": path.name,
        }
    return [records[target] for target in sorted(records)]


def matrix_records(directory: Path, source_commit: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    records: dict[tuple[str, str], dict[str, Any]] = {}
    runs: list[dict[str, Any]] = []
    if directory.is_dir():
        paths = sorted(directory.rglob("*.lifecycle.json"))
    else:
        paths = []
    for path in paths:
        value = read_json(path)
        require_exact(
            value,
            {
                "schemaVersion",
                "kind",
                "evidenceType",
                "sourceCommit",
                "target",
                "artifact",
                "results",
                "sources",
                "ci",
            },
            path.name,
        )
        if value["schemaVersion"] != 1 or value["kind"] != "package-lifecycle":
            raise EvidenceError(f"unsupported lifecycle evidence: {path.name}")
        if value["evidenceType"] != "actual-package":
            raise EvidenceError(f"simulated lifecycle output cannot be release evidence: {path.name}")
        if value["sourceCommit"] != source_commit:
            raise EvidenceError(f"lifecycle evidence belongs to a different source commit: {path.name}")
        target = value["target"]
        if target not in EXPECTED_TARGETS:
            raise EvidenceError(f"unexpected lifecycle target: {target}")
        artifact = value["artifact"]
        require_exact(artifact, {"name", "sha256"}, f"{path.name} artifact")
        if not SHA256.fullmatch(artifact["sha256"]):
            raise EvidenceError(f"invalid lifecycle artifact digest: {path.name}")
        run = ci_run(value["ci"], f"lifecycle {target}")
        runs.append(run)
        if not isinstance(value["sources"], list):
            raise EvidenceError(f"lifecycle sources are not an array: {path.name}")
        source_modes: dict[str, dict[str, Any]] = {}
        for source in value["sources"]:
            require_exact(source, {"kind", "mode", "name", "sha256"}, f"{path.name} source")
            kind = source["kind"]
            mode = source["mode"]
            if kind == "connect-network-scenario":
                expected_checks = NETWORK_PROOF_CHECKS.get(mode)
                expected_job = f"connect-network-scenario ({target})"
                expected_fields = {
                    "schemaVersion",
                    "kind",
                    "mode",
                    "target",
                    "sourceCommit",
                    "artifact",
                    "binarySha256",
                    "ci",
                    "status",
                    "checks",
                    "errorCode",
                }
                kind_matches_target = target.startswith("connect-")
            elif kind == "node-host-network-scenario":
                expected_checks = NODE_HOST_PROOF_CHECKS.get(mode)
                expected_job = f"node-host-network-scenario ({target})"
                expected_fields = {
                    "schemaVersion",
                    "kind",
                    "mode",
                    "target",
                    "sourceCommit",
                    "artifact",
                    "binarySha256",
                    "hooksSha256",
                    "ci",
                    "status",
                    "checks",
                    "errorCode",
                }
                kind_matches_target = target.startswith("node-host-")
            else:
                expected_checks = None
                expected_job = ""
                expected_fields = set()
                kind_matches_target = False
            if (
                expected_checks is None
                or not kind_matches_target
                or mode in source_modes
                or Path(source["name"]).name != source["name"]
                or not SHA256.fullmatch(source["sha256"])
            ):
                raise EvidenceError(f"lifecycle source identity is invalid: {path.name}")
            matches = list(directory.rglob(source["name"]))
            if len(matches) != 1 or sha256_file(matches[0]) != source["sha256"]:
                raise EvidenceError(f"lifecycle source bytes are missing or mismatched: {source['name']}")
            proof = read_json(matches[0])
            require_exact(proof, expected_fields, source["name"])
            proof_artifact = proof["artifact"]
            require_exact(proof_artifact, {"name", "sha256"}, f"{source['name']} artifact")
            proof_ci = ci_run(proof["ci"], f"network proof {source['name']}")
            if (
                proof["schemaVersion"] != 1
                or proof["kind"] != kind
                or proof["mode"] != mode
                or proof["target"] != target
                or proof["sourceCommit"] != source_commit
                or proof_artifact != artifact
                or not SHA256.fullmatch(proof["binarySha256"])
                or proof["status"] != "passed"
                or proof["errorCode"] is not None
                or (proof_ci["repository"], proof_ci["workflow"], proof_ci["runId"], proof_ci["runAttempt"])
                != (run["repository"], run["workflow"], run["runId"], run["runAttempt"])
                or proof_ci["job"] != expected_job
                or (
                    kind == "node-host-network-scenario"
                    and not SHA256.fullmatch(proof["hooksSha256"])
                )
            ):
                raise EvidenceError(f"network proof identity or outcome is invalid: {source['name']}")
            checks = proof["checks"]
            if not isinstance(checks, dict) or set(checks) != expected_checks:
                raise EvidenceError(f"network proof checks are invalid: {source['name']}")
            for check, result in checks.items():
                if check.endswith("ResponseSha256"):
                    if not isinstance(result, str) or not SHA256.fullmatch(result):
                        raise EvidenceError(f"network proof digest is invalid: {source['name']}/{check}")
                elif result is not True:
                    raise EvidenceError(f"network proof check failed: {source['name']}/{check}")
            source_modes[mode] = source
        if not isinstance(value["results"], dict):
            raise EvidenceError(f"lifecycle results are not an object: {path.name}")
        if set(value["results"]) != EXPECTED_SCENARIOS:
            raise EvidenceError(f"lifecycle results do not cover the required matrix: {target}")
        for scenario, status in value["results"].items():
            if scenario not in EXPECTED_SCENARIOS or status not in {"passed", "failed", "incomplete"}:
                raise EvidenceError(f"invalid lifecycle result {target}/{scenario}")
            required_modes = NETWORK_SCENARIO_REQUIREMENTS.get(scenario, set())
            if target.startswith("node-host-"):
                required_modes = NODE_HOST_SCENARIO_REQUIREMENTS.get(scenario, set())
            if (
                status == "passed"
                and (target.startswith("connect-") or target.startswith("node-host-"))
                and required_modes
                and not required_modes <= set(source_modes)
            ):
                raise EvidenceError(f"lifecycle result has no matching network proof: {target}/{scenario}")
            key = (target, scenario)
            if key in records:
                raise EvidenceError(f"duplicate lifecycle result {target}/{scenario}")
            records[key] = {
                "target": target,
                "scenario": scenario,
                "status": status,
                "artifactSha256": artifact["sha256"],
                "evidenceArtifact": path.name,
                "ciRunId": run["runId"],
            }
    return [records[key] for key in sorted(records)], runs


def deduplicate_runs(runs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    unique = {tuple(run[key] for key in ("repository", "workflow", "runId", "runAttempt", "job")): run for run in runs}
    return [unique[key] for key in sorted(unique)]


def parse_upstream(path: Path | None) -> tuple[list[str], list[str]]:
    rejected: list[str] = []
    incomplete: list[str] = []
    if path is None or not path.is_file():
        return rejected, incomplete
    value = read_json(path)
    if not isinstance(value, dict):
        raise EvidenceError("upstream job results must be an object")
    for job, result in value.items():
        if result == "failure":
            rejected.append(f"upstream CI job failed: {job}")
        elif result in {"cancelled", "skipped"}:
            incomplete.append(f"upstream CI job did not complete: {job} ({result})")
        elif result != "success":
            rejected.append(f"upstream CI job has invalid result: {job} ({result})")
    return rejected, incomplete


def release_artifact_target(value: Any, context: str) -> str:
    if not isinstance(value, dict):
        raise EvidenceError(f"{context} is not an object")
    require_exact(
        value,
        {
            "product", "platform", "architecture", "version", "sizeBytes", "sha256", "sbomSha256",
            "minimumConfigurationSchema", "maximumConfigurationSchema", "xrayVersion",
        },
        context,
    )
    target = TARGET_BY_COORDINATE.get((value["product"], value["platform"], value["architecture"]))
    if target is None or not SHA256.fullmatch(value["sha256"]) or not SHA256.fullmatch(value["sbomSha256"]):
        raise EvidenceError(f"{context} has an invalid release artifact identity")
    if not isinstance(value["sizeBytes"], int) or value["sizeBytes"] < 1:
        raise EvidenceError(f"{context} has an invalid package size")
    return target


def validated_release_evidence(path: Path, source_commit: str) -> dict[str, Any]:
    value = read_json(path)
    require_exact(
        value,
        {"schemaVersion", "releaseId", "sourceCommit", "issuedAt", "signatureStatus", "releaseKeyId", "manifestSha256", "artifacts"},
        "release manifest evidence",
    )
    if value["schemaVersion"] != 1 or value["sourceCommit"] != source_commit:
        raise EvidenceError("release manifest evidence belongs to a different or unsupported candidate")
    if value["signatureStatus"] not in {"signed", "unsigned-validation"}:
        raise EvidenceError("release manifest evidence has an invalid signature status")
    if not isinstance(value["releaseKeyId"], str) or not value["releaseKeyId"]:
        raise EvidenceError("release manifest evidence has no signing key identity")
    if not SHA256.fullmatch(value["manifestSha256"]) or not isinstance(value["issuedAt"], int) or value["issuedAt"] < 1:
        raise EvidenceError("release manifest evidence has an invalid manifest identity")
    try:
        UUID(value["releaseId"])
    except (TypeError, ValueError) as error:
        raise EvidenceError("release manifest evidence has an invalid release ID") from error
    if not isinstance(value["artifacts"], list):
        raise EvidenceError("release manifest evidence artifacts are not an array")
    targets = [release_artifact_target(item, "release manifest artifact") for item in value["artifacts"]]
    if set(targets) != EXPECTED_TARGETS or len(targets) != len(set(targets)):
        raise EvidenceError("release manifest evidence does not contain the exact artifact set")
    return value


def aggregate(args: argparse.Namespace) -> dict[str, Any]:
    if not COMMIT.fullmatch(args.source_commit):
        raise EvidenceError("source commit must be a lowercase Git object ID")
    rejected, incomplete = parse_upstream(args.upstream_results)
    try:
        components, component_runs = component_records(args.components, args.source_commit)
        artifacts_internal = artifact_records(args.artifacts, args.source_commit)
        matrix, lifecycle_runs = matrix_records(args.lifecycle, args.source_commit)
    except (EvidenceError, KeyError, TypeError, json.JSONDecodeError) as error:
        rejected.append(str(error))
        components, component_runs, artifacts_internal, matrix, lifecycle_runs = [], [], [], [], []

    release_evidence: dict[str, Any] = {}
    if args.release_evidence and args.release_evidence.is_file():
        try:
            release_evidence = validated_release_evidence(args.release_evidence, args.source_commit)
        except (EvidenceError, TypeError, json.JSONDecodeError, OSError) as error:
            rejected.append(f"release evidence is invalid: {error}")
    else:
        incomplete.append("release manifest evidence is missing")
    release_id = release_evidence.get("releaseId")
    release_key_id = release_evidence.get("releaseKeyId")
    if release_evidence:
        if release_evidence.get("sourceCommit") != args.source_commit:
            rejected.append("release manifest evidence belongs to a different source commit")
        if release_evidence.get("signatureStatus") != "signed":
            incomplete.append("release manifest is not signed")

    try:
        signing = signing_records(args.lifecycle, release_key_id)
    except (EvidenceError, KeyError, TypeError, json.JSONDecodeError) as error:
        rejected.append(str(error))
        signing = []

    try:
        require_current_ci(component_runs, args, "component evidence")
        require_current_ci(lifecycle_runs, args, "lifecycle evidence")
    except EvidenceError as error:
        rejected.append(str(error))

    component_names = {item["name"] for item in components}
    for name in sorted(EXPECTED_COMPONENTS - component_names):
        incomplete.append(f"component evidence is missing: {name}")
    for item in components:
        for check, status in item["checks"].items():
            if status == "failed":
                rejected.append(f"component check failed: {item['name']}/{check}")
            elif status != "passed":
                incomplete.append(f"component check is incomplete: {item['name']}/{check}")

    artifact_by_target = {item["target"]: item for item in artifacts_internal}
    for target in sorted(EXPECTED_TARGETS - set(artifact_by_target)):
        incomplete.append(f"release artifact is missing: {target}")
    for item in artifacts_internal:
        if item["signatureStatus"] != "signed":
            incomplete.append(f"release artifact is unsigned: {item['target']}")

    if release_evidence:
        manifest_artifacts = {
            release_artifact_target(item, "release manifest artifact"): item
            for item in release_evidence["artifacts"]
        }
        for target, artifact in artifact_by_target.items():
            manifest_artifact = manifest_artifacts.get(target)
            if manifest_artifact is None:
                incomplete.append(f"release manifest artifact is missing: {target}")
            elif (
                manifest_artifact["sha256"] != artifact["sha256"]
                or manifest_artifact["sbomSha256"] != artifact["sbomSha256"]
            ):
                rejected.append(f"release manifest artifact mismatch: {target}")

    signing_by_target = {item["target"]: item for item in signing}
    for target in sorted(EXPECTED_TARGETS - set(signing_by_target)):
        incomplete.append(f"signature identity evidence is missing: {target}")
    for item in signing:
        artifact = artifact_by_target.get(item["target"])
        if artifact is None or (
            item["artifactName"] != artifact["name"]
            or item["artifactSha256"] != artifact["sha256"]
        ):
            rejected.append(f"signature evidence artifact mismatch: {item['target']}")
        if item["status"] == "failed":
            rejected.append(f"signature verification failed: {item['target']}")
        elif item["status"] != "verified":
            incomplete.append(f"signature verification is incomplete: {item['target']}")

    matrix_by_key = {(item["target"], item["scenario"]): item for item in matrix}
    for target in sorted(EXPECTED_TARGETS):
        for scenario in sorted(EXPECTED_SCENARIOS):
            item = matrix_by_key.get((target, scenario))
            if item is None:
                incomplete.append(f"lifecycle evidence is missing: {target}/{scenario}")
                continue
            artifact = artifact_by_target.get(target)
            if artifact is None or item["artifactSha256"] != artifact["sha256"]:
                rejected.append(f"lifecycle evidence artifact mismatch: {target}/{scenario}")
            if item["status"] == "failed":
                rejected.append(f"lifecycle scenario failed: {target}/{scenario}")
            elif item["status"] != "passed":
                incomplete.append(f"lifecycle scenario is incomplete: {target}/{scenario}")

    schema = {
        "releaseManifest": release_evidence.get("schemaVersion"),
        "releaseManifestSha256": release_evidence.get("manifestSha256"),
        "releaseManifestSignatureStatus": release_evidence.get("signatureStatus"),
        "database": args.database_schema,
        "minimumAgent": args.minimum_agent,
        "minimumClient": args.minimum_client,
    }
    if any(value is None for value in schema.values()):
        incomplete.append("schema compatibility identity is incomplete")
    if args.tree_state != "clean":
        incomplete.append("candidate source tree is not clean")
    if args.mode == "validation":
        incomplete.append("validation mode can never be accepted")

    candidate_base = {
        "mode": args.mode,
        "sourceCommit": args.source_commit,
        "treeState": args.tree_state,
        "releaseId": release_id,
        "ref": args.ref,
    }
    candidate_digest = canonical_digest(candidate_base)
    if rejected:
        state = "rejected"
        reasons = sorted(set(rejected + incomplete))
    elif incomplete:
        state = "incomplete"
        reasons = sorted(set(incomplete))
    else:
        state = "accepted"
        reasons = []
    artifacts = [{key: value for key, value in item.items() if key != "signatureStatus"} for item in artifacts_internal]
    aggregate_run = {
        "repository": args.repository,
        "workflow": args.workflow,
        "runId": args.run_id,
        "runAttempt": args.run_attempt,
        "job": args.job,
    }
    ci_run(aggregate_run, "acceptance aggregator")
    document = {
        "schemaVersion": 1,
        "candidate": {**candidate_base, "candidateDigest": candidate_digest},
        "components": components,
        "schema": schema,
        "signingIdentities": signing,
        "ciRuns": deduplicate_runs(component_runs + lifecycle_runs + [aggregate_run]),
        "artifacts": artifacts,
        "matrixResults": matrix,
        "decision": {
            "state": state,
            "reasons": reasons,
            "evaluatedCandidateDigest": candidate_digest,
        },
    }
    return document


def verify_accepted(
    path: Path,
    artifacts: Path,
    expected_commit: str | None,
    expected_release_id: str | None,
    components: Path | None = None,
    lifecycle: Path | None = None,
    release_evidence: Path | None = None,
) -> None:
    value = read_json(path)
    require_exact(
        value,
        {"schemaVersion", "candidate", "components", "schema", "signingIdentities", "ciRuns", "artifacts", "matrixResults", "decision"},
        "acceptance evidence",
    )
    if value["schemaVersion"] != 1:
        raise EvidenceError("unsupported acceptance evidence schema")
    candidate = value["candidate"]
    require_exact(candidate, {"mode", "sourceCommit", "treeState", "releaseId", "ref", "candidateDigest"}, "candidate")
    base = {key: candidate[key] for key in ("mode", "sourceCommit", "treeState", "releaseId", "ref")}
    digest = canonical_digest(base)
    if candidate["candidateDigest"] != digest or value["decision"].get("evaluatedCandidateDigest") != digest:
        raise EvidenceError("acceptance decision is not bound to the candidate")
    if value["decision"].get("state") != "accepted" or value["decision"].get("reasons") != []:
        raise EvidenceError("release acceptance evidence is not accepted")
    if candidate["mode"] != "release" or candidate["treeState"] != "clean":
        raise EvidenceError("accepted evidence must describe a clean release candidate")
    if not COMMIT.fullmatch(candidate["sourceCommit"]):
        raise EvidenceError("accepted evidence source commit is invalid")
    if expected_commit and candidate["sourceCommit"] != expected_commit:
        raise EvidenceError("accepted evidence source commit does not match the publish candidate")
    if expected_release_id and candidate["releaseId"] != expected_release_id:
        raise EvidenceError("accepted evidence release ID does not match the publish candidate")
    if not isinstance(value["components"], list) or {item.get("name") for item in value["components"]} != EXPECTED_COMPONENTS:
        raise EvidenceError("accepted evidence does not contain the exact component set")
    for item in value["components"]:
        require_exact(item, {"name", "version", "sourceCommit", "requiredChecks", "checks", "ci"}, f"component {item.get('name')}")
        if item["sourceCommit"] != candidate["sourceCommit"]:
            raise EvidenceError(f"component belongs to another candidate: {item['name']}")
        if set(item["requiredChecks"]) != REQUIRED_COMPONENT_CHECKS[item["name"]] or set(item["requiredChecks"]) != set(item["checks"]):
            raise EvidenceError(f"component checks are incomplete: {item['name']}")
        if any(result != "passed" for result in item["checks"].values()):
            raise EvidenceError(f"component has a non-passing check: {item['name']}")
        ci_run(item["ci"], f"component {item['name']}")
    require_exact(
        value["schema"],
        {"releaseManifest", "releaseManifestSha256", "releaseManifestSignatureStatus", "database", "minimumAgent", "minimumClient"},
        "schema identity",
    )
    if any(item is None for item in value["schema"].values()):
        raise EvidenceError("accepted evidence schema identity is incomplete")
    if not SHA256.fullmatch(value["schema"]["releaseManifestSha256"]) or value["schema"]["releaseManifestSignatureStatus"] != "signed":
        raise EvidenceError("accepted release manifest identity is not signed and digest-bound")
    if not isinstance(value["signingIdentities"], list) or {item.get("target") for item in value["signingIdentities"]} != EXPECTED_TARGETS:
        raise EvidenceError("accepted evidence does not contain the exact signing identity set")
    for item in value["signingIdentities"]:
        require_exact(
            item,
            {"target", "artifactName", "artifactSha256", "artifactSigner", "installerSigner", "releaseManifestKeyId", "status", "evidenceArtifact"},
            f"signing identity {item.get('target')}",
        )
        if (
            item["status"] != "verified"
            or not item["artifactSigner"]
            or not item["installerSigner"]
            or not item["releaseManifestKeyId"]
            or not item["evidenceArtifact"]
            or not SHA256.fullmatch(item["artifactSha256"])
        ):
            raise EvidenceError(f"signing identity is not verified: {item['target']}")
    if not isinstance(value["ciRuns"], list) or not value["ciRuns"]:
        raise EvidenceError("accepted evidence does not identify its CI runs")
    for index, run in enumerate(value["ciRuns"]):
        ci_run(run, f"CI run {index}")
    if not isinstance(value["artifacts"], list) or {item.get("target") for item in value["artifacts"]} != EXPECTED_TARGETS:
        raise EvidenceError("accepted evidence does not contain the exact artifact set")
    artifact_by_target: dict[str, dict[str, Any]] = {}
    for item in value["artifacts"]:
        require_exact(
            item,
            {"target", "name", "sha256", "sbomName", "sbomSha256", "metadataName", "metadataSha256", "sourceCommit"},
            f"artifact {item.get('target')}",
        )
        if item["sourceCommit"] != candidate["sourceCommit"]:
            raise EvidenceError(f"artifact belongs to another candidate: {item['target']}")
        if not all(SHA256.fullmatch(item[key]) for key in ("sha256", "sbomSha256", "metadataSha256")):
            raise EvidenceError(f"artifact digest is invalid: {item['target']}")
        artifact_by_target[item["target"]] = item
    expected_matrix = {(target, scenario) for target in EXPECTED_TARGETS for scenario in EXPECTED_SCENARIOS}
    if not isinstance(value["matrixResults"], list):
        raise EvidenceError("accepted lifecycle matrix is not an array")
    actual_matrix = set()
    for item in value["matrixResults"]:
        require_exact(item, {"target", "scenario", "status", "artifactSha256", "evidenceArtifact", "ciRunId"}, "lifecycle result")
        if item["status"] != "passed" or not item["evidenceArtifact"] or not item["ciRunId"]:
            raise EvidenceError(f"lifecycle result is not passing: {item['target']}/{item['scenario']}")
        if item["artifactSha256"] != artifact_by_target[item["target"]]["sha256"]:
            raise EvidenceError(f"lifecycle result has the wrong artifact digest: {item['target']}/{item['scenario']}")
        actual_matrix.add((item["target"], item["scenario"]))
    if actual_matrix != expected_matrix:
        raise EvidenceError("accepted evidence does not contain the complete passed lifecycle matrix")
    for item in value["artifacts"]:
        artifact = artifacts / item["name"]
        metadata = artifacts / item["metadataName"]
        sbom = artifacts / item["sbomName"]
        for candidate_path, expected in (
            (artifact, item["sha256"]),
            (metadata, item["metadataSha256"]),
            (sbom, item["sbomSha256"]),
        ):
            if not candidate_path.is_file() or sha256_file(candidate_path) != expected:
                raise EvidenceError(f"published bytes do not match accepted evidence: {candidate_path.name}")
    if components is not None:
        records, runs = component_records(components, candidate["sourceCommit"])
        if records != value["components"]:
            raise EvidenceError("published component evidence differs from the accepted record")
        for run in runs:
            ci_run(run, "published component evidence")
    if lifecycle is not None:
        records, runs = matrix_records(lifecycle, candidate["sourceCommit"])
        key_id = value["signingIdentities"][0]["releaseManifestKeyId"]
        signing = signing_records(lifecycle, key_id)
        if records != value["matrixResults"] or signing != value["signingIdentities"]:
            raise EvidenceError("published lifecycle evidence differs from the accepted record")
        for run in runs:
            ci_run(run, "published lifecycle evidence")
    if components is not None and lifecycle is not None:
        accepted_runs = {
            tuple(run[key] for key in ("repository", "workflow", "runId", "runAttempt", "job"))
            for run in value["ciRuns"]
        }
        evidence_runs = {
            tuple(run[key] for key in ("repository", "workflow", "runId", "runAttempt", "job"))
            for run in component_records(components, candidate["sourceCommit"])[1]
            + matrix_records(lifecycle, candidate["sourceCommit"])[1]
        }
        if not evidence_runs <= accepted_runs:
            raise EvidenceError("published evidence CI identities are absent from the accepted record")
    if release_evidence is not None:
        current = validated_release_evidence(release_evidence, candidate["sourceCommit"])
        if (
            current["releaseId"] != candidate["releaseId"]
            or current["manifestSha256"] != value["schema"]["releaseManifestSha256"]
            or current["releaseKeyId"] != value["signingIdentities"][0]["releaseManifestKeyId"]
            or current["signatureStatus"] != "signed"
        ):
            raise EvidenceError("published release manifest evidence differs from the accepted record")
        manifest_artifacts = {
            release_artifact_target(item, "published release manifest artifact"): item
            for item in current["artifacts"]
        }
        for target, artifact in artifact_by_target.items():
            manifest_artifact = manifest_artifacts.get(target)
            if manifest_artifact is None or (
                manifest_artifact["sha256"] != artifact["sha256"]
                or manifest_artifact["sbomSha256"] != artifact["sbomSha256"]
            ):
                raise EvidenceError(f"published release manifest artifact mismatch: {target}")


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser()
    commands = root.add_subparsers(dest="command", required=True)
    aggregate_parser = commands.add_parser("aggregate")
    aggregate_parser.add_argument("--mode", choices=("release", "validation"), required=True)
    aggregate_parser.add_argument("--source-commit", required=True)
    aggregate_parser.add_argument("--tree-state", choices=("clean", "dirty"), required=True)
    aggregate_parser.add_argument("--ref", required=True)
    aggregate_parser.add_argument("--components", type=Path, required=True)
    aggregate_parser.add_argument("--artifacts", type=Path, required=True)
    aggregate_parser.add_argument("--lifecycle", type=Path, required=True)
    aggregate_parser.add_argument("--release-evidence", type=Path)
    aggregate_parser.add_argument("--upstream-results", type=Path)
    aggregate_parser.add_argument("--database-schema", type=int)
    aggregate_parser.add_argument("--minimum-agent")
    aggregate_parser.add_argument("--minimum-client")
    aggregate_parser.add_argument("--repository", required=True)
    aggregate_parser.add_argument("--workflow", required=True)
    aggregate_parser.add_argument("--run-id", required=True)
    aggregate_parser.add_argument("--run-attempt", type=int, required=True)
    aggregate_parser.add_argument("--job", required=True)
    aggregate_parser.add_argument("--output", type=Path, required=True)
    verify_parser = commands.add_parser("verify-accepted")
    verify_parser.add_argument("--evidence", type=Path, required=True)
    verify_parser.add_argument("--artifacts", type=Path, required=True)
    verify_parser.add_argument("--expected-commit")
    verify_parser.add_argument("--expected-release-id")
    verify_parser.add_argument("--components", type=Path)
    verify_parser.add_argument("--lifecycle", type=Path)
    verify_parser.add_argument("--release-evidence", type=Path)
    return root


def main() -> None:
    args = parser().parse_args()
    try:
        if args.command == "aggregate":
            document = aggregate(args)
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            print(document["decision"]["state"])
        else:
            verify_accepted(
                args.evidence,
                args.artifacts,
                args.expected_commit,
                args.expected_release_id,
                args.components,
                args.lifecycle,
                args.release_evidence,
            )
            print("accepted release evidence verified")
    except (EvidenceError, KeyError, TypeError, json.JSONDecodeError, OSError) as error:
        print(f"release acceptance verification failed: {error}", file=sys.stderr)
        raise SystemExit(1) from error


if __name__ == "__main__":
    main()
