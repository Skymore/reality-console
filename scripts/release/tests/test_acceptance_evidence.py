from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


SCRIPT = Path(__file__).parents[1] / "acceptance-evidence.py"
SPEC = importlib.util.spec_from_file_location("acceptance_evidence", SCRIPT)
assert SPEC and SPEC.loader
acceptance = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(acceptance)
LIFECYCLE_SCRIPT = Path(__file__).parents[1] / "write-lifecycle-evidence.py"
LIFECYCLE_SPEC = importlib.util.spec_from_file_location("write_lifecycle_evidence", LIFECYCLE_SCRIPT)
assert LIFECYCLE_SPEC and LIFECYCLE_SPEC.loader
lifecycle_writer = importlib.util.module_from_spec(LIFECYCLE_SPEC)
LIFECYCLE_SPEC.loader.exec_module(lifecycle_writer)


COMMIT = "a" * 40


class AcceptanceEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.components = self.root / "components"
        self.artifacts = self.root / "artifacts"
        self.lifecycle = self.root / "lifecycle"
        for directory in (self.components, self.artifacts, self.lifecycle):
            directory.mkdir()
        self.release_evidence = self.root / "release-evidence.json"
        self._write_components()
        self._write_artifacts_and_lifecycle()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def _ci(job: str) -> dict[str, object]:
        return {
            "repository": "owner/repo",
            "workflow": "release-build.yml",
            "runId": "1234",
            "runAttempt": 1,
            "job": job,
        }

    def _write_components(self) -> None:
        for name in acceptance.EXPECTED_COMPONENTS:
            checks = sorted(acceptance.REQUIRED_COMPONENT_CHECKS[name])
            (self.components / f"{name}.component.json").write_text(json.dumps({
                "schemaVersion": 1,
                "kind": "component-gate",
                "name": name,
                "version": "1.0.0",
                "sourceCommit": COMMIT,
                "requiredChecks": checks,
                "checks": {check: "passed" for check in checks},
                "ci": self._ci(f"component-gates ({name})"),
            }))

    def _write_artifacts_and_lifecycle(self) -> None:
        coordinates = {
            "connect-macos-aarch64": ("connect", "macos", "aarch64", ".dmg"),
            "connect-macos-x86_64": ("connect", "macos", "x86_64", ".dmg"),
            "connect-windows-x86_64": ("connect", "windows", "x86_64", ".exe"),
            "node-host-macos-aarch64": ("nodeHost", "macos", "aarch64", ".pkg"),
            "node-host-macos-x86_64": ("nodeHost", "macos", "x86_64", ".pkg"),
        }
        manifest_artifacts = []
        for target, (product, platform, architecture, suffix) in coordinates.items():
            artifact_name = target + suffix
            sbom_name = artifact_name + ".cdx.json"
            (self.artifacts / artifact_name).write_bytes((target + " package").encode())
            (self.artifacts / sbom_name).write_text("{}\n")
            metadata = {
                "product": product,
                "platform": platform,
                "architecture": architecture,
                "version": "1.0.0",
                "path": artifact_name,
                "sbomPath": sbom_name,
                "minimumConfigurationSchema": 1,
                "maximumConfigurationSchema": 1,
                "xrayVersion": "1.0.0",
                "signatureStatus": "signed",
            }
            (self.artifacts / f"{target}.artifact.json").write_text(json.dumps(metadata))
            manifest_artifacts.append({
                "product": product,
                "platform": platform,
                "architecture": architecture,
                "version": "1.0.0",
                "sizeBytes": (self.artifacts / artifact_name).stat().st_size,
                "sha256": acceptance.sha256_file(self.artifacts / artifact_name),
                "sbomSha256": acceptance.sha256_file(self.artifacts / sbom_name),
                "minimumConfigurationSchema": 1,
                "maximumConfigurationSchema": 1,
                "xrayVersion": "1.0.0",
            })
            (self.lifecycle / f"{target}.signature-verification.json").write_text(json.dumps({
                "schemaVersion": 1,
                "kind": "signature-verification",
                "target": target,
                "artifact": {"name": artifact_name, "sha256": acceptance.sha256_file(self.artifacts / artifact_name)},
                "artifactSigner": "Developer ID Application: Example",
                "installerSigner": "Developer ID Installer: Example" if platform == "macos" else "Example Corp",
                "status": "verified",
            }))
            artifact_sha = acceptance.sha256_file(self.artifacts / artifact_name)
            sources = []
            if product == "connect":
                proof_checks = {
                    "online": {
                        "activationEnrollment": True,
                        "directResponseSha256": "1" * 64,
                        "relayResponseSha256": "2" * 64,
                    },
                    "offline": {
                        "offlineRefreshFailedClosed": True,
                        "directResponseSha256": "1" * 64,
                        "relayResponseSha256": "2" * 64,
                        "offlineRestart": True,
                    },
                    "logout": {"logoutRemovalCleanup": True},
                    "direct-failed": {
                        "directPathUnavailable": True,
                        "relayResponseSha256": "2" * 64,
                    },
                    "relay-failed": {
                        "relayPathUnavailable": True,
                        "directResponseSha256": "1" * 64,
                    },
                }
                for mode, checks in proof_checks.items():
                    proof_name = f"{target}.{mode}.network.json"
                    proof_path = self.lifecycle / proof_name
                    proof_path.write_text(json.dumps({
                        "schemaVersion": 1,
                        "kind": "connect-network-scenario",
                        "mode": mode,
                        "target": target,
                        "sourceCommit": COMMIT,
                        "artifact": {"name": artifact_name, "sha256": artifact_sha},
                        "binarySha256": "c" * 64,
                        "ci": self._ci(f"connect-network-scenario ({target})"),
                        "status": "passed",
                        "checks": checks,
                        "errorCode": None,
                    }))
                    sources.append({
                        "kind": "connect-network-scenario",
                        "mode": mode,
                        "name": proof_name,
                        "sha256": acceptance.sha256_file(proof_path),
                    })
            elif product == "nodeHost":
                proof_checks = {
                    "online": {
                        "activationEnrollment": True,
                        "directProtocolVerified": True,
                        "relayProtocolVerified": True,
                    },
                    "offline-restart": {
                        "controlUnavailableDuringRestart": True,
                        "serviceInstanceChanged": True,
                        "lastKnownGoodPreserved": True,
                    },
                    "isolation": {
                        "directFailureIsolated": True,
                        "relayFailureIsolated": True,
                    },
                    "logout": {"logoutRemovalCleanup": True},
                }
                for mode, checks in proof_checks.items():
                    proof_name = f"{target}.{mode}.node.json"
                    proof_path = self.lifecycle / proof_name
                    proof_path.write_text(json.dumps({
                        "schemaVersion": 1,
                        "kind": "node-host-network-scenario",
                        "mode": mode,
                        "target": target,
                        "sourceCommit": COMMIT,
                        "artifact": {"name": artifact_name, "sha256": artifact_sha},
                        "binarySha256": "c" * 64,
                        "hooksSha256": "d" * 64,
                        "ci": self._ci(f"node-host-network-scenario ({target})"),
                        "status": "passed",
                        "checks": checks,
                        "errorCode": None,
                    }))
                    sources.append({
                        "kind": "node-host-network-scenario",
                        "mode": mode,
                        "name": proof_name,
                        "sha256": acceptance.sha256_file(proof_path),
                    })
            (self.lifecycle / f"{target}.lifecycle.json").write_text(json.dumps({
                "schemaVersion": 1,
                "kind": "package-lifecycle",
                "evidenceType": "actual-package",
                "sourceCommit": COMMIT,
                "target": target,
                "artifact": {"name": artifact_name, "sha256": artifact_sha},
                "results": {scenario: "passed" for scenario in acceptance.EXPECTED_SCENARIOS},
                "sources": sources,
                "ci": self._ci(f"artifact-lifecycle ({target})"),
            }))
        self.release_evidence.write_text(json.dumps({
            "schemaVersion": 1,
            "releaseId": "18d10d40-f516-4d8d-881a-79dbce9a5449",
            "sourceCommit": COMMIT,
            "issuedAt": 1_700_000_000,
            "signatureStatus": "signed",
            "releaseKeyId": "production-release-key",
            "manifestSha256": "b" * 64,
            "artifacts": manifest_artifacts,
        }))

    def _args(self, mode: str = "release") -> argparse.Namespace:
        return argparse.Namespace(
            mode=mode,
            source_commit=COMMIT,
            tree_state="clean",
            ref="refs/tags/v1.0.0" if mode == "release" else "refs/heads/main",
            components=self.components,
            artifacts=self.artifacts,
            lifecycle=self.lifecycle,
            release_evidence=self.release_evidence,
            upstream_results=None,
            database_schema=8,
            minimum_agent="1.0.0",
            minimum_client="1.0.0",
            repository="owner/repo",
            workflow="release-build.yml",
            run_id="1234",
            run_attempt=1,
            job="release-acceptance",
            output=self.root / "acceptance.json",
        )

    def test_complete_release_is_accepted_and_reverified(self) -> None:
        self.assertIn("headless-smoke", acceptance.REQUIRED_COMPONENT_CHECKS["connect"])
        evidence = acceptance.aggregate(self._args())
        self.assertEqual(evidence["decision"]["state"], "accepted")
        path = self.root / "accepted.json"
        path.write_text(json.dumps(evidence))
        acceptance.verify_accepted(
            path,
            self.artifacts,
            COMMIT,
            evidence["candidate"]["releaseId"],
            self.components,
            self.lifecycle,
            self.release_evidence,
        )

    def test_validation_is_never_accepted(self) -> None:
        evidence = acceptance.aggregate(self._args("validation"))
        self.assertEqual(evidence["decision"]["state"], "incomplete")
        self.assertIn("validation mode can never be accepted", evidence["decision"]["reasons"])

    def test_missing_evidence_is_incomplete(self) -> None:
        (self.components / "relay.component.json").unlink()
        evidence = acceptance.aggregate(self._args())
        self.assertEqual(evidence["decision"]["state"], "incomplete")

    def test_failed_check_is_rejected(self) -> None:
        path = self.components / "relay.component.json"
        value = json.loads(path.read_text())
        value["checks"]["clippy"] = "failed"
        path.write_text(json.dumps(value))
        evidence = acceptance.aggregate(self._args())
        self.assertEqual(evidence["decision"]["state"], "rejected")

    def test_simulated_lifecycle_cannot_be_release_evidence(self) -> None:
        path = self.lifecycle / "connect-windows-x86_64.lifecycle.json"
        value = json.loads(path.read_text())
        value["evidenceType"] = "simulated-filesystem"
        path.write_text(json.dumps(value))
        evidence = acceptance.aggregate(self._args())
        self.assertEqual(evidence["decision"]["state"], "rejected")
        self.assertTrue(any("simulated lifecycle" in reason for reason in evidence["decision"]["reasons"]))

    def test_partial_lifecycle_matrix_is_rejected(self) -> None:
        path = self.lifecycle / "connect-windows-x86_64.lifecycle.json"
        value = json.loads(path.read_text())
        value["results"].pop("failed-upgrade-rollback")
        path.write_text(json.dumps(value))
        evidence = acceptance.aggregate(self._args())
        self.assertEqual(evidence["decision"]["state"], "rejected")

    def test_signature_evidence_must_bind_the_built_package(self) -> None:
        path = self.lifecycle / "connect-windows-x86_64.signature-verification.json"
        value = json.loads(path.read_text())
        value["artifact"]["sha256"] = "f" * 64
        path.write_text(json.dumps(value))
        evidence = acceptance.aggregate(self._args())
        self.assertEqual(evidence["decision"]["state"], "rejected")

    def test_connect_isolation_requires_both_failure_proofs(self) -> None:
        path = self.lifecycle / "connect-macos-aarch64.lifecycle.json"
        value = json.loads(path.read_text())
        value["sources"] = [source for source in value["sources"] if source["mode"] != "relay-failed"]
        path.write_text(json.dumps(value))
        evidence = acceptance.aggregate(self._args())
        self.assertEqual(evidence["decision"]["state"], "rejected")
        self.assertTrue(any("relay-path-isolation" in reason for reason in evidence["decision"]["reasons"]))

    def test_evidence_from_another_ci_attempt_is_rejected(self) -> None:
        path = self.components / "relay.component.json"
        value = json.loads(path.read_text())
        value["ci"]["runAttempt"] = 2
        path.write_text(json.dumps(value))
        evidence = acceptance.aggregate(self._args())
        self.assertEqual(evidence["decision"]["state"], "rejected")

    def test_publish_reverification_detects_changed_artifact(self) -> None:
        evidence = acceptance.aggregate(self._args())
        path = self.root / "accepted.json"
        path.write_text(json.dumps(evidence))
        artifact = self.artifacts / evidence["artifacts"][0]["name"]
        artifact.write_bytes(b"changed")
        with self.assertRaises(acceptance.EvidenceError):
            acceptance.verify_accepted(path, self.artifacts, COMMIT, evidence["candidate"]["releaseId"])

    def test_echo_file_cannot_be_lifecycle_artifact(self) -> None:
        fake = self.root / "fake.exe"
        fake.write_text("fake release artifact\n" * 100)
        with self.assertRaisesRegex(ValueError, "do not match a supported release package"):
            lifecycle_writer.verify_real_package(fake)


if __name__ == "__main__":
    unittest.main()
