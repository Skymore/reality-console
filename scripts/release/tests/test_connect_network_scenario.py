import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest


SCRIPT = Path(__file__).parents[2] / "smoke" / "run-connect-network-scenario.py"
SPEC = importlib.util.spec_from_file_location("connect_network_scenario", SCRIPT)
scenario = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(scenario)
WRITER_SCRIPT = Path(__file__).parents[1] / "write-lifecycle-evidence.py"
WRITER_SPEC = importlib.util.spec_from_file_location("write_lifecycle_evidence_for_network", WRITER_SCRIPT)
writer = importlib.util.module_from_spec(WRITER_SPEC)
WRITER_SPEC.loader.exec_module(writer)


class ConnectNetworkScenarioTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.config = {
            "schemaVersion": 1,
            "deviceName": "Acceptance device",
            "directNodeId": "11111111-1111-4111-8111-111111111111",
            "relayNodeId": "22222222-2222-4222-8222-222222222222",
            "testUrl": "https://acceptance.example.test/probe",
            "expectedResponseSha256": "0" * 64,
            "holdSeconds": 15,
            "readinessTimeoutSeconds": 20,
        }

    def tearDown(self):
        self.temporary.cleanup()

    def write_config(self, value=None):
        path = self.root / "config.json"
        path.write_text(json.dumps(self.config if value is None else value))
        return path

    def test_config_is_closed_and_requires_distinct_canonical_nodes(self):
        self.assertEqual(scenario.load_config(self.write_config())["schemaVersion"], 1)
        extended = dict(self.config, secret="not-allowed")
        with self.assertRaisesRegex(scenario.ScenarioError, "scenario_config_invalid"):
            scenario.load_config(self.write_config(extended))
        duplicate = dict(self.config, relayNodeId=self.config["directNodeId"])
        with self.assertRaisesRegex(scenario.ScenarioError, "scenario_nodes_not_distinct"):
            scenario.load_config(self.write_config(duplicate))

    def test_config_rejects_credentials_query_and_unbounded_holds(self):
        for url in (
            "https://user:secret@acceptance.example.test/probe",
            "https://acceptance.example.test/probe?token=secret",
        ):
            invalid = dict(self.config, testUrl=url)
            with self.assertRaisesRegex(scenario.ScenarioError, "scenario_test_url_invalid"):
                scenario.load_config(self.write_config(invalid))
        invalid = dict(self.config, holdSeconds=301)
        with self.assertRaisesRegex(scenario.ScenarioError, "scenario_hold_invalid"):
            scenario.load_config(self.write_config(invalid))

    def test_isolation_proofs_have_distinct_closed_check_sets(self):
        self.assertEqual(
            writer.NETWORK_CHECKS["direct-failed"],
            {"directPathUnavailable", "relayResponseSha256"},
        )
        self.assertEqual(
            writer.NETWORK_CHECKS["relay-failed"],
            {"relayPathUnavailable", "directResponseSha256"},
        )
        self.assertEqual(writer.NETWORK_RESULTS["direct-failed"], set())

    def test_proof_is_owner_only_create_new_and_contains_no_topology_url(self):
        binary = self.root / "connect"
        binary.write_bytes(b"installed-binary")
        binary.chmod(0o755)
        artifact = self.root / "connect.dmg"
        artifact.write_bytes(b"artifact" * 100)
        proof = self.root / "proof.json"
        scenario.write_proof(
            proof,
            "online",
            "connect-macos-aarch64",
            artifact,
            binary,
            "a" * 40,
            {
                "repository": "owner/repo",
                "workflow": "release-build.yml",
                "runId": "1234",
                "runAttempt": 1,
                "job": "connect-network-scenario (connect-macos-aarch64)",
            },
            {"activationEnrollment": True, "directResponseSha256": "0" * 64},
            None,
        )
        value = json.loads(proof.read_text())
        self.assertEqual(value["status"], "passed")
        self.assertEqual(value["artifact"]["name"], "connect.dmg")
        self.assertEqual(value["target"], "connect-macos-aarch64")
        self.assertEqual(value["sourceCommit"], "a" * 40)
        self.assertEqual(value["ci"]["runId"], "1234")
        self.assertNotIn("testUrl", value)
        if os.name != "nt":
            self.assertEqual(proof.stat().st_mode & 0o777, 0o600)
        with self.assertRaises(FileExistsError):
            scenario.write_proof(
                proof,
                "online",
                "connect-macos-aarch64",
                artifact,
                binary,
                "a" * 40,
                {
                    "repository": "owner/repo",
                    "workflow": "release-build.yml",
                    "runId": "1234",
                    "runAttempt": 1,
                    "job": "connect-network-scenario (connect-macos-aarch64)",
                },
                {},
                None,
            )

    def test_lifecycle_import_accepts_only_candidate_bound_complete_proof(self):
        binary = self.root / "connect"
        binary.write_bytes(b"installed-binary")
        binary.chmod(0o755)
        artifact = self.root / "connect.dmg"
        artifact.write_bytes(b"artifact" * 100)
        proof = self.root / "online.json"
        ci = {
            "repository": "owner/repo",
            "workflow": "release-build.yml",
            "runId": "1234",
            "runAttempt": 1,
            "job": "connect-network-scenario (connect-macos-aarch64)",
        }
        scenario.write_proof(
            proof,
            "online",
            "connect-macos-aarch64",
            artifact,
            binary,
            "a" * 40,
            ci,
            {
                "activationEnrollment": True,
                "directResponseSha256": "0" * 64,
                "relayResponseSha256": "1" * 64,
            },
            None,
        )
        mode, results, source = writer.import_network_proof(
            proof,
            "connect-macos-aarch64",
            artifact,
            "a" * 40,
            ("owner/repo", "release-build.yml", "1234", 1),
            scenario.file_sha256(binary),
        )
        self.assertEqual(mode, "online")
        self.assertEqual(results, {"activation-enrollment", "direct-path"})
        self.assertEqual(source["kind"], "connect-network-scenario")

        value = json.loads(proof.read_text())
        value["artifact"]["sha256"] = "f" * 64
        proof.write_text(json.dumps(value))
        with self.assertRaisesRegex(ValueError, "another package"):
            writer.import_network_proof(
                proof,
                "connect-macos-aarch64",
                artifact,
                "a" * 40,
                ("owner/repo", "release-build.yml", "1234", 1),
                scenario.file_sha256(binary),
            )


if __name__ == "__main__":
    unittest.main()
