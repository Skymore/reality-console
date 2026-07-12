import importlib.util
import argparse
import json
from pathlib import Path
import tempfile
import unittest


SCRIPT = Path(__file__).parents[2] / "smoke" / "run-node-host-network-acceptance.py"
SPEC = importlib.util.spec_from_file_location("node_host_network_acceptance", SCRIPT)
scenario = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(scenario)
WRITER_SCRIPT = Path(__file__).parents[1] / "write-lifecycle-evidence.py"
WRITER_SPEC = importlib.util.spec_from_file_location("node_host_lifecycle_writer", WRITER_SCRIPT)
writer = importlib.util.module_from_spec(WRITER_SPEC)
WRITER_SPEC.loader.exec_module(writer)


class NodeHostNetworkAcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self):
        self.temporary.cleanup()

    def test_hook_contract_is_closed_and_command_array_only(self):
        value = {
            "schemaVersion": 1,
            "hookTimeoutSeconds": 30,
            "hooks": {name: ["/usr/bin/true"] for name in scenario.HOOK_NAMES},
        }
        path = self.root / "hooks.json"
        path.write_text(json.dumps(value))
        timeout, hooks = scenario.load_hooks(path)
        self.assertEqual(timeout, 30)
        self.assertEqual(set(hooks), scenario.HOOK_NAMES)

        value["hooks"]["cleanup"] = "/bin/true; rm -rf /"
        path.write_text(json.dumps(value))
        with self.assertRaisesRegex(scenario.ScenarioError, "node_hook_invalid_cleanup"):
            scenario.load_hooks(path)

    def test_ready_status_requires_complete_protocol_and_live_relay_evidence(self):
        status = {field: None for field in scenario.STATUS_FIELDS}
        status.update(
            {
                "phase": "ready",
                "packageVerified": True,
                "nodeId": "11111111-1111-4111-8111-111111111111",
                "serviceInstanceId": "22222222-2222-4222-8222-222222222222",
                "appliedRevision": 7,
                "runtimeState": "serving",
                "setupPhase": "ready",
                "directVerification": "verified",
                "relayVerification": "verified",
                "relayConnection": "registered",
            }
        )
        self.assertTrue(scenario.ready_status(status))
        status["relayConnection"] = "notRegistered"
        self.assertFalse(scenario.ready_status(status))
        status["relayConnection"] = "registered"
        status["serviceInstanceId"] = None
        self.assertFalse(scenario.ready_status(status))

    def test_lifecycle_import_binds_node_host_proof_to_package_and_agent(self):
        binary = self.root / "node-host"
        binary.write_bytes(b"agent-binary")
        binary.chmod(0o755)
        artifact = self.root / "node-host.pkg"
        artifact.write_bytes(b"xar!" + b"package" * 100)
        hooks = self.root / "hooks.json"
        hooks.write_text("{}")
        proof = self.root / "node-host-macos-aarch64.online.node.json"
        args = argparse.Namespace(
            target="node-host-macos-aarch64",
            source_commit="a" * 40,
            artifact=artifact,
            binary=binary,
            repository="owner/repo",
            workflow="release-build.yml",
            run_id="1234",
            run_attempt=1,
        )
        scenario.write_proof(
            proof,
            "online",
            args,
            scenario.file_sha256(hooks),
            {
                "activationEnrollment": True,
                "directProtocolVerified": True,
                "relayProtocolVerified": True,
            },
            None,
        )
        mode, results, source = writer.import_node_host_proof(
            proof,
            args.target,
            artifact,
            args.source_commit,
            (args.repository, args.workflow, args.run_id, args.run_attempt),
            scenario.file_sha256(binary),
        )
        self.assertEqual(mode, "online")
        self.assertEqual(results, {"activation-enrollment", "direct-path"})
        self.assertEqual(source["kind"], "node-host-network-scenario")

        value = json.loads(proof.read_text())
        value["binarySha256"] = "f" * 64
        proof.write_text(json.dumps(value))
        with self.assertRaisesRegex(ValueError, "another package"):
            writer.import_node_host_proof(
                proof,
                args.target,
                artifact,
                args.source_commit,
                (args.repository, args.workflow, args.run_id, args.run_attempt),
                scenario.file_sha256(binary),
            )


if __name__ == "__main__":
    unittest.main()
