import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


SCRIPT = Path(__file__).parents[2] / "smoke" / "run-connect-network-acceptance.py"
SPEC = importlib.util.spec_from_file_location("connect_network_acceptance", SCRIPT)
coordinator = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(coordinator)


class ConnectNetworkAcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.value = {
            "schemaVersion": 1,
            "hookTimeoutSeconds": 30,
            "hooks": {name: ["/usr/bin/true"] for name in coordinator.HOOK_NAMES},
        }

    def tearDown(self):
        self.temporary.cleanup()

    def write(self, value=None):
        path = self.root / "hooks.json"
        path.write_text(json.dumps(self.value if value is None else value))
        return path

    def test_hook_contract_is_closed_and_never_uses_shell_strings(self):
        timeout, hooks = coordinator.load_hooks(self.write())
        self.assertEqual(timeout, 30)
        self.assertEqual(set(hooks), coordinator.HOOK_NAMES)

        extended = dict(self.value, setupCode="secret")
        with self.assertRaisesRegex(coordinator.CoordinatorError, "coordinator_config_invalid"):
            coordinator.load_hooks(self.write(extended))
        invalid = json.loads(json.dumps(self.value))
        invalid["hooks"]["cleanup"] = "/bin/true; rm -rf /"
        with self.assertRaisesRegex(coordinator.CoordinatorError, "coordinator_hook_invalid_cleanup"):
            coordinator.load_hooks(self.write(invalid))

    def test_proof_modes_and_names_are_fixed(self):
        self.assertEqual(
            coordinator.MODES,
            ("online", "offline", "direct-failed", "relay-failed", "logout"),
        )


if __name__ == "__main__":
    unittest.main()
