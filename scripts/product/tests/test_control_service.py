import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest


SCRIPT = Path(__file__).parents[1] / "control-service.py"
SPEC = importlib.util.spec_from_file_location("product_control_service", SCRIPT)
control = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(control)


class ControlServiceProductTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.xray = self.root / "xray"
        self.xray.write_bytes(b"xray")
        self.xray.chmod(0o700)

    def tearDown(self):
        self.temporary.cleanup()

    def test_config_is_closed_absolute_and_preserves_admin_token(self):
        first = control.build_config(
            self.root,
            "127.0.0.1:8787",
            "http://127.0.0.1:8787",
            "Friends",
            self.xray,
            None,
        )
        second = control.build_config(
            self.root,
            "127.0.0.1:8787",
            "https://control.example.test",
            "Friends",
            self.xray,
            first,
        )
        self.assertEqual(first["bootstrapToken"], second["bootstrapToken"])
        self.assertTrue(Path(str(first["databasePath"])).is_absolute())
        path = self.root / "control.json"
        control.atomic_json(path, second)
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(json.loads(path.read_text())["schemaVersion"], 1)

    def test_public_http_and_non_loopback_binding_are_rejected(self):
        with self.assertRaisesRegex(control.ProductError, "loopback"):
            control.validate_bind("0.0.0.0:8787")
        with self.assertRaisesRegex(control.ProductError, "HTTPS"):
            control.validate_origin("http://control.example.test")

    def test_launch_agent_contains_no_admin_token(self):
        binary = self.root / "control-server"
        config = self.root / "control.json"
        logs = self.root / "logs"
        token = "secret-admin-token-that-must-not-enter-plist"
        value = control.build_plist(binary, config, logs)
        encoded = json.dumps(value)
        self.assertNotIn(token, encoded)
        self.assertEqual(value["ProgramArguments"], [str(binary), "serve", "--config", str(config)])


if __name__ == "__main__":
    unittest.main()
