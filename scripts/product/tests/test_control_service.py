import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


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

    def test_config_upgrade_preserves_existing_operator_settings_by_default(self):
        existing = control.build_config(
            self.root,
            "127.0.0.1:9876",
            "https://control.example.test:8443",
            "Existing Friends",
            self.xray,
            None,
            "local-tcp",
        )
        upgraded = control.build_config(
            self.root,
            None,
            None,
            None,
            self.xray,
            existing,
        )
        self.assertEqual(upgraded["bindAddress"], existing["bindAddress"])
        self.assertEqual(upgraded["publicOrigin"], existing["publicOrigin"])
        self.assertEqual(upgraded["networkName"], existing["networkName"])
        self.assertEqual(upgraded["probeMode"], "local-tcp")
        self.assertEqual(upgraded["bootstrapToken"], existing["bootstrapToken"])

    def test_public_http_and_non_loopback_binding_are_rejected(self):
        with self.assertRaisesRegex(control.ProductError, "loopback"):
            control.validate_bind("0.0.0.0:8787")
        with self.assertRaisesRegex(control.ProductError, "HTTPS"):
            control.validate_origin("http://control.example.test")

    def test_remote_probe_requires_https_endpoint_and_private_token_file(self):
        token = self.root / "probe-token"
        token.write_text("p" * 48)
        token.chmod(0o600)
        self.assertEqual(
            control.probe_config(
                "remote-http",
                "https://probe.example.test/v1/tcp-probe",
                token,
                None,
            ),
            ("remote-http", "https://probe.example.test/v1/tcp-probe", "p" * 48),
        )
        token.chmod(0o644)
        with self.assertRaisesRegex(control.ProductError, "owner-only"):
            control.probe_config(
                "remote-http",
                "https://probe.example.test/v1/tcp-probe",
                token,
                None,
            )
        with self.assertRaisesRegex(control.ProductError, "requires"):
            control.probe_config("remote-http", None, None, None)

    def test_launch_agent_contains_no_admin_token(self):
        binary = self.root / "control-server"
        config = self.root / "control.json"
        logs = self.root / "logs"
        token = "secret-admin-token-that-must-not-enter-plist"
        value = control.build_plist(binary, config, logs)
        encoded = json.dumps(value)
        self.assertNotIn(token, encoded)
        self.assertEqual(value["ProgramArguments"], [str(binary), "serve", "--config", str(config)])

    def test_node_invitation_has_complete_initial_configuration(self):
        class Args:
            display_name = "Friend Mac"
            expires_in_seconds = 900
            listen_port = 10443
            public_port = 443
            server_name = "www.microsoft.com"
            target = None

        body = control.node_invitation_body(Args())
        self.assertEqual(body["displayName"], "Friend Mac")
        self.assertEqual(body["initialConfiguration"]["xray"], {
            "listenPort": 10443,
            "publicPort": 443,
            "serverNames": ["www.microsoft.com"],
            "target": "www.microsoft.com:443",
        })

    def test_admin_requests_stay_on_loopback_when_public_origin_is_remote(self):
        config = {
            "bindAddress": "127.0.0.1:8787",
            "publicOrigin": "https://control.example.test",
            "bootstrapToken": "secret-token",
        }

        class Response:
            status = 200

            def __enter__(self):
                return self

            def __exit__(self, *_):
                return False

            @staticmethod
            def read():
                return b'{"nodes":[]}'

        with patch.object(control, "urlopen", return_value=Response()) as request:
            self.assertEqual(control.admin_request(config, "GET", "/v1/admin/nodes"), {"nodes": []})
        self.assertEqual(request.call_args.args[0].full_url, "http://127.0.0.1:8787/v1/admin/nodes")
        self.assertNotIn("Idempotency-key", request.call_args.args[0].headers)

    def test_admin_mutation_uses_the_explicit_idempotency_key(self):
        config = {"bindAddress": "127.0.0.1:8787", "bootstrapToken": "secret-token"}

        class Response:
            def __enter__(self):
                return self

            def __exit__(self, *_):
                return False

            @staticmethod
            def read():
                return b'{"account":{"userId":"00000000-0000-0000-0000-000000000001"}}'

        with patch.object(control, "urlopen", return_value=Response()) as request:
            control.admin_request(
                config,
                "POST",
                "/v1/admin/accounts",
                {"displayName": "Friend"},
                "retry-key",
            )
        sent = request.call_args.args[0]
        self.assertEqual(sent.headers["Idempotency-key"], "retry-key")
        self.assertEqual(json.loads(sent.data), {"displayName": "Friend"})


if __name__ == "__main__":
    unittest.main()
