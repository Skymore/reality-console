from __future__ import annotations

import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest import mock


SCRIPT = Path(__file__).parents[1] / "acquire-sidecar.py"
SPEC = importlib.util.spec_from_file_location("acquire_sidecar", SCRIPT)
assert SPEC and SPEC.loader
acquire_sidecar = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(acquire_sidecar)


class AcquireSidecarTests(unittest.TestCase):
    def test_install_stages_replace_on_destination_drive(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source_dir = root / "download-drive"
            output_dir = root / "workspace-drive"
            source_dir.mkdir()
            output_dir.mkdir()
            source = source_dir / "xray.exe"
            output = output_dir / "xray.exe"
            source.write_bytes(b"verified xray")
            real_replace = acquire_sidecar.os.replace

            def same_directory_replace(staged: Path, destination: Path) -> None:
                self.assertEqual(Path(staged).parent, Path(destination).parent)
                real_replace(staged, destination)

            with mock.patch.object(acquire_sidecar.os, "replace", same_directory_replace):
                acquire_sidecar.install_verified_binary(source, output)

            self.assertEqual(output.read_bytes(), b"verified xray")
            self.assertEqual(source.read_bytes(), b"verified xray")
            self.assertEqual(list(output_dir.iterdir()), [output])


if __name__ == "__main__":
    unittest.main()
