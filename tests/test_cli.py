from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile


ROOT = Path(__file__).resolve().parents[1]


class WildernessCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.cwd = Path(self.tempdir.name)
        self.env = dict(**{"PYTHONPATH": str(ROOT / "src")})

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def run_cli(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-m", "wilderness.cli", *args],
            cwd=self.cwd,
            env=self.env,
            text=True,
            capture_output=True,
        )

    def test_benign_file_can_be_promoted(self) -> None:
        sample = ROOT / "data" / "benign" / "sample.json"
        copied = self.cwd / "sample.json"
        shutil.copy2(sample, copied)

        inspect = self.run_cli("inspect", str(copied))
        self.assertEqual(inspect.returncode, 0, inspect.stderr)
        report_path = Path(
            inspect.stdout.strip().split("report_path: ", 1)[1]
        )
        artifact = json.loads(report_path.read_text(encoding="utf-8"))
        self.assertEqual(artifact["status"], "shelter")
        self.assertTrue(artifact["promotion"]["eligible"])

        promote = self.run_cli("promote", str(report_path))
        self.assertEqual(promote.returncode, 0, promote.stdout + promote.stderr)
        promoted = json.loads(report_path.read_text(encoding="utf-8"))
        self.assertEqual(promoted["status"], "safe_camp")

    def test_archive_traversal_is_blocked(self) -> None:
        bundle = self.cwd / "traversal.zip"
        with zipfile.ZipFile(bundle, "w") as archive:
            archive.writestr("../escape.txt", "nope")
            archive.writestr("ok.txt", "still here")

        inspect = self.run_cli("inspect", str(bundle), "--json")
        self.assertEqual(inspect.returncode, 20)
        artifact = json.loads(inspect.stdout)
        families = {finding["family"] for finding in artifact["findings"]}
        self.assertIn("archive_escape", families)
        self.assertEqual(artifact["status"], "discard")

    def test_binary_payload_in_text_name_is_flagged(self) -> None:
        bundle = self.cwd / "binary.zip"
        with zipfile.ZipFile(bundle, "w") as archive:
            archive.writestr("notes.txt", b"\x00\x01\x02\x03")

        inspect = self.run_cli("inspect", str(bundle), "--json")
        artifact = json.loads(inspect.stdout)
        families = {finding["family"] for finding in artifact["findings"]}
        self.assertIn("binary_payload", families)

    def test_manifest_check_surfaces_invalid_manifest(self) -> None:
        manifest = self.cwd / "manifest.json"
        manifest.write_text("{not json", encoding="utf-8")
        result = self.run_cli("manifest-check", str(manifest))
        self.assertEqual(result.returncode, 20)
        self.assertIn("valid: False", result.stdout)


if __name__ == "__main__":
    unittest.main()
