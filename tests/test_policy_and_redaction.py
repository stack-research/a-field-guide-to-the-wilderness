from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import unittest


ROOT = Path(__file__).resolve().parents[1]


class WildernessPolicyTests(unittest.TestCase):
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

    def test_control_characters_are_reported_safely(self) -> None:
        hostile_name = self.cwd / "ansi.txt"
        hostile_name.write_text("hello\x1b[31mworld", encoding="utf-8")

        inspect = self.run_cli("inspect", str(hostile_name))
        self.assertEqual(inspect.returncode, 0)
        self.assertIn("\\x1b", inspect.stdout)

    def test_redaction_records_redacted_hash(self) -> None:
        sample = self.cwd / "sample.txt"
        sample.write_text(
            "token=abc123\npath=/Users/tester/project/file.txt\n",
            encoding="utf-8",
        )
        policy = self.cwd / "policy.toml"
        policy.write_text(
            textwrap.dedent(
                """
                [redaction]
                enabled = true
                redact_paths = true
                redact_secrets = true
                """
            ).strip()
            + "\n",
            encoding="utf-8",
        )

        inspect = self.run_cli("inspect", str(sample), "--json", "--policy", str(policy))
        artifact = json.loads(inspect.stdout)
        file_record = artifact["files"][0]
        self.assertIn("redacted_sha256", file_record)
        self.assertTrue(artifact["provenance"]["redaction_applied"])

    def test_nested_archive_depth_is_enforced(self) -> None:
        import zipfile

        inner = self.cwd / "inner.zip"
        with zipfile.ZipFile(inner, "w") as archive:
            archive.writestr("nested.txt", "hi")

        outer = self.cwd / "outer.zip"
        with zipfile.ZipFile(outer, "w") as archive:
            archive.write(inner, arcname="inner.zip")

        policy = self.cwd / "policy.toml"
        policy.write_text("max_nested_archive_depth = 0\n", encoding="utf-8")

        inspect = self.run_cli("inspect", str(outer), "--json", "--policy", str(policy))
        self.assertEqual(inspect.returncode, 20)
        artifact = json.loads(inspect.stdout)
        self.assertEqual(artifact["status"], "discard")
        self.assertTrue(
            any(
                finding["family"] == "nested_archive" and finding["severity"] == "severe"
                for finding in artifact["findings"]
            )
        )

    def test_benign_artifact_does_not_create_discard_copy_when_retention_enabled(self) -> None:
        sample = self.cwd / "sample.json"
        sample.write_text('{"ok": true}\n', encoding="utf-8")
        policy = self.cwd / "policy.toml"
        policy.write_text("discard_retention_enabled = true\n", encoding="utf-8")

        inspect = self.run_cli("inspect", str(sample), "--json", "--policy", str(policy))
        self.assertEqual(inspect.returncode, 0, inspect.stderr)
        artifact = json.loads(inspect.stdout)
        self.assertFalse(artifact["discard"]["retained"])
        self.assertFalse((self.cwd / ".wilderness" / "discard" / artifact["inspection_id"]).exists())


if __name__ == "__main__":
    unittest.main()
