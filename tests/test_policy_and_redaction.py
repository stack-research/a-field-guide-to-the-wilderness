from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from wilderness.policy import PolicyValidationError, load_policy


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

    def write_policy(self, body: str, *, name: str = "policy.toml") -> Path:
        policy = self.cwd / name
        policy.write_text(textwrap.dedent(body).strip() + "\n", encoding="utf-8")
        return policy

    def assert_policy_error(self, body: str, message: str) -> None:
        policy = self.write_policy(body)
        with self.assertRaises(PolicyValidationError) as error:
            load_policy(str(policy))
        self.assertIn(message, str(error.exception))

    def test_unknown_top_level_policy_field_is_rejected(self) -> None:
        self.assert_policy_error(
            """
            manifest_free_fallback_enabled = true
            unknown_field = 1
            """,
            "unknown policy field",
        )

    def test_unknown_redaction_policy_field_is_rejected(self) -> None:
        self.assert_policy_error(
            """
            manifest_free_fallback_enabled = true

            [redaction]
            enabled = true
            strange = true
            """,
            "unknown redaction policy field",
        )

    def test_wrong_scalar_type_is_rejected(self) -> None:
        self.assert_policy_error(
            """
            manifest_free_fallback_enabled = "yes"
            """,
            "manifest_free_fallback_enabled must be a boolean",
        )

    def test_wrong_list_type_is_rejected(self) -> None:
        self.assert_policy_error(
            """
            suspicious_text_rule_packs = "custom.toml"
            """,
            "suspicious_text_rule_packs must be a list",
        )

    def test_empty_string_list_item_is_rejected(self) -> None:
        self.assert_policy_error(
            """
            suspicious_text_rule_packs = [""]
            """,
            "suspicious_text_rule_packs entries must be non-empty strings",
        )

    def test_invalid_enum_value_is_rejected(self) -> None:
        self.assert_policy_error(
            """
            manifest_free_fallback_scope = "anything"
            """,
            "manifest_free_fallback_scope must be",
        )

    def test_non_positive_numeric_limit_is_rejected(self) -> None:
        self.assert_policy_error(
            """
            suspicious_text_max_bytes = 0
            """,
            "suspicious_text_max_bytes must be a positive integer",
        )

    def test_duplicate_block_rule_ids_are_rejected(self) -> None:
        self.assert_policy_error(
            """
            suspicious_text_block_rule_ids = ["credential_request", "credential_request"]
            """,
            "suspicious_text_block_rule_ids entries must be unique",
        )

    def test_policy_check_accepts_valid_policy_and_lists_loaded_packs(self) -> None:
        pack = self.cwd / "custom.toml"
        pack.write_text(
            textwrap.dedent(
                """
                schema_version = 1

                [[rules]]
                id = "audit_log_leak"
                pattern = "leak the audit log"
                """
            ).strip()
            + "\n",
            encoding="utf-8",
        )
        policy = self.write_policy(
            """
            manifest_free_fallback_enabled = true
            suspicious_text_rule_packs = ["custom.toml"]
            """
        )

        result = self.run_cli("policy-check", str(policy))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("valid: True", result.stdout)
        self.assertIn(f"policy_path: {policy.resolve()}", result.stdout)
        self.assertIn(str(pack.resolve()), result.stdout)

    def test_policy_check_rejects_invalid_policy(self) -> None:
        policy = self.write_policy(
            """
            manifest_free_fallback_enabled = "yes"
            """
        )

        result = self.run_cli("policy-check", str(policy))
        self.assertEqual(result.returncode, 20)
        self.assertIn("policy error:", result.stderr)

    def test_policy_aware_commands_reject_same_invalid_policy_before_side_effects(self) -> None:
        sample = self.cwd / "sample.json"
        sample.write_text('{"ok": true}\n', encoding="utf-8")
        notes = self.cwd / "notes.txt"
        notes.write_text("plain text\n", encoding="utf-8")
        valid_policy = self.write_policy(
            """
            manifest_free_fallback_enabled = true
            """,
            name="valid-policy.toml",
        )
        invalid_policy = self.write_policy(
            """
            state_root = ".broken-state"
            manifest_free_fallback_enabled = "yes"
            """,
            name="invalid-policy.toml",
        )

        inspect = self.run_cli("inspect", str(sample), "--json", "--policy", str(valid_policy))
        self.assertEqual(inspect.returncode, 0, inspect.stderr)
        artifact = json.loads(inspect.stdout)
        report_path = self.cwd / ".wilderness" / "reports" / f"{artifact['inspection_id']}.json"
        history_path = Path(artifact["history_path"])
        history_before = history_path.read_text(encoding="utf-8")

        commands = [
            ("inspect", str(sample), "--policy", str(invalid_policy)),
            ("scan", str(sample), "--policy", str(invalid_policy)),
            ("promote", str(report_path), "--policy", str(invalid_policy)),
            ("manifest-check", str(sample), "--policy", str(invalid_policy)),
            ("suspicious-text-check", str(notes), "--policy", str(invalid_policy)),
        ]
        for args in commands:
            result = self.run_cli(*args)
            self.assertEqual(result.returncode, 20, (args, result.stdout, result.stderr))
            self.assertIn("policy error:", result.stderr, args)

        self.assertEqual(history_path.read_text(encoding="utf-8"), history_before)
        self.assertFalse((self.cwd / ".broken-state").exists())

    def test_control_characters_are_reported_safely(self) -> None:
        hostile_name = self.cwd / "ansi.txt"
        hostile_name.write_text("hello\x1b[31mworld", encoding="utf-8")
        policy = self.cwd / "policy.toml"
        policy.write_text("manifest_free_fallback_enabled = true\n", encoding="utf-8")

        inspect = self.run_cli("inspect", str(hostile_name), "--policy", str(policy))
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
                manifest_free_fallback_enabled = true
                redaction_required = false

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
        self.assertEqual(inspect.returncode, 0, inspect.stderr)
        artifact = json.loads(inspect.stdout)
        file_record = artifact["files"][0]
        self.assertTrue(file_record["redacted"])
        self.assertIn("redacted_sha256", file_record)
        self.assertTrue(artifact["provenance"]["redaction_applied"])
        self.assertTrue(artifact["redaction"]["enabled"])
        self.assertTrue(artifact["redaction"]["applied"])
        self.assertTrue(artifact["redaction"]["available"])
        redacted_path = Path(artifact["redaction"]["path"])
        self.assertTrue(redacted_path.exists())
        self.assertEqual(
            (redacted_path / "sample.txt").read_text(encoding="utf-8"),
            "token=<redacted>\npath=<redacted-path>\n",
        )

        report_path = self.cwd / ".wilderness" / "reports" / f"{artifact['inspection_id']}.json"
        report = self.run_cli("report", str(report_path))
        self.assertIn("redaction_applied: True", report.stdout)
        self.assertIn("redaction_available: True", report.stdout)
        self.assertIn("redaction_path:", report.stdout)

    def test_redaction_without_changes_does_not_create_derivative(self) -> None:
        sample = self.cwd / "sample.txt"
        sample.write_text("plain text only\n", encoding="utf-8")
        policy = self.cwd / "policy.toml"
        policy.write_text(
            textwrap.dedent(
                """
                manifest_free_fallback_enabled = true

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
        self.assertEqual(inspect.returncode, 0, inspect.stderr)
        artifact = json.loads(inspect.stdout)
        self.assertFalse(artifact["redaction"]["applied"])
        self.assertFalse(artifact["redaction"]["available"])
        self.assertIsNone(artifact["redaction"]["path"])
        self.assertIsNone(artifact["redaction"]["normalized_sha256"])
        self.assertFalse(artifact["files"][0]["redacted"])

    def test_redaction_required_still_blocks_when_no_changes_are_made(self) -> None:
        sample = self.cwd / "sample.txt"
        sample.write_text("plain text only\n", encoding="utf-8")
        policy = self.cwd / "policy.toml"
        policy.write_text(
            textwrap.dedent(
                """
                manifest_free_fallback_enabled = true
                redaction_required = true

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
        self.assertEqual(inspect.returncode, 10, inspect.stderr)
        artifact = json.loads(inspect.stdout)
        self.assertFalse(artifact["promotion"]["eligible"])
        self.assertIn(
            "redaction required by policy but no changes were applied",
            artifact["promotion"]["blocking_reasons"],
        )
        self.assertFalse(artifact["redaction"]["available"])

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
        policy.write_text(
            "discard_retention_enabled = true\nmanifest_free_fallback_enabled = true\n",
            encoding="utf-8",
        )

        inspect = self.run_cli("inspect", str(sample), "--json", "--policy", str(policy))
        self.assertEqual(inspect.returncode, 0, inspect.stderr)
        artifact = json.loads(inspect.stdout)
        self.assertFalse(artifact["discard"]["retained"])
        self.assertFalse((self.cwd / ".wilderness" / "discard" / artifact["inspection_id"]).exists())


if __name__ == "__main__":
    unittest.main()
