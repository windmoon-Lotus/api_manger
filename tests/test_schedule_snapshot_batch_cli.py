"""CLI contract tests for tools/schedule_snapshot_batch.py.

These tests are intentionally dependency-free: they run the CLI --help and
statically verify that recipe-auth pinned version arguments are wired into
ExecutionContext. Live Mongo/worker behaviour is covered by the integration
suites and by the manual end-to-end execution.
"""
import subprocess
import sys
import unittest
from pathlib import Path

from apiAnalysis.tool.execution_contract import ExecutionContext

ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "tools" / "schedule_snapshot_batch.py"

PINNED_ARGS = (
    "--auth-profile-revision-id",
    "--auth-realm-revision-id",
    "--auth-adapter-version-id",
)


class ScheduleSnapshotBatchCliTests(unittest.TestCase):
    def test_cli_help_exposes_recipe_auth_pinned_version_args(self):
        proc = subprocess.run(
            [sys.executable, str(CLI), "--help"],
            capture_output=True, text=True,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        for flag in PINNED_ARGS:
            self.assertIn(flag, proc.stdout)

    def test_cli_wires_pinned_versions_into_execution_context(self):
        source = CLI.read_text(encoding="utf-8")
        for field in ("auth_profile_revision_id", "auth_realm_revision_id",
                      "auth_adapter_version_id"):
            self.assertIn(
                "{} = args.{}".format(field, field).replace(" = ", "="),
                source,
                "ExecutionContext field {} must be populated from the CLI arg".format(field),
            )

    def test_recipe_auth_context_requires_all_pinned_versions(self):
        incomplete = ExecutionContext(
            project_id="p1", env_id="e", account_id="owner",
            auth_mode="account", auth_provider_id="auth_recipe",
            auth_context_ref="pr-1",
            auth_profile_revision_id="pr-1",
        )
        with self.assertRaises(ValueError):
            incomplete.validate()

        complete = ExecutionContext(
            project_id="p1", env_id="e", account_id="owner",
            auth_mode="account", auth_provider_id="auth_recipe",
            auth_context_ref="pr-1",
            auth_profile_revision_id="pr-1",
            auth_realm_revision_id="rr-1",
            auth_adapter_version_id="av-1",
        )
        complete.validate()


if __name__ == "__main__":
    unittest.main()
