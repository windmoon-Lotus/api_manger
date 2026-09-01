import unittest
from types import SimpleNamespace
from unittest.mock import patch

from apiAnalysis.tool.execution_contract import (
    ExecutionContext,
    create_execution_snapshot,
    record_execution_result,
)


class ExecutionContractTests(unittest.TestCase):
    def test_anonymous_context_rejects_account_binding(self):
        with self.assertRaises(ValueError):
            ExecutionContext(project_id="p1", auth_mode="anonymous", account_id="owner").validate()

    def test_context_produces_explicit_run_fields(self):
        context = ExecutionContext(
            project_id="p1", env_id="formal", account_id="owner", auth_mode="account",
            auth_provider_id="local_json", auth_context_ref="owner-current",
            adapter_id="authenticated_snapshot_batch", adapter_version="2",
            plan_version="v3", plan_sha256="ABC",
        )
        fields = context.run_fields()
        self.assertEqual(fields["project_id"], "p1")
        self.assertEqual(fields["auth_mode"], "account")
        self.assertEqual(fields["auth_provider_id"], "local_json")
        self.assertEqual(fields["plan_sha256"], "ABC")

    @patch("apiAnalysis.tool.execution_contract.create_request_snapshot")
    def test_snapshot_creation_calls_existing_composer(self, create_snapshot):
        context = ExecutionContext(
            project_id="p1", env_id="formal", auth_mode="anonymous",
            plan_version="v1", plan_sha256="HASH",
        )
        create_execution_snapshot(42, context)
        create_snapshot.assert_called_once_with(
            42, account_id=None, env_id="formal", project_id="p1",
            auth_mode="anonymous", source="execution_plan",
            execution_metadata={
                "plan_version": "v1", "plan_sha256": "HASH",
                "adapter_id": "snapshot_batch", "adapter_version": "1",
                "auth_provider_id": "", "auth_context_ref": "",
                "auth_profile_revision_id": "", "auth_realm_revision_id": "",
                "auth_adapter_version_id": "",
            },
        )

    def test_account_context_requires_explicit_provider_binding(self):
        with self.assertRaises(ValueError):
            ExecutionContext(
                project_id="p1", env_id="formal", account_id="owner", auth_mode="account",
            ).validate()

    def test_matrix_context_has_no_single_run_account_binding(self):
        context = ExecutionContext(
            project_id="p1", env_id="formal", auth_mode="matrix",
            adapter_id="authorization_matrix",
        )
        self.assertEqual(context.run_fields()["auth_mode"], "matrix")
        with self.assertRaisesRegex(ValueError, "per case"):
            ExecutionContext(
                project_id="p1", env_id="formal", auth_mode="matrix",
                account_id="not-a-run-level-owner",
                adapter_id="authorization_matrix",
            ).validate()

    @patch("apiAnalysis.tool.execution_contract.security_test_result")
    def test_result_write_projects_verdict_to_outcome_class(self, result_model):
        stored = result_model.return_value
        run = SimpleNamespace(
            id="run-1",
            project_id="p1",
            env_id="test",
            account_id="owner",
            auth_mode="account",
            auth_provider_id="auth_recipe",
            auth_context_ref="profile-rev-1",
            evidence_ref="",
            expires_at=None,
        )
        snapshot = SimpleNamespace(
            id="snapshot-1",
            pathid=42,
            method="GET",
        )

        result = record_execution_result(
            run,
            snapshot,
            case_name="GET /resource",
            check_type="authenticated_snapshot_batch",
            verdict="not_evaluable",
        )

        self.assertIs(result, stored)
        self.assertEqual(
            result_model.call_args.kwargs["outcome_class"],
            "blocked",
        )
        stored.save.assert_called_once_with(force_insert=False)


if __name__ == "__main__":
    unittest.main()
