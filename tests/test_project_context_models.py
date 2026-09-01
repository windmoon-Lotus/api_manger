import unittest
from types import SimpleNamespace

from apiAnalysis.db.collection import (
    ImportRun, parameter_relation_analysis_run, request_snapshot, security_test_run,
)
from apiAnalysis.project_context import asset_context, data_source_identity
from apiAnalysis.tool.compose_request import payload_to_snapshot_data


class ProjectContextModelTests(unittest.TestCase):
    def test_asset_context_prefers_explicit_fields_and_supports_legacy_meta(self):
        explicit = SimpleNamespace(project_id="p1", env_id="formal", import_run_id="i1", source_meta={"internal_project_id": "legacy"})
        self.assertEqual(asset_context(explicit), {"project_id": "p1", "env_id": "formal", "import_run_id": "i1"})
        legacy = SimpleNamespace(source_meta={"internal_project_id": "p2", "env_id": "beta", "import_run_id": "i2"})
        self.assertEqual(asset_context(legacy), {"project_id": "p2", "env_id": "beta", "import_run_id": "i2"})

    def test_snapshot_payload_keeps_execution_context(self):
        data = payload_to_snapshot_data({
            "pathid": 1, "source": "test", "project_id": "p1", "import_run_id": "i1",
            "env_id": "formal", "account_id": "owner", "auth_mode": "anonymous",
            "method": "GET", "url": "https://api.example.com/x", "rendered_url": "https://api.example.com/x",
            "metadata": {"plan_version": "v1", "plan_sha256": "ABC", "adapter_id": "batch", "adapter_version": "1"},
        })
        self.assertEqual(data["project_id"], "p1")
        self.assertEqual(data["auth_mode"], "anonymous")
        self.assertEqual(data["plan_version"], "v1")
        snapshot = request_snapshot(**data)
        self.assertEqual(snapshot.adapter_id, "batch")

    def test_security_run_has_explicit_orchestration_fields(self):
        run = security_test_run(
            name="r", check_type="unauth", project_id="p1", env_id="formal",
            auth_mode="anonymous", adapter_id="snapshot_batch", plan_version="v1",
        )
        self.assertEqual(run.project_id, "p1")
        self.assertEqual(run.auth_mode, "anonymous")

    def test_mixed_source_import_run_can_start_unassigned(self):
        run = ImportRun(import_run_id="i1", source_type="har", project_id="", project_ids=[])
        self.assertEqual(run.project_id, "")
        self.assertEqual(run.project_ids, [])

    def test_offline_analysis_run_has_rule_provenance_and_resume_cursor(self):
        run = parameter_relation_analysis_run(
            project_id="p1", env_id="test",
            analysis_version="unified-offline-rules.p1.v1",
            rule_bundle_sha256="a" * 64, input_watermark_sha256="b" * 64,
            cursor_phase="rule_persistence", cursor_key="role:1:id",
        )
        self.assertEqual(run.analysis_version, "unified-offline-rules.p1.v1")
        self.assertEqual(run.cursor_phase, "rule_persistence")

    def test_data_source_identity_is_stable_and_type_scoped(self):
        first = data_source_identity("OpenAPI", "orders-v1")
        self.assertEqual(first, data_source_identity("openapi", "orders-v1"))
        self.assertNotEqual(first, data_source_identity("postman", "orders-v1"))
        self.assertTrue(first.startswith("source-"))


if __name__ == "__main__":
    unittest.main()
