import ast
import unittest
from pathlib import Path
from unittest.mock import patch

from apiAnalysis.maintenance import run_maintenance_once


ROOT = Path(__file__).resolve().parents[1]


class ProcessBoundaryTests(unittest.TestCase):
    def test_retired_workspace_and_duplicate_execution_runtimes_are_absent(self):
        retired = (
            "apiAnalysis/core/lib.py",
            "apiAnalysis/core/jobs.py",
            "apiAnalysis/core/flow.py",
            "apiAnalysis/rule/privilege.py",
            "apiAnalysis/tool/base_adapter.py",
            "apiAnalysis/tool/adapters/builtin_adapters.py",
        )
        for relative in retired:
            self.assertFalse((ROOT / relative).exists(), relative)

        import_source = (ROOT / "apiAnalysis/import_pipeline.py").read_text(
            encoding="utf-8",
        )
        analysis_source = (ROOT / "apiAnalysis/rule/analysis.py").read_text(
            encoding="utf-8",
        )
        self.assertNotIn("verify_weak_relations(", import_source)
        self.assertNotIn("Workspace", analysis_source)
        self.assertNotIn("deal_request", analysis_source)

        asset_source = (ROOT / "apiAnalysis/web/views_api_assets.py").read_text(
            encoding="utf-8",
        )
        self.assertNotIn("vuln_record", asset_source)
        self.assertNotIn("batch_link_vuln", asset_source)

        data_source_source = (
            ROOT / "apiAnalysis/web/views_data_source.py"
        ).read_text(encoding="utf-8")
        self.assertNotIn('@bp_web.route("/import-data"', data_source_source)

    def test_web_launchers_do_not_embed_workers_or_schedulers(self):
        for relative in ("run_web.py", "tools/run_web_server.py"):
            source = (ROOT / relative).read_text(encoding="utf-8")
            ast.parse(source)
            self.assertNotIn("ExecutionWorker", source)
            self.assertNotIn("ParameterRelationAnalysisWorker", source)
            self.assertNotIn("Scheduler", source)
            self.assertNotIn("threading", source)

    def test_application_factory_has_no_background_start_calls(self):
        source = (ROOT / "apiAnalysis/__init__.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        starts = [
            node for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in {"start", "run_forever"}
        ]
        self.assertEqual(starts, [])

    @patch("apiAnalysis.maintenance.ParameterRelationAnalysisWorker")
    @patch("apiAnalysis.maintenance.recover_expired_executions")
    @patch("apiAnalysis.maintenance.evaluate_completed_finding_retests")
    def test_maintenance_contract_recovers_all_durable_workflows(
        self, evaluate_retests, recover, worker_cls,
    ):
        recover.return_value = {"recovered": 2}
        worker_cls.return_value.recover_abandoned.return_value = 3
        evaluate_retests.return_value = 1
        self.assertEqual(run_maintenance_once("snapshot"), {
            "execution": {"recovered": 2},
            "relation_analysis_requeued": 3,
            "finding_retests_evaluated": 1,
        })
        recover.assert_called_once_with(queue_name="snapshot")


if __name__ == "__main__":
    unittest.main()
