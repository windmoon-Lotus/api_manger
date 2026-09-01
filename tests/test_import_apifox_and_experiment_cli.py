import io
import json
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from tools.import_apifox_and_experiment import main


BASE_ARGS = [
    "--details-dir", ".",
    "--source-id", "apifox-source-a",
    "--project-id", "project-a",
    "--env-id", "test",
    "--profile-revision-id", "profile-revision-a",
]


class ImportApifoxAndExperimentCliTests(unittest.TestCase):
    @patch("tools.import_apifox_and_experiment.apifox_experiment_report")
    @patch("tools.import_apifox_and_experiment.build_apifox_experiment_plan")
    @patch("tools.import_apifox_and_experiment.execute_import")
    @patch("tools.import_apifox_and_experiment._ensure_mongo_connection")
    def test_default_imports_then_returns_dry_run_plan(
        self, _connect, execute_import, build_plan, report,
    ):
        execute_import.return_value = SimpleNamespace(
            run=SimpleNamespace(import_run_id="import-a", status="done"),
            summary={"asset_count": 4, "parameter_analysis": False},
        )
        build_plan.return_value = SimpleNamespace(plan_sha256="a" * 64)
        report.return_value = {
            "schema_version": "apifox-test-experiment.v1",
            "mode": "dry_run",
            "business_network_requests": 0,
        }
        output = io.StringIO()
        with patch("tools.import_apifox_and_experiment.sys.stdout", output):
            code = main(BASE_ARGS)

        self.assertEqual(code, 0)
        request = execute_import.call_args.args[0]
        self.assertEqual(request.source_type, "apifox")
        self.assertEqual(request.project_id, "project-a")
        self.assertEqual(build_plan.call_args.kwargs["import_run_id"], "import-a")
        payload = json.loads(output.getvalue())
        self.assertEqual(payload["import"]["asset_count"], 4)
        self.assertEqual(payload["experiment"]["mode"], "dry_run")

    @patch("tools.import_apifox_and_experiment.enqueue_apifox_experiment")
    @patch("tools.import_apifox_and_experiment.build_apifox_experiment_plan")
    @patch("tools.import_apifox_and_experiment.execute_import")
    @patch("tools.import_apifox_and_experiment._ensure_mongo_connection")
    def test_enqueue_uses_same_import_plan_hash_and_concurrency(
        self, _connect, execute_import, build_plan, enqueue,
    ):
        execute_import.return_value = SimpleNamespace(
            run=SimpleNamespace(import_run_id="import-a", status="done"),
            summary={"asset_count": 2},
        )
        plan = SimpleNamespace(plan_sha256="b" * 64)
        build_plan.return_value = plan
        enqueue.return_value = {"status": "queued", "business_network_requests": 0}
        output = io.StringIO()
        with patch("tools.import_apifox_and_experiment.sys.stdout", output):
            code = main(BASE_ARGS + [
                "--enqueue", "--max-workers", "12", "--per-host-workers", "3",
            ])

        self.assertEqual(code, 0)
        self.assertIs(enqueue.call_args.args[0], plan)
        self.assertEqual(enqueue.call_args.args[1], "b" * 64)
        self.assertEqual(enqueue.call_args.kwargs["max_workers"], 12)
        self.assertEqual(enqueue.call_args.kwargs["per_host_workers"], 3)


if __name__ == "__main__":
    unittest.main()
