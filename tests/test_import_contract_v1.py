import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from apiAnalysis.import_pipeline import ImportRequest, execute_import


class ImportContractV1Tests(unittest.TestCase):
    def test_document_import_requires_explicit_project(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "openapi.json"
            source.write_text("{}", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "project_id"):
                ImportRequest("openapi", str(source)).validate()

    @patch("apiAnalysis.import_pipeline.finish_import_run")
    @patch("apiAnalysis.import_pipeline.RequestObservation")
    @patch("apiAnalysis.import_pipeline.raw_data")
    @patch("apiAnalysis.import_pipeline.process_import_batch")
    @patch("apiAnalysis.import_pipeline._dispatch_import")
    @patch("apiAnalysis.import_pipeline.start_import_run")
    @patch("apiAnalysis.import_pipeline.ensure_source_binding")
    @patch("apiAnalysis.import_pipeline.ensure_data_source")
    def test_success_owns_one_lifecycle_and_normalizes_outcome(
        self, ensure_source, ensure_binding, start_run, dispatch, process_batch,
        raw_model, observation_model, finish_run,
    ):
        ensure_source.return_value = SimpleNamespace(
            data_source_id="source-1", external_id="external-1", name="Public API",
        )
        run = SimpleNamespace(import_run_id="import-1", status="running")
        start_run.return_value = run
        dispatch.return_value = ["507f1f77bcf86cd799439011", "507f1f77bcf86cd799439011"]
        process_batch.return_value = {"skipped": False}
        raw_model.objects.return_value.distinct.return_value = ["project-1"]
        observation_model.objects.return_value.count.return_value = 2
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "api.json"
            source.write_text("{}", encoding="utf-8")
            outcome = execute_import(ImportRequest(
                source_type="openapi",
                source_path=str(source),
                project_id="project-1",
                env_id="test",
                source_id="external-1",
                source_name="Public API",
            ))

        self.assertEqual(outcome.raw_ids, ["507f1f77bcf86cd799439011"])
        self.assertEqual(outcome.summary["contract_version"], "import.v1")
        self.assertEqual(outcome.summary["asset_count"], 1)
        start_run.assert_called_once()
        finish_run.assert_called_once_with(run, summary=outcome.summary)
        ensure_binding.assert_called_once_with("source-1", "project-1", env_id="test")

    @patch("apiAnalysis.import_pipeline.finish_import_run")
    @patch("apiAnalysis.import_pipeline._dispatch_import", side_effect=RuntimeError("parse failed"))
    @patch("apiAnalysis.import_pipeline.start_import_run")
    @patch("apiAnalysis.import_pipeline.ensure_source_binding")
    @patch("apiAnalysis.import_pipeline.ensure_data_source")
    def test_failure_finishes_the_same_run_once(
        self, ensure_source, _ensure_binding, start_run, _dispatch, finish_run,
    ):
        ensure_source.return_value = SimpleNamespace(
            data_source_id="source-1", external_id="external-1", name="Public API",
        )
        run = SimpleNamespace(import_run_id="import-1", status="running")
        start_run.return_value = run
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "api.json"
            source.write_text("{}", encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "parse failed"):
                execute_import(ImportRequest(
                    source_type="openapi",
                    source_path=str(source),
                    project_id="project-1",
                    source_id="external-1",
                ))
        start_run.assert_called_once()
        finish_run.assert_called_once()
        self.assertEqual(finish_run.call_args.kwargs["error"], "parse failed")


if __name__ == "__main__":
    unittest.main()
