import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch
from bson import ObjectId

from apiAnalysis.import_pipeline import (
    ImportRequest,
    _dispatch_import,
    normalize_raw_ids,
    process_import_batch,
)
from apiAnalysis.db.save import data_generate_openapi, data_generate_postman
from apiAnalysis.rule.analysis import analysis


class ImportPipelineTests(unittest.TestCase):
    @patch("apiAnalysis.rule.analysis.raw_data")
    def test_classifier_scopes_raw_data_by_primary_key(self, raw_model):
        raw_model.objects.return_value = []
        raw_id = ObjectId()

        analysis().classify_raw_data(raw_ids=[str(raw_id)])

        raw_model.objects.assert_called_once_with(pk__in=[raw_id])

    @patch("apiAnalysis.import_pipeline.import_apifox_details")
    @patch("apiAnalysis.import_pipeline.raw_data")
    def test_apifox_dispatch_reads_touched_primary_keys_via_pk(
        self, raw_model, import_details,
    ):
        import_details.return_value = {"pathids": [11, 12]}
        raw_model.objects.return_value.scalar.return_value = ["raw-a", "raw-b"]
        request = ImportRequest(
            source_type="apifox",
            source_path="details",
            project_id="project-a",
            env_id="default",
            source_id="2127251",
        )

        result = _dispatch_import(
            request,
            SimpleNamespace(import_run_id="import-a"),
            SimpleNamespace(external_id="2127251", data_source_id="source-a"),
        )

        self.assertEqual(result, ["raw-a", "raw-b"])
        raw_model.objects.assert_called_once_with(ptah_id__in=[11, 12])
        raw_model.objects.return_value.scalar.assert_called_once_with("pk")

    def test_normalize_raw_ids_deduplicates_and_preserves_order(self):
        self.assertEqual(normalize_raw_ids(["a", "b", "a", None, ""]), ["a", "b"])

    @patch("apiAnalysis.import_pipeline.analysis")
    @patch("apiAnalysis.import_pipeline.parameter_date_mongodb")
    @patch("apiAnalysis.import_pipeline.parameter_disassemble_mongodb")
    def test_empty_import_never_runs_unbounded_analysis(self, disassemble, summarize, analysis_factory):
        summary = process_import_batch([], run_parameters=True)

        self.assertTrue(summary["skipped"])
        self.assertEqual(summary["asset_count"], 0)
        analysis_factory.assert_not_called()
        disassemble.assert_not_called()
        summarize.assert_not_called()

    @patch("apiAnalysis.import_pipeline.pathids_for_raw_ids", return_value=[])
    @patch("apiAnalysis.import_pipeline.parameter_date_mongodb")
    @patch("apiAnalysis.import_pipeline.parameter_disassemble_mongodb")
    @patch("apiAnalysis.import_pipeline.analysis")
    def test_unresolved_batch_never_falls_back_to_global_parameter_work(
        self, analysis_factory, disassemble, summarize, pathids
    ):
        worker = MagicMock()
        analysis_factory.return_value = worker

        summary = process_import_batch(
            ["507f1f77bcf86cd799439011"], run_parameters=True
        )

        self.assertTrue(summary["scope_warning"])
        worker.classify_raw_data.assert_called_once()
        disassemble.assert_not_called()
        summarize.assert_not_called()
        worker.infer_weak_relations.assert_not_called()

    @patch("apiAnalysis.import_pipeline.pathids_for_raw_ids", return_value=[11, 12])
    @patch("apiAnalysis.import_pipeline.parameter_date_mongodb")
    @patch("apiAnalysis.import_pipeline.parameter_disassemble_mongodb")
    @patch("apiAnalysis.import_pipeline.analysis")
    def test_batch_scope_is_forwarded_to_each_incremental_stage(
        self, analysis_factory, disassemble, summarize, pathids
    ):
        worker = MagicMock()
        analysis_factory.return_value = worker

        summary = process_import_batch(
            ["507f1f77bcf86cd799439011", "507f1f77bcf86cd799439012"],
            account_id="account-a",
            run_parameters=True,
        )

        self.assertFalse(summary["skipped"])
        self.assertEqual(summary["pathids"], [11, 12])
        worker.classify_raw_data.assert_called_once_with(raw_ids=summary["raw_ids"])
        disassemble.assert_called_once_with(raw_ids=summary["raw_ids"])
        summarize.assert_called_once_with(raw_ids=summary["raw_ids"])
        worker.parameter_archive.assert_called_once_with(
            pathids=[11, 12],
            account_id="account-a",
            project_id="",
            env_id="",
        )
        worker.infer_weak_relations.assert_called_once_with(pathids=[11, 12])
        worker.verify_weak_relations.assert_not_called()
        worker.build_request_compose.assert_called_once_with(pathids=[11, 12])

    @patch("apiAnalysis.rule.analysis.parameter_archive")
    @patch("apiAnalysis.rule.analysis.parameter_data")
    def test_parameter_archive_is_offline_and_strictly_batch_scoped(
        self, parameter_model, archive_model,
    ):
        parameter_model.objects.return_value = [SimpleNamespace(
            parameter="orders[].id",
            parameterid=7,
            req_pathid=[11, 999],
            res_pathid=[12],
            req_value=["order-1", {"id": "order-2"}],
            res_value=["order-1"],
        )]
        record = MagicMock()
        archive_model.objects.return_value.first.return_value = record

        count = analysis().parameter_archive(
            pathids=[11, 12], account_id="account-a",
            project_id="project-a", env_id="preprod",
        )

        self.assertEqual(count, 1)
        archive_model.objects.assert_called_once_with(
            parameter="id", account_id="account-a",
            project_id="project-a", env_id="preprod",
        )
        self.assertEqual(record.parameterid, [7])
        self.assertEqual(record.req_pathid, [11])
        self.assertEqual(record.res_pathid, [12])
        self.assertEqual(record.modificator, "offline_import_batch_v1")
        record.save.assert_called_once_with()

    @patch("apiAnalysis.rule.analysis.parameter_data")
    def test_parameter_archive_rejects_unbounded_scope(self, parameter_model):
        with self.assertRaisesRegex(ValueError, "non-empty pathids"):
            analysis().parameter_archive(pathids=[])
        parameter_model.objects.assert_not_called()

    @patch("apiAnalysis.import_pipeline.preprocess_relations")
    @patch("apiAnalysis.import_pipeline.discover_project_relations")
    @patch("apiAnalysis.import_pipeline.ProjectAssetLink")
    @patch("apiAnalysis.import_pipeline.raw_data")
    @patch("apiAnalysis.import_pipeline.pathids_for_raw_ids", return_value=[21, 22])
    @patch("apiAnalysis.import_pipeline.parameter_date_mongodb")
    @patch("apiAnalysis.import_pipeline.parameter_disassemble_mongodb")
    @patch("apiAnalysis.import_pipeline.analysis")
    def test_project_import_incrementally_rediscovers_only_touched_relationships(
        self, analysis_factory, disassemble, summarize, pathids, raw_model,
        asset_link, discover, preprocess,
    ):
        worker = MagicMock()
        analysis_factory.return_value = worker

        summary = process_import_batch(
            ["507f1f77bcf86cd799439011"],
            project_id="project-a", env_id="preprod",
            run_parameters=True,
        )

        self.assertEqual(summary["project_id"], "project-a")
        discover.assert_called_once_with("project-a", changed_pathids=[21, 22])
        preprocess.assert_called_once_with(
            "project-a", env_id="preprod", pathids=[21, 22], limit=20,
        )
        self.assertEqual(asset_link.objects.call_count, 2)

    @patch("apiAnalysis.db.save._ensure_raw_data")
    def test_openapi_import_returns_the_touched_asset_ids(self, ensure_asset):
        ensure_asset.return_value = MagicMock(id="asset-openapi-1")
        document = {"openapi": "3.0.0", "paths": {"/ping": {"get": {"responses": {}}}}}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "api.json"
            path.write_text(json.dumps(document), encoding="utf-8")
            self.assertEqual(data_generate_openapi(str(path)), ["asset-openapi-1"])

    @patch("apiAnalysis.db.save.save_request_sample")
    @patch("apiAnalysis.db.save.raw_data")
    def test_postman_import_returns_existing_touched_asset_ids(self, raw_model, save_sample):
        existing = MagicMock()
        existing.id = "asset-postman-1"
        existing.url = "https://example.test/ping"
        existing.domain = "example.test"
        existing.query = {}
        existing.headers = {}
        existing.Max_records = 10
        existing.asset_kind = "concrete"
        existing.raw_req = []
        raw_model.objects.return_value.first.return_value = existing
        document = {
            "item": [{"request": {"method": "GET", "url": "https://example.test/ping"}}]
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "postman.json"
            path.write_text(json.dumps(document), encoding="utf-8")
            self.assertEqual(data_generate_postman(str(path)), ["asset-postman-1"])
        existing.save.assert_called_once()


if __name__ == "__main__":
    unittest.main()
