import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from apiAnalysis.tool.apifox_importer import import_apifox_detail_file, import_apifox_details


class ApifoxProjectImportContextTests(unittest.TestCase):
    @patch("apiAnalysis.tool.apifox_importer._import_response_params", return_value=0)
    @patch("apiAnalysis.tool.apifox_importer._import_request_params", return_value=0)
    @patch("apiAnalysis.tool.apifox_importer._upsert_raw")
    def test_webdav_methods_are_imported(self, upsert_raw, _request_params, _response_params):
        upsert_raw.return_value = SimpleNamespace(ptah_id=7, method="", path="/webdav")
        with tempfile.TemporaryDirectory() as tmp:
            for method in ("PROPFIND", "COPY", "MOVE", "LOCK", "UNLOCK"):
                with self.subTest(method=method):
                    upsert_raw.return_value.method = method
                    path = Path(tmp) / f"{method}.json"
                    path.write_text(json.dumps({
                        "data": {
                            "id": method,
                            "projectId": 1001,
                            "type": "http",
                            "method": method.lower(),
                            "path": "/webdav",
                        }
                    }), encoding="utf-8")
                    result = import_apifox_detail_file(path, base_url="https://api.example.com")
                    self.assertTrue(result["imported"])
                    self.assertEqual(result["method"], method)

    @patch("apiAnalysis.tool.apifox_importer.finish_import_run")
    @patch("apiAnalysis.tool.apifox_importer.start_import_run")
    @patch("apiAnalysis.tool.apifox_importer.ensure_project_for_source")
    @patch("apiAnalysis.tool.apifox_importer.import_apifox_detail_file")
    def test_batch_auto_binds_project_and_import_run(self, import_file, ensure_project, start_run, finish_run):
        ensure_project.return_value = {"project_id": "internal-p1"}
        start_run.return_value = SimpleNamespace(import_run_id="import-r1")
        import_file.return_value = {"imported": True, "pathid": 7, "req_params": 2, "res_params": 3}
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "1.json"
            path.write_text(json.dumps({"data": {"id": 1, "projectId": 1001, "name": "List", "type": "http", "method": "GET", "path": "/items"}}), encoding="utf-8")
            summary = import_apifox_details(Path(tmp), base_url="https://api.example.com")
        self.assertEqual(summary["project_id"], "internal-p1")
        self.assertEqual(summary["import_run_id"], "import-r1")
        context = import_file.call_args.kwargs["source_context"]
        self.assertEqual(context["project_id"], "internal-p1")
        self.assertEqual(context["import_run_id"], "import-r1")
        ensure_project.assert_called_once()
        start_run.assert_called_once()
        finish_run.assert_called_once()


if __name__ == "__main__":
    unittest.main()
