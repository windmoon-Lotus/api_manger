import json
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from tools.pull_apifox_endpoint_details import endpoints_from_document, run_apifox_list


class PullApifoxEndpointDetailsTests(unittest.TestCase):
    def test_endpoint_document_can_include_every_status(self):
        document = {
            "data": [
                {"id": 1, "status": "released"},
                {"id": 2, "status": "developing"},
                {"id": 3, "status": "testing"},
            ]
        }
        self.assertEqual(
            [item["id"] for item in endpoints_from_document(document)],
            [1, 2, 3],
        )
        self.assertEqual(
            [item["id"] for item in endpoints_from_document(document, ["released"])],
            [1],
        )

    @patch("tools.pull_apifox_endpoint_details.subprocess.run")
    def test_live_list_uses_apifox_project(self, run):
        payload = {"success": True, "data": [{"id": 7}]}
        run.return_value = SimpleNamespace(
            returncode=0, stdout=json.dumps(payload), stderr="",
        )
        self.assertEqual(run_apifox_list("apifox", 2127251, 30), payload)
        self.assertEqual(
            run.call_args.args[0],
            ["apifox", "endpoint", "list", "--project", "2127251"],
        )


if __name__ == "__main__":
    unittest.main()
