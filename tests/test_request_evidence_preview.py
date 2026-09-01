import json
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import requests

from apiAnalysis.tool.execution_request_evidence import snapshot_phase_previews
from apiAnalysis.tool.request_evidence_preview import MASK, request_evidence_preview
from apiAnalysis.tool.snapshot_runner import replay_snapshot


def sample_snapshot():
    return SimpleNamespace(
        id="snapshot-1", pathid=42, project_id="project", env_id="test",
        account_id="owner", auth_mode="inherit", method="PUT",
        url=(
            "https://api.example.test/resources/7381?view=full&access_token=query-secret"
        ),
        path="/resources/7381", domain="api.example.test",
        headers={
            "Content-Type": "application/json", "X-Trace-Id": "trace-88",
            "Authorization": "Bearer header-secret", "X-Signature": "signed-secret",
        },
        cookies={"session": "cookie-secret"}, path_params={"id": 7381},
        body={
            "resource_id": 7381, "enabled": False,
            "password": "body-secret", "nested": {"name": "visible"},
        },
        content_type="application/json", expected_status_codes=[200],
        parameter_sources={
            "resource_id": {"position": "body", "source": "request_fixture", "required": True},
        }, metadata={},
    )


class RequestEvidencePreviewTests(unittest.TestCase):
    def test_preview_keeps_business_values_and_masks_secrets(self):
        preview = request_evidence_preview(sample_snapshot())
        self.assertIn("/resources/7381", preview["url"])
        self.assertIn("view=full", preview["url"])
        self.assertIn("access_token=%3Credacted%3E", preview["url"])
        self.assertEqual(preview["headers"]["Authorization"], MASK)
        self.assertEqual(preview["headers"]["X-Signature"], MASK)
        self.assertEqual(preview["headers"]["X-Trace-Id"], "trace-88")
        self.assertEqual(preview["cookies"]["session"], MASK)
        self.assertEqual(preview["body"]["resource_id"], 7381)
        self.assertEqual(preview["body"]["password"], MASK)
        self.assertEqual(
            preview["parameter_sources"]["resource_id"]["source"], "request_fixture",
        )
        rendered = json.dumps(preview, sort_keys=True)
        for secret in ("query-secret", "header-secret", "signed-secret", "cookie-secret", "body-secret"):
            self.assertNotIn(secret, rendered)

    def test_live_trace_occurs_before_request_and_is_not_returned_as_evidence(self):
        snapshot = sample_snapshot()
        events = []
        response = requests.Response()
        response.status_code = 200
        response._content = b"{}"
        response.headers["Content-Type"] = "application/json"
        response.request = requests.Request("PUT", snapshot.url).prepare()

        def request_side_effect(*_args, **_kwargs):
            self.assertEqual(len(events), 1)
            return response

        with patch(
            "apiAnalysis.tool.snapshot_runner.requests_request", side_effect=request_side_effect,
        ):
            evidence = replay_snapshot(
                snapshot, request_trace_callback=events.append,
                request_trace_phase="mutation",
            )
        self.assertEqual(events[0]["phase"], "mutation")
        self.assertEqual(events[0]["body"]["resource_id"], 7381)
        self.assertNotIn("body", evidence)
        self.assertNotIn("headers", evidence)

    def test_stored_lifecycle_projection_marks_execution_and_template_limit(self):
        snapshot = sample_snapshot()
        snapshot.metadata = {"mutation_lifecycle_plan": {
            "strategy": "update_restore",
            "readback_payload": {
                "pathid": 43, "method": "GET", "url": snapshot.url,
                "rendered_url": snapshot.url, "path": snapshot.path,
                "domain": snapshot.domain, "headers": {}, "cookies": {},
                "query": {}, "path_params": {}, "body": None,
                "content_type": "application/json", "parameter_sources": {},
            },
            "cleanup_payload": {
                "pathid": 42, "method": "PUT", "url": snapshot.url,
                "rendered_url": snapshot.url, "path": snapshot.path,
                "domain": snapshot.domain, "headers": {}, "cookies": {},
                "query": {}, "path_params": {}, "body": snapshot.body,
                "content_type": "application/json", "parameter_sources": {},
            },
        }}
        phases = snapshot_phase_previews(snapshot, {
            "before_readback_attempted": True, "before_status_code": 200,
            "mutation_status_code": 400, "cleanup_attempted": False,
        })
        self.assertEqual([item["phase"] for item in phases], [
            "before_readback", "mutation", "after_readback", "cleanup_restore", "final_readback",
        ])
        self.assertTrue(phases[0]["executed"])
        self.assertTrue(phases[1]["executed"])
        self.assertFalse(phases[3]["executed"])
        self.assertIn("transient", phases[3]["note"])


if __name__ == "__main__":
    unittest.main()
