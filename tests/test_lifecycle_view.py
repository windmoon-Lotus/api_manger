import json
import unittest
from types import SimpleNamespace

from apiAnalysis.tool.lifecycle_view import (
    checkpoint_view,
    execution_result_view,
    execution_run_view,
    routing_decision_view,
    safe_auth_context_summary,
    source_binding_view,
)


class LifecycleViewTests(unittest.TestCase):
    def test_auth_summary_is_allowlist_based_and_never_renders_values(self):
        summary = safe_auth_context_summary({
            "status": "ready",
            "header_names": ["Authorization"],
            "cookie_names": ["session"],
            "headers": {"Authorization": "Bearer do-not-render"},
            "cookies": {"session": "do-not-render"},
            "authorization": "Bearer do-not-render",
            "allowed_hosts": ["api.example.test"],
        })
        rendered = json.dumps(summary, sort_keys=True)
        self.assertNotIn("do-not-render", rendered)
        self.assertNotIn("headers", summary)
        self.assertEqual(summary["header_names"], ["Authorization"])

    def test_run_view_contains_counts_and_sanitized_health_only(self):
        run = SimpleNamespace(
            id="run-1", name="batch", project_id="p1", env_id="formal",
            account_id="owner", auth_mode="account", auth_provider_id="provider",
            auth_context_ref="current", adapter_id="authenticated_snapshot_batch",
            adapter_version="1", check_type="baseline", status="paused",
            total_cases=10, pending_cases=4, running_cases=0, completed_cases=6,
            failed_cases=0, skipped_cases=0, cancelled_cases=0, dispatch_attempt=1,
            last_error_type="AccountContextExpired", queued_at=None, updated_at=None,
            started_at=None, finished_at=None,
            summary={"cluster_count": 2, "review_candidate_count": 1},
            auth_context_summary={
                "status": "unavailable", "error_type": "AccountContextExpired",
                "authorization": "secret",
            },
            host_state={"hosts": [{"host": "api.example.test", "transport_errors": 0}]},
        )
        view = execution_run_view(run, "Project One")
        self.assertEqual(view["pending_cases"], 4)
        self.assertEqual(view["project_name"], "Project One")
        self.assertNotIn("secret", json.dumps(view))

    def test_checkpoint_and_result_views_ignore_private_evidence(self):
        checkpoint = SimpleNamespace(
            id="cp", ordinal=0, snapshot_id="snap", pathid=1, host="api.example.test",
            status="done", attempt_count=1, reason_codes=["ok"], error_type="",
            outcome_summary={
                "status_code": 200,
                "response_len": 12,
                "response_record_count": 2,
                "response_collection_path": "$.data",
                "response_field_names": ["id", "name"],
                "request_method": "GET",
                "request_origin": "https://api.example.test",
                "request_path": "/x",
                "request_header_names": ["Accept", "Authorization"],
                "request_cookie_names": ["session"],
                "request_body_bytes": 0,
                "request_tls_verify": False,
                "request_timeout_seconds": 15,
                "headers": {"Authorization": "private"},
                "text_sample": "private",
            },
        )
        result = SimpleNamespace(
            id="result", snapshot_id="snap", related_pathid=1, case_name="GET /x",
            check_type="baseline", method="GET", verdict="not_evaluable", priority="",
            outcome_class="blocked", confidence=0.5, reason_codes=["manual_review"],
            evidence_summary={"body": "private"}, evidence_ref="D:/private/evidence.json",
        )
        views = {
            "checkpoint": checkpoint_view(checkpoint),
            "result": execution_result_view(result),
        }
        rendered = json.dumps(views)
        self.assertNotIn("private", rendered)
        self.assertEqual(views["result"]["outcome_class"], "blocked")
        self.assertEqual(views["checkpoint"]["request_method"], "GET")
        self.assertFalse(views["checkpoint"]["request_tls_verify"])
        self.assertEqual(views["checkpoint"]["response_record_count"], 2)
        self.assertEqual(
            views["checkpoint"]["execution_effect"], "业务响应成功",
        )
        self.assertEqual(
            views["checkpoint"]["execution_effect_tone"], "success",
        )
        self.assertEqual(
            views["checkpoint"]["response_field_names"], ["id", "name"],
        )

    def test_routing_view_never_exposes_observation_url_or_request_metadata(self):
        observation = SimpleNamespace(
            method="GET", domain="api.example.test", path="/users/{id}",
            source_type="har", source_id="capture", env_id="formal", captured_at=None,
            url="https://api.example.test/users/1?token=private",
            request_metadata={"Authorization": "private"},
        )
        view = routing_decision_view({
            "_id": "decision", "observation_id": "obs", "decision": "ambiguous",
            "confidence": 0.9, "reason_codes": ["multiple_equal_project_matches"],
            "candidate_projects": [{"project_id": "p1", "score": 0.9}],
        }, observation, {"p1": "Project One"})
        rendered = json.dumps(view)
        self.assertNotIn("token", rendered)
        self.assertNotIn("Authorization", rendered)
        self.assertEqual(view["path"], "/users/{id}")

    def test_source_binding_view_only_exposes_supported_routing_rules(self):
        binding = SimpleNamespace(
            id="binding", project_id="p1", source_type="apifox", source_id="1001",
            env_id="formal", workspace_id="", active=True,
            routing_rules={
                "hosts": ["api.example.test"], "path_prefixes": ["/v1"],
                "private_token": "do-not-render",
            },
        )
        view = source_binding_view(binding, "Project One")
        self.assertEqual(view["hosts"], ["api.example.test"])
        self.assertNotIn("do-not-render", json.dumps(view))


if __name__ == "__main__":
    unittest.main()
