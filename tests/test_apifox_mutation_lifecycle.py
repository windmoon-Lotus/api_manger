import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from apiAnalysis.tool.apifox_mutation_lifecycle import (
    ADAPTER_ID,
    _extract_unique_id,
    _override_path_parameter,
    _restore_body,
    _update_resource_identity_aligned,
    build_mutation_lifecycle_adapter,
    judge_mutation_lifecycle,
    replay_mutation_lifecycle,
)
from apiAnalysis.tool.execution_scheduler import ExecutionWorker, sanitize_execution_evidence


def response(status, *, sha="a", json_type="object"):
    return {
        "status_code": status,
        "ok": 200 <= status < 400,
        "elapsed_ms": 1,
        "response_len": 10,
        "response_sha256": sha * 64,
        "response_content_type": "application/json",
        "response_json_type": json_type,
        "error_type": "",
        "request_path": "/resource",
    }


def update_snapshot():
    return SimpleNamespace(
        id="snapshot-a", raw_data=None, pathid=10, project_id="project-a",
        env_id="test", account_id="owner", auth_mode="account",
        method="PUT", url="https://api.example.test/config", path="/config",
        domain="api.example.test", query={}, headers={}, cookies={},
        path_params={}, body={"enabled": False, "name": "changed"},
        content_type="application/json", expected_status_codes=[],
        parameter_sources={},
        metadata={"mutation_lifecycle_plan": {
            "strategy": "update_restore",
            "readback_payload": {
                "pathid": 11, "method": "GET",
                "rendered_url": "https://api.example.test/config",
                "url": "https://api.example.test/config", "path": "/config",
                "domain": "api.example.test", "query": {}, "headers": {},
                "cookies": {}, "path_params": {}, "body": None,
                "content_type": "application/json",
            },
            "cleanup_payload": {
                "pathid": 10, "method": "PUT",
                "rendered_url": "https://api.example.test/config",
                "url": "https://api.example.test/config", "path": "/config",
                "domain": "api.example.test", "query": {}, "headers": {},
                "cookies": {}, "path_params": {},
                "body": {"enabled": False, "name": "changed"},
                "content_type": "application/json",
            },
        }},
    )


class MutationLifecycleTests(unittest.TestCase):
    def test_archive_rotation_rebuilds_path_from_template(self):
        payload = {
            "url": "https://api.example.test/resources/old",
            "rendered_url": "https://api.example.test/resources/old",
            "path": "/resources/{resource_id}",
            "path_params": {"resource_id": "old"},
        }
        rotated = _override_path_parameter(
            payload, SimpleNamespace(path="/resources/{resource_id}"),
            "resource_id", "next",
        )
        self.assertEqual(rotated["rendered_url"], "https://api.example.test/resources/next")
        self.assertEqual(rotated["path_params"], {"resource_id": "next"})

    def test_restore_body_requires_one_unambiguous_object(self):
        value = {"data": {"enabled": True, "name": "before", "other": 1}}
        self.assertEqual(
            _restore_body({"enabled": False, "name": "after"}, value),
            {"enabled": True, "name": "before"},
        )
        ambiguous = {"a": {"enabled": True}, "b": {"enabled": False}}
        self.assertIsNone(_restore_body({"enabled": False}, ambiguous))

    def test_created_id_extraction_is_unique(self):
        self.assertEqual(_extract_unique_id({"data": {"group_id": 42}}, "group_id"), 42)
        self.assertIsNone(_extract_unique_id({"id": 1, "data": {"id": 2}}, "id"))

    def test_update_readback_must_target_same_resource(self):
        self.assertTrue(_update_resource_identity_aligned(
            {"url": "https://api.example.test/roles/212", "path_params": {"role_id": 212}},
            {"url": "https://api.example.test/roles/212", "path_params": {"role_id": 212}},
        ))
        self.assertFalse(_update_resource_identity_aligned(
            {"url": "https://api.example.test/roles/217", "path_params": {"role_id": 217}},
            {"url": "https://api.example.test/roles/212", "path_params": {"role_id": 212}},
        ))

    @patch("apiAnalysis.tool.apifox_mutation_lifecycle.replay_snapshot_with_json")
    def test_runtime_gate_blocks_synthetic_required_value(self, replay):
        snapshot = update_snapshot()
        snapshot.parameter_sources = {
            "enabled": {"source": "empty_default", "required": True},
        }
        evidence = replay_mutation_lifecycle(snapshot)
        replay.assert_not_called()
        self.assertEqual(evidence["lifecycle_gap"], "synthetic_required_mutation_value")

    @patch("apiAnalysis.tool.apifox_mutation_lifecycle.replay_snapshot_with_json")
    def test_runtime_gate_blocks_readback_identity_mismatch(self, replay):
        snapshot = update_snapshot()
        snapshot.url = "https://api.example.test/config/217"
        snapshot.metadata["mutation_lifecycle_plan"]["readback_payload"]["url"] = (
            "https://api.example.test/config/212"
        )
        replay.return_value = (response(200), {})
        evidence = replay_mutation_lifecycle(snapshot)
        replay.assert_not_called()
        self.assertEqual(evidence["lifecycle_gap"], "readback_resource_identity_mismatch")

    @patch("apiAnalysis.tool.apifox_mutation_lifecycle.replay_snapshot_with_json")
    def test_update_is_read_back_and_restored(self, replay):
        before = {"data": {"enabled": True, "name": "before"}}
        after = {"data": {"enabled": False, "name": "changed"}}
        replay.side_effect = [
            (response(200), before),
            (response(204, json_type=""), None),
            (response(200), after),
            (response(204, json_type=""), None),
            (response(200), before),
        ]
        evidence = replay_mutation_lifecycle(update_snapshot())
        self.assertEqual(replay.call_count, 5)
        self.assertEqual(
            [call.kwargs["request_trace_phase"] for call in replay.call_args_list],
            ["before_readback", "mutation", "after_readback", "cleanup_restore", "final_readback"],
        )
        restore_snapshot = replay.call_args_list[3].args[0]
        self.assertEqual(restore_snapshot.body, {"enabled": True, "name": "before"})
        self.assertTrue(evidence["effect_observed"])
        self.assertTrue(evidence["cleanup_verified"])
        self.assertEqual(evidence["lifecycle_request_count"], 5)
        verdict, reasons, _confidence = judge_mutation_lifecycle(evidence, "", "")
        self.assertEqual(verdict, "not_evaluable")
        self.assertEqual(reasons, ["mutation_effect_observed_and_restored"])

    @patch("apiAnalysis.tool.apifox_mutation_lifecycle.replay_snapshot_with_json")
    def test_missing_restore_data_prevents_mutation(self, replay):
        replay.return_value = (response(200), {"data": {"other": 1}})
        evidence = replay_mutation_lifecycle(update_snapshot())
        self.assertEqual(replay.call_count, 1)
        self.assertEqual(evidence["lifecycle_gap"], "unique_restore_payload_unavailable")
        self.assertFalse(evidence["cleanup_attempted"])
        verdict, reasons, _confidence = judge_mutation_lifecycle(evidence, "", "")
        self.assertEqual(verdict, "not_evaluable")
        self.assertIn("mutation_not_sent", reasons)

    @patch("apiAnalysis.tool.apifox_mutation_lifecycle.replay_snapshot_with_json")
    def test_preflight_stops_even_when_restore_is_ready(self, replay):
        snapshot = update_snapshot()
        snapshot.metadata["mutation_lifecycle_plan"]["preflight_only"] = True
        replay.return_value = (
            response(200), {"data": {"enabled": True, "name": "before"}},
        )
        evidence = replay_mutation_lifecycle(snapshot)
        self.assertEqual(replay.call_count, 1)
        self.assertTrue(evidence["restore_payload_ready"])
        self.assertEqual(evidence["lifecycle_gap"], "preflight_complete_mutation_not_sent")
        self.assertFalse(evidence["cleanup_attempted"])

    def test_sanitizer_keeps_lifecycle_outcome_without_values(self):
        sanitized = sanitize_execution_evidence({
            "status_code": 204, "lifecycle_strategy": "update_restore",
            "before_status_code": 200, "mutation_status_code": 204,
            "cleanup_status_code": 204, "final_status_code": 200,
            "effect_observed": True, "cleanup_verified": True,
            "private_before": {"name": "secret"},
        })
        self.assertTrue(sanitized["cleanup_verified"])
        self.assertNotIn("private_before", sanitized)

    def test_default_worker_registers_lifecycle_adapter(self):
        worker = ExecutionWorker(account_context_resolver=MagicMock())
        self.assertIn(ADAPTER_ID, worker.adapters)
        self.assertTrue(worker.adapters[ADAPTER_ID].supports_mutation)
        adapter = build_mutation_lifecycle_adapter()
        self.assertEqual(adapter.adapter_id, ADAPTER_ID)


if __name__ == "__main__":
    unittest.main()
