import threading
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from bson import ObjectId

from apiAnalysis.db.collection import security_execution_checkpoint, security_test_run
from apiAnalysis.tool.execution_adapter import ExecutionRequestBlocked
from apiAnalysis.tool.execution_contract import ExecutionContext
from apiAnalysis.tool.execution_scheduler import (
    ExecutionPolicy,
    HostPolicyCoordinator,
    _build_coordinated_request_executor,
    build_idempotency_key,
    classify_execution_result,
    enqueue_snapshot_batch,
    sanitize_execution_evidence,
    summarize_execution_records,
)


class ExecutionSchedulerTests(unittest.TestCase):
    def test_policy_requires_explicit_mutation_acknowledgement(self):
        with self.assertRaises(ValueError):
            ExecutionPolicy(allow_mutation=True).validate()
        ExecutionPolicy(allow_mutation=True, mutation_acknowledged=True).validate()

    def test_idempotency_is_order_independent_and_context_bound(self):
        first, second = ObjectId(), ObjectId()
        policy = ExecutionPolicy()
        anonymous = ExecutionContext(project_id="p1", env_id="formal", auth_mode="anonymous")
        key_a = build_idempotency_key(anonymous, [first, second], "unauth_access", policy)
        key_b = build_idempotency_key(anonymous, [second, first], "unauth_access", policy)
        self.assertEqual(key_a, key_b)
        account = ExecutionContext(
            project_id="p1", env_id="formal", account_id="owner", auth_mode="account",
            auth_provider_id="test_provider", adapter_id="authenticated_snapshot_batch",
        )
        self.assertNotEqual(key_a, build_idempotency_key(account, [first, second], "unauth_access", policy))

    def test_explicit_idempotency_key_rejects_different_snapshot_set(self):
        original_id, requested_id = ObjectId(), ObjectId()
        existing = SimpleNamespace(
            status=security_test_run.PREPARING,
            snapshot_ids=[original_id],
        )
        query = Mock()
        query.first.return_value = existing
        context = ExecutionContext(
            project_id="p1",
            env_id="formal",
            auth_mode="anonymous",
        )
        with patch(
                "apiAnalysis.tool.execution_scheduler._load_and_validate_snapshots",
                return_value=[SimpleNamespace(id=requested_id)]), patch.object(
                security_test_run, "objects", return_value=query):
            with self.assertRaisesRegex(ValueError, "different snapshot_ids"):
                enqueue_snapshot_batch(
                    "batch",
                    "snapshot_baseline",
                    context,
                    [requested_id],
                    idempotency_key="shared-key",
                )

    def test_sanitized_evidence_drops_body_and_raw_error(self):
        sanitized = sanitize_execution_evidence({
            "status_code": 401,
            "response_len": 30,
            "request_method": "GET",
            "request_header_names": ["Accept", "Authorization"],
            "request_cookie_names": ["session"],
            "request_tls_verify": False,
            "response_record_count": 0,
            "headers": {"Authorization": "Bearer private"},
            "cookies": {"session": "private"},
            "body": {"password": "private"},
            "text_sample": "private body",
            "error": "https://api.example.test/?token=secret",
            "error_type": "ReadTimeout",
        })
        self.assertEqual(sanitized["status_code"], 401)
        self.assertEqual(sanitized["request_method"], "GET")
        self.assertEqual(sanitized["request_cookie_names"], ["session"])
        self.assertFalse(sanitized["request_tls_verify"])
        self.assertEqual(sanitized["response_record_count"], 0)
        self.assertNotIn("headers", sanitized)
        self.assertNotIn("cookies", sanitized)
        self.assertNotIn("body", sanitized)
        self.assertNotIn("text_sample", sanitized)
        self.assertNotIn("error", sanitized)

    def test_body_free_cluster_summary_drives_targeted_review(self):
        first_id, second_id = ObjectId(), ObjectId()
        first_summary = sanitize_execution_evidence({
            "status_code": 200,
            "response_len": 120,
            "response_content_type": "application/json",
            "response_json_type": "object",
            "response_sha256": "a" * 64,
        })
        second_summary = dict(first_summary, response_sha256="b" * 64)
        checkpoints = [
            SimpleNamespace(
                host="api.example", pathid=1, snapshot_id=first_id,
                outcome_summary=first_summary,
            ),
            SimpleNamespace(
                host="api.example", pathid=2, snapshot_id=second_id,
                outcome_summary=second_summary,
            ),
        ]
        results = [
            SimpleNamespace(
                id=ObjectId(), snapshot_id=first_id, related_pathid=1,
                verdict="need_review", reason_codes=["anonymous_2xx_requires_content_review"],
            ),
            SimpleNamespace(
                id=ObjectId(), snapshot_id=second_id, related_pathid=2,
                verdict="no_vuln", reason_codes=["anonymous_authentication_required"],
            ),
        ]
        summary = summarize_execution_records(checkpoints, results)
        self.assertEqual(summary["cluster_count"], 1)
        self.assertEqual(summary["clusters"][0]["count"], 2)
        self.assertEqual(summary["clusters"][0]["distinct_response_hashes"], 2)
        self.assertEqual(summary["review_candidate_count"], 1)
        self.assertEqual(summary["review_candidates"][0]["pathid"], 1)

    def test_unauth_judge_is_conservative(self):
        verdict, reasons, confidence = classify_execution_result(
            {"status_code": 401}, "unauth_access", "anonymous"
        )
        self.assertEqual(verdict, "no_vuln")
        self.assertGreater(confidence, 0.9)
        verdict, reasons, _ = classify_execution_result(
            {"status_code": 200}, "unauth_access", "anonymous"
        )
        self.assertEqual(verdict, "need_review")
        self.assertIn("anonymous_2xx_requires_content_review", reasons)
        verdict, _, _ = classify_execution_result(
            {"status_code": 200}, "idor", "account"
        )
        self.assertEqual(verdict, "not_evaluable")

    def test_host_stop_is_isolated_and_persistable(self):
        policy = ExecutionPolicy(
            transport_error_stop=2,
            rate_limit_stop=2,
            server_error_stop=2,
        )
        coordinator = HostPolicyCoordinator(policy)
        self.assertEqual(coordinator.record_outcome("a.example", {"error_type": "ReadTimeout"}), "")
        self.assertEqual(
            coordinator.record_outcome("a.example", {"error_type": "ReadTimeout"}),
            "transport_error_threshold",
        )
        self.assertEqual(coordinator.record_outcome("b.example", {"status_code": 200}), "")
        persisted = coordinator.snapshot()
        self.assertEqual([item["host"] for item in persisted["hosts"]], ["a.example", "b.example"])
        restored = HostPolicyCoordinator(policy, persisted=persisted)
        self.assertEqual(
            restored.record_outcome("a.example", {"status_code": 200}),
            "transport_error_threshold",
        )

    def test_request_executor_coordinates_and_records_each_real_request(self):
        coordinator = Mock()
        first_permit = object()
        second_permit = object()
        coordinator.acquire.side_effect = [
            (True, "", first_permit),
            (True, "", second_permit),
        ]
        execute = _build_coordinated_request_executor(
            coordinator, "api.example", lambda: False,
        )
        first = execute(lambda: ({"status_code": 200}, {"value": 1}))
        second = execute(lambda: {"status_code": 204})

        self.assertEqual(first[0]["status_code"], 200)
        self.assertEqual(second["status_code"], 204)
        self.assertEqual(coordinator.acquire.call_count, 2)
        self.assertEqual(coordinator.record_outcome.call_count, 2)
        coordinator.record_outcome.assert_any_call(
            "api.example", {"status_code": 200}
        )
        coordinator.record_outcome.assert_any_call(
            "api.example", {"status_code": 204}
        )
        self.assertEqual(
            [call.args[0] for call in coordinator.release.call_args_list],
            [first_permit, second_permit],
        )

    def test_request_executor_stops_before_request_after_breaker_opens(self):
        coordinator = HostPolicyCoordinator(ExecutionPolicy(
            max_workers=1,
            per_host_workers=1,
            min_interval_ms=0,
            server_error_stop=1,
        ))
        execute = _build_coordinated_request_executor(
            coordinator, "api.example", lambda: False,
        )
        execute(lambda: {"status_code": 500})
        called = []
        with self.assertRaises(ExecutionRequestBlocked) as raised:
            execute(lambda: called.append(True))
        self.assertEqual(raised.exception.reason, "server_error_threshold")
        self.assertEqual(called, [])

    def test_request_executor_checks_cancellation_before_request(self):
        coordinator = HostPolicyCoordinator(ExecutionPolicy(
            max_workers=1,
            per_host_workers=1,
            min_interval_ms=0,
        ))
        execute = _build_coordinated_request_executor(
            coordinator, "api.example", lambda: True,
        )
        called = []
        with self.assertRaises(ExecutionRequestBlocked) as raised:
            execute(lambda: called.append(True))
        self.assertEqual(raised.exception.reason, "execution_stopping")
        self.assertEqual(called, [])

    def test_request_executor_checks_cancellation_while_waiting_for_permit(self):
        coordinator = HostPolicyCoordinator(ExecutionPolicy(
            max_workers=2,
            per_host_workers=1,
            min_interval_ms=0,
        ))
        allowed, _, permit = coordinator.acquire("api.example", lambda: False)
        self.assertTrue(allowed)
        abort = threading.Event()
        finished = threading.Event()
        called = []
        reasons = []
        execute = _build_coordinated_request_executor(
            coordinator, "api.example", abort.is_set,
        )

        def run_request():
            try:
                execute(lambda: called.append(True))
            except ExecutionRequestBlocked as exc:
                reasons.append(exc.reason)
            finally:
                finished.set()

        worker = threading.Thread(target=run_request)
        try:
            worker.start()
            abort.set()
            self.assertTrue(finished.wait(1.0))
        finally:
            coordinator.release(permit)
            worker.join(1.0)
        self.assertEqual(reasons, ["execution_stopping"])
        self.assertEqual(called, [])
        self.assertFalse(worker.is_alive())

    def test_existing_run_model_is_scheduler_job_and_checkpoint_is_progress_only(self):
        run = security_test_run(
            name="batch",
            check_type="snapshot_baseline",
            project_id="p1",
            scheduler_managed=True,
            status=security_test_run.QUEUED,
            idempotency_key="key",
            total_cases=2,
        )
        self.assertTrue(run.scheduler_managed)
        self.assertEqual(run.status, "queued")
        checkpoint = security_execution_checkpoint(
            run_id=ObjectId(), snapshot_id=ObjectId(), ordinal=0,
        )
        self.assertEqual(checkpoint.status, security_execution_checkpoint.PENDING)
        self.assertFalse(hasattr(checkpoint, "verdict"))


if __name__ == "__main__":
    unittest.main()
