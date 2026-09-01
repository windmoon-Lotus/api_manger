import json
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from apiAnalysis.tool.apifox_experiment import (
    APIFOX_EXPERIMENT_ADAPTER_ID,
    ApifoxExperimentError,
    ApifoxExperimentLimits,
    ApifoxExperimentPlan,
    ExperimentCandidate,
    _bounded_response_json,
    _experiment_judge,
    apifox_experiment_report,
    build_apifox_experiment_adapter,
    build_apifox_experiment_plan,
    enqueue_apifox_experiment,
)
from apiAnalysis.tool.execution_contract import ExecutionContext
from apiAnalysis.tool.execution_scheduler import ExecutionWorker
from apiAnalysis.tool.request_sample_store import sample_signature


class FakeQuerySet:
    def __init__(self, rows):
        self.rows = list(rows)

    def count(self):
        return len(self.rows)

    def order_by(self, *_):
        return self

    def first(self):
        return self.rows[0] if self.rows else None

    def __iter__(self):
        return iter(self.rows)


def context(plan_sha256=""):
    return ExecutionContext(
        project_id="project-a",
        env_id="test",
        account_id="owner",
        auth_mode="account",
        auth_provider_id="auth_recipe",
        auth_context_ref="profile-revision-a",
        auth_profile_revision_id="profile-revision-a",
        auth_realm_revision_id="realm-revision-a",
        auth_adapter_version_id="adapter-version-a",
        adapter_id=APIFOX_EXPERIMENT_ADAPTER_ID,
        adapter_version="1",
        plan_version="apifox-test-experiment.v1",
        plan_sha256=plan_sha256,
    )


class ApifoxExperimentTests(unittest.TestCase):
    @patch("apiAnalysis.tool.apifox_experiment.build_request_payload")
    @patch("apiAnalysis.tool.apifox_experiment.environment_host_names", return_value=["api.example.test"])
    @patch("apiAnalysis.tool.apifox_experiment.profile_context_fields")
    @patch("apiAnalysis.tool.apifox_experiment.raw_data")
    @patch("apiAnalysis.tool.apifox_experiment.ProjectEnvironment")
    @patch("apiAnalysis.tool.apifox_experiment.ProjectAuthProfile")
    @patch("apiAnalysis.tool.apifox_experiment.ProjectAuthProfileRevision")
    def test_plan_keeps_all_http_methods_and_emits_value_free_report(
        self, revision_model, profile_model, environment_model, raw_model,
        profile_fields, _host_names, build_payload,
    ):
        revision_model.objects.return_value.first.return_value = SimpleNamespace(
            profile_id="profile-a", config_sha256="a" * 64,
        )
        profile_model.objects.return_value.first.return_value = SimpleNamespace(
            profile_id="profile-a", current_revision_id="profile-revision-a",
        )
        profile_fields.return_value = {
            "project_id": "project-a", "env_id": "test", "account_id": "owner",
            "auth_mode": "account", "auth_provider_id": "auth_recipe",
            "auth_context_ref": "profile-revision-a",
            "auth_profile_revision_id": "profile-revision-a",
            "auth_realm_revision_id": "realm-revision-a",
            "auth_adapter_version_id": "adapter-version-a",
        }
        environment_model.objects.return_value.first.return_value = SimpleNamespace(
            environment_type="test", allow_mutation=True,
        )
        assets = [
            SimpleNamespace(
                id="asset-{}".format(index), ptah_id=700 + index,
                method=method, env_id="", source_meta={"updated_at": "2026-08-12"},
            )
            for index, method in enumerate(("GET", "POST", "PUT", "PATCH", "DELETE", "GET"), 1)
        ]
        raw_model.objects.return_value.order_by.return_value = FakeQuerySet(assets)

        def payload(_pathid, **_kwargs):
            method = assets[_pathid - 701].method
            return {
                "pathid": _pathid,
                "method": method,
                "url": "https://api.example.test/resources",
                "rendered_url": "https://api.example.test/resources",
                "query": {"secret_id": "private-resource-42"},
                "headers": {"X-Test": "bad\nvalue"} if _pathid == 706 else {},
                "cookies": {},
                "body": {"name": "private-body-value"},
                "parameter_sources": {},
            }

        build_payload.side_effect = payload

        plan = build_apifox_experiment_plan(
            "project-a", "test", "profile-revision-a",
        )
        report = apifox_experiment_report(plan, mode="dry_run")

        self.assertEqual(len(plan.candidates), 5)
        self.assertEqual(sum(item.mutation for item in plan.candidates), 4)
        self.assertEqual(plan.skipped, {"invalid_request_header": 1})
        self.assertEqual(report["candidates"]["method_counts"]["DELETE"], 1)
        self.assertEqual(report["database_writes"], 0)
        self.assertEqual(report["business_network_requests"], 0)
        serialized = json.dumps(report, ensure_ascii=False, sort_keys=True)
        self.assertNotIn("private-resource-42", serialized)
        self.assertNotIn("private-body-value", serialized)
        self.assertNotIn("/resources", serialized)

    @patch("apiAnalysis.tool.apifox_experiment.ProjectEnvironment")
    def test_non_test_environment_is_rejected_before_asset_planning(self, environment_model):
        environment_model.objects.return_value.first.return_value = SimpleNamespace(
            environment_type="production", allow_mutation=True,
        )
        with self.assertRaisesRegex(ApifoxExperimentError, "explicit test environment"):
            build_apifox_experiment_plan(
                "project-a", "formal", "profile-revision-a",
            )

    @patch("apiAnalysis.tool.apifox_experiment.enqueue_snapshot_batch")
    @patch("apiAnalysis.tool.apifox_experiment.raw_data")
    @patch("apiAnalysis.tool.apifox_experiment.request_snapshot")
    def test_enqueue_uses_mutation_adapter_and_concurrency_policy(
        self, snapshot_model, raw_model, enqueue,
    ):
        candidate = ExperimentCandidate(
            asset_id="asset-a", pathid=701, method="POST", host="api.example.test",
            mutation=True, payload_sha256="b" * 64, source_updated_at="",
            payload={
                "pathid": 701, "method": "POST",
                "rendered_url": "https://api.example.test/resources",
                "url": "https://api.example.test/resources", "path": "/resources",
                "domain": "api.example.test", "query": {}, "headers": {},
                "cookies": {}, "path_params": {}, "body": {"name": "test"},
                "content_type": "application/json", "metadata": {},
            },
        )
        plan = ApifoxExperimentPlan(
            project_id="project-a", env_id="test",
            profile_revision_id="profile-revision-a", import_run_id="import-a",
            context=context("a" * 64), candidates=(candidate,), skipped={},
            input_watermark_sha256="c" * 64, plan_sha256="a" * 64,
            limits=ApifoxExperimentLimits(),
        )
        snapshot_model.objects.return_value.first.return_value = None
        snapshot = snapshot_model.return_value
        snapshot.id = "snapshot-a"
        raw_model.objects.return_value.first.return_value = SimpleNamespace(id="asset-a")
        run = SimpleNamespace(
            id="run-a", status="queued", total_cases=1,
            adapter_id=APIFOX_EXPERIMENT_ADAPTER_ID,
        )
        enqueue.return_value = (run, True)

        report = enqueue_apifox_experiment(
            plan, "a" * 64, max_workers=12, per_host_workers=3,
        )

        policy = enqueue.call_args.kwargs["policy"]
        queued_context = enqueue.call_args.kwargs["context"]
        self.assertEqual(policy.max_workers, 12)
        self.assertEqual(policy.per_host_workers, 3)
        self.assertTrue(policy.allow_mutation)
        self.assertEqual(queued_context.adapter_id, APIFOX_EXPERIMENT_ADAPTER_ID)
        self.assertEqual(report["status"], "queued")
        self.assertEqual(report["database_records_created"], 3)
        snapshot.save.assert_called_once_with(force_insert=True)
        self.assertEqual(snapshot_model.call_args.kwargs["import_run_id"], "import-a")

    def test_adapter_supports_mutation_without_claiming_effect(self):
        adapter = build_apifox_experiment_adapter()
        run = SimpleNamespace(
            adapter_id=APIFOX_EXPERIMENT_ADAPTER_ID,
            adapter_version="1", auth_mode="account",
        )
        adapter.validate(run, allow_mutation=True)
        verdict, reasons, confidence = _experiment_judge({
            "status_code": 201, "mutation_request": True,
        }, "apifox_environment_observation", "account")
        self.assertEqual(verdict, "not_evaluable")
        self.assertEqual(reasons, ["mutation_response_requires_readback"])
        self.assertGreaterEqual(confidence, 0.9)

    def test_default_worker_registers_apifox_experiment_adapter(self):
        worker = ExecutionWorker(account_context_resolver=MagicMock())
        self.assertIn(APIFOX_EXPERIMENT_ADAPTER_ID, worker.adapters)
        self.assertTrue(worker.adapters[APIFOX_EXPERIMENT_ADAPTER_ID].supports_mutation)

    def test_large_json_sample_remains_valid_and_bounded(self):
        value = [{"id": index, "name": "x" * 1000, "nested": {"enabled": True}}
                 for index in range(100)]
        encoded = _bounded_response_json(value)
        self.assertIsNotNone(encoded)
        self.assertLessEqual(len(encoded.encode("utf-8")), 1900)
        parsed = json.loads(encoded)
        self.assertIsInstance(parsed, list)
        self.assertIn("id", parsed[0])

    def test_structured_request_body_can_be_sampled_after_replay(self):
        signature = sample_signature(
            "POST", "https://api.example.test/resources", "/resources",
            {}, {"name": "test", "items": [{"id": 1}]}, headers={},
        )
        self.assertEqual(len(signature), 64)


if __name__ == "__main__":
    unittest.main()
