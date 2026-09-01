import os
import re
import unittest
import uuid

import redis
from bson import ObjectId
from flask import Flask

from apiAnalysis.db.collection import (
    ApiProject,
    ObservationRoutingDecision,
    ProjectSourceBinding,
    RequestObservation,
    security_execution_checkpoint,
    security_test_result,
    security_test_run,
)
from apiAnalysis.main import _ensure_mongo_connection
from apiAnalysis.model.model import PolicyEnum
from apiAnalysis.tool import redis_pool
from apiAnalysis.tool.execution_scheduler import WAKEUP_KEY
from apiAnalysis.web import bp_web


@unittest.skipUnless(
    os.getenv("API_MANAGER_INTEGRATION_TESTS") == "1",
    "set API_MANAGER_INTEGRATION_TESTS=1 to use local MongoDB/Redis",
)
class ProjectExecutionWebIntegrationTests(unittest.TestCase):
    def setUp(self):
        _ensure_mongo_connection()
        suffix = uuid.uuid4().hex
        self.project_id = "web-lifecycle-{}".format(suffix)
        self.observation_id = "web-observation-{}".format(suffix)
        self.project = ApiProject(project_id=self.project_id, name="Web Lifecycle Test")
        self.project.save()
        ProjectSourceBinding(
            project_id=self.project_id,
            source_type="integration",
            source_id=suffix,
            env_id="test",
            routing_rules={
                "hosts": ["lifecycle.invalid"],
                "path_prefixes": ["/v1"],
                "private_value": "must-not-render",
            },
        ).save()
        RequestObservation(
            observation_id=self.observation_id,
            source_type="integration",
            source_id=suffix,
            env_id="test",
            method="GET",
            url="https://lifecycle.invalid/v1/users?token=must-not-render",
            domain="lifecycle.invalid",
            path="/v1/users",
            request_metadata={"Authorization": "must-not-render"},
        ).save()
        self.decision = ObservationRoutingDecision(
            observation_id=self.observation_id,
            candidate_projects=[{
                "project_id": self.project_id,
                "score": 0.9,
                "reason_codes": ["abstract_signature_match"],
            }],
            confidence=0.9,
            reason_codes=["multiple_equal_project_matches"],
            decision=ObservationRoutingDecision.AMBIGUOUS,
        )
        self.decision.save()
        self.snapshot_id = ObjectId()
        self.run = security_test_run(
            name="Web paused test run",
            check_type="snapshot_baseline",
            project_id=self.project_id,
            env_id="test",
            account_id="owner",
            auth_mode="account",
            auth_provider_id="integration_provider",
            auth_context_ref="owner-current",
            auth_context_summary={
                "status": "unavailable",
                "error_type": "AccountContextExpired",
                "authorization": "must-not-render",
            },
            adapter_id="authenticated_snapshot_batch",
            adapter_version="1",
            status=security_test_run.PAUSED,
            scheduler_managed=True,
            queue_name="web-lifecycle-{}".format(suffix),
            total_cases=1,
            pending_cases=1,
        )
        self.run.save()
        security_execution_checkpoint(
            run_id=self.run.id,
            snapshot_id=self.snapshot_id,
            project_id=self.project_id,
            env_id="test",
            pathid=999001,
            ordinal=0,
            host="lifecycle.invalid",
            status=security_execution_checkpoint.PENDING,
        ).save()
        security_test_result(
            run_id=self.run.id,
            project_id=self.project_id,
            snapshot_id=self.snapshot_id,
            case_name="GET /v1/users",
            check_type="snapshot_baseline",
            method="GET",
            verdict="not_evaluable",
            confidence=0.5,
            reason_codes=["fixture_required"],
            evidence_summary={"body": "must-not-render"},
            evidence_ref="private://sha256/example-evidence",
        ).save()

        app = Flask(
            __name__,
            template_folder=str(os.path.join(os.path.dirname(__file__), "..", "apiAnalysis", "templates")),
            static_folder=str(os.path.join(os.path.dirname(__file__), "..", "apiAnalysis", "static")),
        )
        app.secret_key = "test-integration-only-secret"
        app.register_blueprint(bp_web)
        app.config.update(TESTING=True)
        self.client = app.test_client()
        with self.client.session_transaction() as state:
            state["username"] = "integration-admin"
            state["role"] = [PolicyEnum.MANAGE.value, PolicyEnum.ACCESS.value]

    def tearDown(self):
        run_ids = list(security_test_run.objects(project_id=self.project_id).scalar("id"))
        security_test_result.objects(run_id__in=run_ids).delete()
        security_execution_checkpoint.objects(run_id__in=run_ids).delete()
        security_test_run.objects(id__in=run_ids).delete()
        ObservationRoutingDecision.objects(observation_id=self.observation_id).delete()
        RequestObservation.objects(observation_id=self.observation_id).delete()
        ProjectSourceBinding.objects(project_id=self.project_id).delete()
        ApiProject.objects(project_id=self.project_id).delete()
        try:
            client = redis.Redis(connection_pool=redis_pool)
            for run_id in run_ids:
                client.lrem(WAKEUP_KEY, 0, str(run_id))
        except Exception:
            pass

    def _page(self):
        response = self.client.get(
            "/project-executions",
            query_string={
                "project_id": self.project_id,
                "run_id": str(self.run.id),
            },
        )
        self.assertEqual(response.status_code, 200)
        body = response.get_data(as_text=True)
        token_match = re.search(r'name="csrf_token" value="([^"]+)"', body)
        self.assertIsNotNone(token_match)
        return body, token_match.group(1)

    def test_page_redaction_module_split_resume_and_cancel(self):
        body, csrf_token = self._page()
        self.assertIn(str(self.run.id), body)
        self.assertNotIn(self.observation_id, body)
        self.assertNotIn("must-not-render", body)

        invalid = self.client.post("/project-executions", data={
            "csrf_token": "invalid",
            "action": "resume_run",
            "run_id": str(self.run.id),
            "expected_status": security_test_run.PAUSED,
        })
        self.assertEqual(invalid.status_code, 302)
        self.run.reload()
        self.assertEqual(self.run.status, security_test_run.PAUSED)

        resumed = self.client.post("/project-executions", data={
            "csrf_token": csrf_token,
            "action": "resume_run",
            "run_id": str(self.run.id),
            "expected_status": security_test_run.PAUSED,
        })
        self.assertEqual(resumed.status_code, 302)
        self.run.reload()
        self.assertEqual(self.run.status, security_test_run.QUEUED)

        cancelled = self.client.post("/project-executions", data={
            "csrf_token": csrf_token,
            "action": "cancel_run",
            "run_id": str(self.run.id),
            "expected_status": security_test_run.QUEUED,
        })
        self.assertEqual(cancelled.status_code, 302)
        self.run.reload()
        self.assertEqual(self.run.status, security_test_run.CANCELLED)
        checkpoint = security_execution_checkpoint.objects(run_id=self.run.id).first()
        self.assertEqual(checkpoint.status, security_execution_checkpoint.CANCELLED)

    def test_non_manager_cannot_mutate_lifecycle(self):
        _, csrf_token = self._page()
        with self.client.session_transaction() as state:
            state["role"] = [PolicyEnum.ACCESS.value]
        response = self.client.post("/project-executions", data={
            "csrf_token": csrf_token,
            "action": "resume_run",
            "run_id": str(self.run.id),
            "expected_status": security_test_run.PAUSED,
        })
        self.assertEqual(response.status_code, 403)
        self.run.reload()
        self.assertEqual(self.run.status, security_test_run.PAUSED)


if __name__ == "__main__":
    unittest.main()
