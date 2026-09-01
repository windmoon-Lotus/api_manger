import os
import re
import unittest
import uuid

from flask import Flask

from apiAnalysis.db.collection import (
    ApiProject,
    DataSource,
    ObservationRoutingDecision,
    ProjectEnvironment,
    ProjectSourceBinding,
    RequestObservation,
)
from apiAnalysis.main import _ensure_mongo_connection
from apiAnalysis.model.model import PolicyEnum
from apiAnalysis.tool.api_signature import abstract_signature
from apiAnalysis.web import bp_web


@unittest.skipUnless(
    os.getenv("API_MANAGER_INTEGRATION_TESTS") == "1",
    "set API_MANAGER_INTEGRATION_TESTS=1 to use local MongoDB",
)
class DataSourceWebIntegrationTests(unittest.TestCase):
    def setUp(self):
        _ensure_mongo_connection()
        suffix = uuid.uuid4().hex
        self.project_id = "source-web-{}".format(suffix)
        self.source_id = "source-{}".format(suffix)
        self.observation_id = "observation-{}".format(suffix)
        self.ignored_observation_id = "ignored-{}".format(suffix)
        ApiProject(
            project_id=self.project_id,
            name="Data Source Web Test",
        ).save()
        ProjectEnvironment(
            project_id=self.project_id,
            env_id="test",
            name="测试环境",
            environment_type="test",
            active=True,
        ).save()
        DataSource(
            data_source_id=self.source_id,
            source_type="integration",
            external_id=suffix,
            name="Integration Traffic",
        ).save()
        signature = abstract_signature("GET", "/v1/users/{id}")
        RequestObservation(
            observation_id=self.observation_id,
            data_source_id=self.source_id,
            source_type="integration",
            source_id=suffix,
            method="GET",
            url="https://source-web.invalid/v1/users/123?token=must-not-render",
            domain="source-web.invalid",
            path="/v1/users/123",
            abstract_signature=signature,
            request_metadata={
                "header_names": ["accept", "authorization"],
                "body_shape": {"type": "object", "keys": ["department_id"]},
                "private_value": "must-not-render",
            },
            response_metadata={"status": 200, "length": 123},
        ).save()
        self.decision = ObservationRoutingDecision(
            observation_id=self.observation_id,
            candidate_projects=[{
                "project_id": self.project_id,
                "score": 0.78,
                "reason_codes": ["candidate_signature"],
            }],
            confidence=0.78,
            reason_codes=["multiple_equal_project_matches"],
            decision=ObservationRoutingDecision.AMBIGUOUS,
        )
        self.decision.save()
        RequestObservation(
            observation_id=self.ignored_observation_id,
            data_source_id=self.source_id,
            source_type="integration",
            source_id=suffix,
            method="GET",
            url="https://source-web.invalid/health",
            domain="source-web.invalid",
            path="/health",
            abstract_signature=abstract_signature("GET", "/health"),
            request_metadata={"header_names": [], "body_shape": {}},
            response_metadata={"status": 200, "length": 2},
        ).save()
        self.ignored_decision = ObservationRoutingDecision(
            observation_id=self.ignored_observation_id,
            candidate_projects=[],
            confidence=0.0,
            reason_codes=["no_high_confidence_project_match"],
            decision=ObservationRoutingDecision.UNASSIGNED,
        )
        self.ignored_decision.save()

        app = Flask(
            __name__,
            template_folder=str(os.path.join(
                os.path.dirname(__file__), "..", "apiAnalysis", "templates",
            )),
            static_folder=str(os.path.join(
                os.path.dirname(__file__), "..", "apiAnalysis", "static",
            )),
        )
        app.secret_key = "test-data-source-secret"
        app.register_blueprint(bp_web)
        app.config.update(TESTING=True)
        self.client = app.test_client()
        with self.client.session_transaction() as state:
            state["username"] = "integration-admin"
            state["role"] = [
                PolicyEnum.MANAGE.value,
                PolicyEnum.ACCESS.value,
            ]

    def tearDown(self):
        ObservationRoutingDecision.objects(
            observation_id__in=[
                self.observation_id,
                self.ignored_observation_id,
            ],
        ).delete()
        RequestObservation.objects(
            observation_id__in=[
                self.observation_id,
                self.ignored_observation_id,
            ],
        ).delete()
        ProjectSourceBinding.objects(project_id=self.project_id).delete()
        ProjectEnvironment.objects(project_id=self.project_id).delete()
        DataSource.objects(data_source_id=self.source_id).delete()
        ApiProject.objects(project_id=self.project_id).delete()

    def _routing_page(self):
        response = self.client.get(
            "/data-sources",
            query_string={"view": "routing", "routing_decision": "open"},
        )
        self.assertEqual(response.status_code, 200)
        body = response.get_data(as_text=True)
        token = re.search(r'name="csrf_token" value="([^"]+)"', body)
        self.assertIsNotNone(token)
        return body, token.group(1)

    def test_manual_assignment_teaches_future_route_and_ignore_is_audited(self):
        body, csrf_token = self._routing_page()
        self.assertIn(self.observation_id, body)
        self.assertIn(self.ignored_observation_id, body)
        self.assertNotIn("must-not-render", body)

        invalid = self.client.post("/data-sources", data={
            "csrf_token": "invalid",
            "action": "assign_observation",
            "observation_id": self.observation_id,
            "expected_decision_id": str(self.decision.id),
            "project_environment": "{}|test".format(self.project_id),
            "teach_future": "1",
            "return_view": "routing",
        })
        self.assertEqual(invalid.status_code, 302)
        self.assertEqual(
            ObservationRoutingDecision.objects(
                observation_id=self.observation_id,
            ).count(),
            1,
        )

        assigned = self.client.post("/data-sources", data={
            "csrf_token": csrf_token,
            "action": "assign_observation",
            "observation_id": self.observation_id,
            "expected_decision_id": str(self.decision.id),
            "project_environment": "{}|test".format(self.project_id),
            "teach_future": "1",
            "return_view": "routing",
        })
        self.assertEqual(assigned.status_code, 302)
        latest = ObservationRoutingDecision.objects(
            observation_id=self.observation_id,
        ).order_by("-ctime", "-id").first()
        self.assertEqual(latest.decision, ObservationRoutingDecision.ASSIGNED)
        self.assertEqual(latest.selected_project_id, self.project_id)
        self.assertEqual(latest.selected_env_id, "test")
        self.assertEqual(latest.manual_by, "integration-admin")
        binding = ProjectSourceBinding.objects(
            project_id=self.project_id,
            data_source_id=self.source_id,
            env_id="test",
        ).first()
        self.assertIsNotNone(binding)
        self.assertIn(
            "GET {}".format(
                abstract_signature("GET", "/v1/users/{id}"),
            ),
            binding.routing_rules.get("signatures") or [],
        )

        corrected = self.client.post("/data-sources", data={
            "csrf_token": csrf_token,
            "action": "ignore_observation",
            "observation_id": self.observation_id,
            "expected_decision_id": str(latest.id),
            "override_final": "1",
            "return_view": "routing",
        })
        self.assertEqual(corrected.status_code, 302)
        corrected_latest = ObservationRoutingDecision.objects(
            observation_id=self.observation_id,
        ).order_by("-ctime", "-id").first()
        self.assertEqual(
            corrected_latest.decision,
            ObservationRoutingDecision.IGNORED,
        )
        binding.reload()
        self.assertEqual(binding.routing_rules.get("signatures") or [], [])

        restored = self.client.post("/data-sources", data={
            "csrf_token": csrf_token,
            "action": "assign_observation",
            "observation_id": self.observation_id,
            "expected_decision_id": str(corrected_latest.id),
            "project_environment": "{}|test".format(self.project_id),
            "teach_future": "1",
            "override_final": "1",
            "return_view": "routing",
        })
        self.assertEqual(restored.status_code, 302)
        restored_latest = ObservationRoutingDecision.objects(
            observation_id=self.observation_id,
        ).order_by("-ctime", "-id").first()
        self.assertEqual(
            restored_latest.decision,
            ObservationRoutingDecision.ASSIGNED,
        )
        self.assertIn(
            "manual_project_override",
            restored_latest.reason_codes,
        )

        ignored = self.client.post("/data-sources", data={
            "csrf_token": csrf_token,
            "action": "ignore_observation",
            "observation_id": self.ignored_observation_id,
            "expected_decision_id": str(self.ignored_decision.id),
            "return_view": "routing",
        })
        self.assertEqual(ignored.status_code, 302)
        latest_ignored = ObservationRoutingDecision.objects(
            observation_id=self.ignored_observation_id,
        ).order_by("-ctime", "-id").first()
        self.assertEqual(
            latest_ignored.decision,
            ObservationRoutingDecision.IGNORED,
        )
        self.assertEqual(latest_ignored.manual_by, "integration-admin")

        source_page = self.client.get(
            "/data-sources",
            query_string={"view": "sources", "source_type": "integration"},
        )
        source_body = source_page.get_data(as_text=True)
        self.assertIn("Integration Traffic", source_body)
        self.assertIn("Data Source Web Test", source_body)
        self.assertNotIn("must-not-render", source_body)

        binding.reload()
        disabled = self.client.post("/data-sources", data={
            "csrf_token": csrf_token,
            "action": "deactivate_source_binding",
            "binding_id": str(binding.id),
            "data_source_id": self.source_id,
            "return_view": "sources",
        })
        self.assertEqual(disabled.status_code, 302)
        binding.reload()
        self.assertFalse(binding.active)
        self.assertEqual(binding.disabled_by, "integration-admin")

        rebound = self.client.post("/data-sources", data={
            "csrf_token": csrf_token,
            "action": "bind_source",
            "data_source_id": self.source_id,
            "project_environment": "{}|test".format(self.project_id),
            "return_view": "sources",
        })
        self.assertEqual(rebound.status_code, 302)
        binding.reload()
        self.assertTrue(binding.active)
        self.assertEqual(binding.disabled_by, "")

    def test_non_manager_cannot_change_routing(self):
        _, csrf_token = self._routing_page()
        with self.client.session_transaction() as state:
            state["role"] = [PolicyEnum.ACCESS.value]
        response = self.client.post("/data-sources", data={
            "csrf_token": csrf_token,
            "action": "ignore_observation",
            "observation_id": self.ignored_observation_id,
            "expected_decision_id": str(self.ignored_decision.id),
        })
        self.assertEqual(response.status_code, 403)
        self.assertEqual(
            ObservationRoutingDecision.objects(
                observation_id=self.ignored_observation_id,
            ).count(),
            1,
        )

    def test_host_group_can_be_confirmed_once_with_stale_count_guard(self):
        body, csrf_token = self._routing_page()
        self.assertIn("先按来源与 Host 批量处理", body)
        self.assertIn("source-web.invalid", body)

        stale = self.client.post("/data-sources", data={
            "csrf_token": csrf_token,
            "action": "assign_routing_group",
            "data_source_id": self.source_id,
            "domain": "source-web.invalid",
            "expected_count": "99",
            "project_environment": "{}|test".format(self.project_id),
            "teach_future": "1",
            "return_view": "routing",
        })
        self.assertEqual(stale.status_code, 302)
        self.assertEqual(
            ObservationRoutingDecision.objects(
                observation_id=self.observation_id,
            ).count(),
            1,
        )

        assigned = self.client.post("/data-sources", data={
            "csrf_token": csrf_token,
            "action": "assign_routing_group",
            "data_source_id": self.source_id,
            "domain": "source-web.invalid",
            "expected_count": "2",
            "project_environment": "{}|test".format(self.project_id),
            "teach_future": "1",
            "return_view": "routing",
        })
        self.assertEqual(assigned.status_code, 302)
        for observation_id in (
            self.observation_id,
            self.ignored_observation_id,
        ):
            latest = ObservationRoutingDecision.objects(
                observation_id=observation_id,
            ).order_by("-ctime", "-id").first()
            self.assertEqual(
                latest.decision,
                ObservationRoutingDecision.ASSIGNED,
            )
            self.assertEqual(latest.selected_project_id, self.project_id)


if __name__ == "__main__":
    unittest.main()
