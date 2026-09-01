import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from apiAnalysis.tool.observation_store import save_observation


class ObservationStoreTests(unittest.TestCase):
    @patch(
        "apiAnalysis.tool.observation_store.ensure_data_source",
        return_value=SimpleNamespace(data_source_id="source-test"),
    )
    @patch("apiAnalysis.tool.observation_store.ObservationRoutingDecision.save")
    @patch("apiAnalysis.tool.observation_store.ObservationRoutingDecision.objects")
    @patch("apiAnalysis.tool.observation_store.RequestObservation.objects")
    @patch("apiAnalysis.tool.observation_store.RequestObservation.save")
    def test_observation_keeps_header_names_not_secret_values(
            self, save, observation_objects, decision_objects,
            decision_save, ensure_source):
        observation_objects.return_value.first.return_value = None
        decision_objects.return_value.first.return_value = None
        decision_objects.return_value.order_by.return_value.first.return_value = None
        observation, decision = save_observation(
            source_type="har", source_id="run-1", method="GET",
            url="https://api.example.com/users/1?token=secret-value&page=2",
            path="/users/1",
            request_headers={"Authorization": "Bearer secret-value", "Accept": "application/json"},
            request_body=None, response_status=401, response_len=10, response_hash="HASH",
            routing_decision={
                "decision": "unassigned", "selected_project_id": "", "confidence": 0,
                "reason_codes": ["no_high_confidence_project_match"], "candidate_projects": [],
                "rule_version": "v1",
            },
        )
        self.assertEqual(decision["decision"], "unassigned")
        self.assertEqual(observation.request_metadata["header_names"], ["accept", "authorization"])
        self.assertEqual(
            observation.request_metadata["query_names"],
            ["page", "token"],
        )
        self.assertEqual(observation.url, "https://api.example.com/users/1")
        self.assertNotIn("secret-value", str(observation.request_metadata))
        self.assertNotIn("secret-value", observation.url)
        save.assert_called_once()
        decision_save.assert_called_once()
        ensure_source.assert_called_once()

    @patch(
        "apiAnalysis.tool.observation_store.ensure_data_source",
        return_value=SimpleNamespace(data_source_id="source-test"),
    )
    @patch("apiAnalysis.tool.observation_store.ObservationRoutingDecision.save")
    @patch("apiAnalysis.tool.observation_store.ObservationRoutingDecision.objects")
    @patch("apiAnalysis.tool.observation_store.RequestObservation.objects")
    def test_repeated_capture_does_not_overwrite_manual_final_decision(
            self, observation_objects, decision_objects,
            decision_save, ensure_source):
        existing = SimpleNamespace(observation_id="existing")
        observation_objects.return_value.first.return_value = existing
        latest = SimpleNamespace(
            rule_version="manual-v2",
            decision="ignored",
            selected_project_id="",
            selected_env_id="",
            candidate_projects=[],
            confidence=1.0,
            reason_codes=["manual_non_business_traffic"],
        )
        decision_objects.return_value.order_by.return_value.first.return_value = latest

        observation, decision = save_observation(
            source_type="har",
            source_id="run-1",
            method="GET",
            url="https://api.example.com/health",
            path="/health",
            routing_decision={
                "decision": "assigned",
                "selected_project_id": "wrong-project",
                "confidence": 1.0,
                "reason_codes": ["explicit_project_selection"],
                "candidate_projects": [],
                "rule_version": "v1",
            },
        )

        self.assertIs(observation, existing)
        self.assertEqual(decision["decision"], "ignored")
        self.assertEqual(decision["selected_project_id"], "")
        decision_save.assert_not_called()
        ensure_source.assert_called_once()


if __name__ == "__main__":
    unittest.main()
