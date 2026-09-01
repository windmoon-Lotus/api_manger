import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from bson import ObjectId

from apiAnalysis.tool.test_plan import (
    activate_plan,
    create_next_version,
    create_plan,
    plan_content_sha256,
    plan_pathids,
    schedule_plan_execution,
)
from apiAnalysis.tool.result_review import (
    VERDICT_OUTCOME_MAP,
    project_outcome_class,
)
from apiAnalysis.tool.vulnerability_lifecycle import (
    VALID_TRANSITIONS,
    _validate_transition,
)
class TestPlanExecutionTests(unittest.TestCase):
    @staticmethod
    def _plan(**overrides):
        values = {
            "id": ObjectId(),
            "name": "owner baseline",
            "project_id": "project-1",
            "env_id": "test",
            "version": 2,
            "status": "active",
            "check_type": "snapshot_baseline",
            "adapter_id": "snapshot_batch",
            "adapter_version": "1",
            "auth_mode": "anonymous",
            "auth_profile_id": "",
            "scope": {
                "pathids": [42],
                "target_origins": ["https://api.example.test"],
            },
            "execution_policy": {
                "max_workers": 1,
                "per_host_workers": 1,
                "request_timeout_seconds": 15,
            },
            "snapshot_filter": {"pathids": [42]},
            "request_budget": 1,
        }
        values.update(overrides)
        return SimpleNamespace(**values)

    def test_plan_hash_is_stable_and_bound_to_executable_content(self):
        first = self._plan()
        second = self._plan(id=ObjectId())
        self.assertEqual(plan_content_sha256(first), plan_content_sha256(second))
        second.scope = {"pathids": [43]}
        self.assertNotEqual(plan_content_sha256(first), plan_content_sha256(second))

    def test_plan_pathids_require_explicit_bounded_scope(self):
        self.assertEqual(plan_pathids(self._plan()), [42])
        with self.assertRaises(ValueError):
            plan_pathids(self._plan(scope={}, snapshot_filter={}))
        with self.assertRaises(ValueError):
            plan_pathids(self._plan(
                scope={"pathids": [42, 43]},
                snapshot_filter={},
                request_budget=1,
            ))

    @patch("apiAnalysis.tool.execution_scheduler.enqueue_snapshot_batch")
    @patch("apiAnalysis.tool.execution_contract.create_execution_snapshot")
    @patch("apiAnalysis.tool.test_plan.raw_data")
    @patch("apiAnalysis.tool.test_plan.get_plan")
    def test_active_plan_creates_fresh_snapshot_and_enqueues(
            self, get_plan_mock, raw_data_mock, create_snapshot_mock,
            enqueue_mock):
        plan = self._plan()
        get_plan_mock.return_value = plan
        raw_data_mock.objects.return_value.first.return_value = SimpleNamespace(
            project_id="project-1",
        )
        snapshot_id = ObjectId()
        create_snapshot_mock.return_value = SimpleNamespace(
            id=snapshot_id,
            url="https://api.example.test/items",
        )
        enqueue_mock.return_value = (
            SimpleNamespace(id=ObjectId(), status="queued"),
            True,
        )

        _run, created = schedule_plan_execution(
            plan.id, operator="admin", run_name="manual run",
        )

        self.assertTrue(created)
        create_snapshot_mock.assert_called_once()
        kwargs = enqueue_mock.call_args.kwargs
        self.assertEqual(kwargs["snapshot_ids"], [snapshot_id])
        self.assertEqual(kwargs["operator"], "admin")
        self.assertEqual(kwargs["name"], "manual run")
        self.assertEqual(kwargs["context"].plan_version, "2")
        self.assertEqual(len(kwargs["context"].plan_sha256), 64)


class OutcomeClassProjectionTests(unittest.TestCase):
    def test_all_standard_verdicts_map_to_outcome_class(self):
        self.assertEqual(project_outcome_class("potential_vuln"), "candidate")
        self.assertEqual(project_outcome_class("need_review"), "review")
        self.assertEqual(project_outcome_class("no_vuln"), "pass")
        self.assertEqual(project_outcome_class("not_evaluable"), "blocked")
        self.assertEqual(project_outcome_class("error"), "error")

    def test_unknown_verdict_maps_to_informational(self):
        self.assertEqual(project_outcome_class("something_else"), "informational")
        self.assertEqual(project_outcome_class(""), "informational")

    def test_map_covers_all_documented_verdicts(self):
        standard = {"potential_vuln", "need_review", "no_vuln", "not_evaluable", "error"}
        self.assertTrue(standard.issubset(set(VERDICT_OUTCOME_MAP.keys())))


class VulnerabilityTransitionTests(unittest.TestCase):
    def test_open_can_transition_to_fixing(self):
        _validate_transition("open", "fixing")

    def test_open_can_transition_to_false_positive(self):
        _validate_transition("open", "false_positive")

    def test_open_can_transition_to_accepted_risk(self):
        _validate_transition("open", "accepted_risk")

    def test_open_cannot_transition_to_verified_fixed(self):
        with self.assertRaises(ValueError):
            _validate_transition("open", "verified_fixed")

    def test_fixing_can_transition_to_fixed_pending_verify(self):
        _validate_transition("fixing", "fixed_pending_verify")

    def test_fixed_pending_verify_can_transition_to_verified_fixed(self):
        _validate_transition("fixed_pending_verify", "verified_fixed")

    def test_fixed_pending_verify_can_transition_to_reopened(self):
        _validate_transition("fixed_pending_verify", "reopened")

    def test_reopened_can_transition_to_fixing(self):
        _validate_transition("reopened", "fixing")

    def test_verified_fixed_is_terminal(self):
        with self.assertRaises(ValueError):
            _validate_transition("verified_fixed", "open")

    def test_false_positive_is_terminal(self):
        with self.assertRaises(ValueError):
            _validate_transition("false_positive", "fixing")

    def test_all_states_have_defined_transitions(self):
        expected_states = {
            "open", "fixing", "fixed_pending_verify",
            "verified_fixed", "reopened", "false_positive", "accepted_risk",
        }
        terminal = {"verified_fixed", "false_positive", "accepted_risk"}
        for state in expected_states - terminal:
            self.assertIn(state, VALID_TRANSITIONS)


if __name__ == "__main__":
    unittest.main()
