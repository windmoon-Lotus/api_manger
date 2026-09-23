import unittest

from bson import ObjectId
from types import SimpleNamespace
from unittest.mock import patch

from apiAnalysis.db.collection import precondition_fact, unlock_step
from apiAnalysis.tool import unlock_plan
from apiAnalysis.tool.unlock_plan import (
    FACT_ENTERPRISE_CONTEXT_TOKEN,
    FACT_ENTERPRISE_OWNER_ACCOUNT,
    FACT_GRPC_BODY_SAMPLE,
    FACT_SQL_USERID_CONCATENATED,
    blocking_summary,
    default_plan,
    evaluate_steps,
    ready_steps,
    record_fact,
)


def step(key, requires=(), produces=(), priority=100, status=unlock_step.PENDING, **extra):
    return SimpleNamespace(
        step_key=key, title=extra.get("title", key), serves=extra.get("serves", ""),
        priority=priority, status=status, requires_fact_keys=list(requires),
        produces_fact_keys=list(produces),
    )


def fact(key, state):
    return SimpleNamespace(fact_key=key, state=state)


def satisfied(*keys):
    return [fact(key, precondition_fact.SATISFIED) for key in keys]


def plan_as_steps(status_overrides=None):
    overrides = status_overrides or {}
    return [
        step(entry["step_key"], entry["requires_fact_keys"], entry["produces_fact_keys"],
             priority=entry["priority"], status=overrides.get(entry["step_key"],
                                                               unlock_step.PENDING))
        for entry in default_plan()
    ]


class DefaultPlanIntegrityTests(unittest.TestCase):
    def test_step_keys_are_unique(self):
        keys = [entry["step_key"] for entry in default_plan()]
        self.assertEqual(len(keys), len(set(keys)))

    def test_every_required_fact_is_produced_by_some_step(self):
        plan = default_plan()
        produced = {key for entry in plan for key in entry["produces_fact_keys"]}
        required = {key for entry in plan for key in entry["requires_fact_keys"]}
        self.assertTrue(required.issubset(produced),
                        "unproducible requirements: {}".format(sorted(required - produced)))

    def test_every_referenced_fact_has_a_title(self):
        plan = default_plan()
        referenced = {key for entry in plan
                      for key in entry["requires_fact_keys"] + entry["produces_fact_keys"]}
        self.assertTrue(referenced.issubset(set(unlock_plan.FACT_TITLES)))

    def test_graph_is_acyclic(self):
        producers = {}
        for entry in default_plan():
            for key in entry["produces_fact_keys"]:
                producers.setdefault(key, []).append(entry["step_key"])
        graph = {
            entry["step_key"]: [
                producer
                for key in entry["requires_fact_keys"]
                for producer in producers.get(key, [])
            ]
            for entry in default_plan()
        }
        remaining = {node: set(deps) for node, deps in graph.items()}
        while remaining:
            free = [node for node, deps in remaining.items() if not deps]
            self.assertTrue(free, "dependency cycle among {}".format(sorted(remaining)))
            for node in free:
                remaining.pop(node)
            for deps in remaining.values():
                deps.difference_update(free)

    def test_at_least_one_step_can_start_immediately(self):
        evaluated = evaluate_steps(plan_as_steps(), [])
        self.assertTrue([item for item in evaluated
                         if item["readiness"] == unlock_step.READY])


class EvaluateStepsTests(unittest.TestCase):
    def test_step_without_requirements_is_ready(self):
        self.assertEqual(evaluate_steps([step("a")], [])[0]["readiness"], unlock_step.READY)

    def test_unmet_requirement_blocks_and_names_the_fact(self):
        evaluated = evaluate_steps([step("b", requires=["f1"])], [])
        self.assertEqual(evaluated[0]["readiness"], unlock_step.BLOCKED)
        self.assertEqual(evaluated[0]["blocked_by"], ["f1"])

    def test_unknown_fact_blocks_like_unsatisfied(self):
        evaluated = evaluate_steps([step("b", requires=["f1"])],
                                   [fact("f1", precondition_fact.UNKNOWN)])
        self.assertEqual(evaluated[0]["readiness"], unlock_step.BLOCKED)

    def test_satisfied_fact_unlocks_the_dependent_step(self):
        steps = [step("a", produces=["f1"]), step("b", requires=["f1"])]
        before = evaluate_steps(steps, [])
        after = evaluate_steps(steps, satisfied("f1"))
        self.assertEqual(before[1]["readiness"], unlock_step.BLOCKED)
        self.assertEqual(after[1]["readiness"], unlock_step.READY)
        self.assertEqual(after[1]["blocked_by"], [])

    def test_unsatisfied_fact_does_not_unlock(self):
        evaluated = evaluate_steps([step("b", requires=["f1"])],
                                   [fact("f1", precondition_fact.UNSATISFIED)])
        self.assertEqual(evaluated[0]["readiness"], unlock_step.BLOCKED)

    def test_terminal_status_outranks_readiness(self):
        self.assertEqual(
            evaluate_steps([step("a", status=unlock_step.DONE)], [])[0]["readiness"],
            unlock_step.DONE,
        )

    def test_in_progress_is_reported_as_such(self):
        self.assertEqual(
            evaluate_steps([step("a", status=unlock_step.IN_PROGRESS)], [])[0]["readiness"],
            unlock_step.IN_PROGRESS,
        )

    def test_done_step_with_lost_precondition_is_flagged(self):
        evaluated = evaluate_steps(
            [step("a", requires=["f1"], status=unlock_step.DONE)], []
        )
        self.assertEqual(evaluated[0]["precondition_lost"], ["f1"])

    def test_healthy_done_step_is_not_flagged(self):
        evaluated = evaluate_steps(
            [step("a", requires=["f1"], status=unlock_step.DONE)], satisfied("f1")
        )
        self.assertEqual(evaluated[0]["precondition_lost"], [])

    def test_abandoned_producer_deadlocks_the_dependent_step(self):
        steps = [
            step("a", produces=["f1"], status=unlock_step.ABANDONED),
            step("b", requires=["f1"]),
        ]
        evaluated = {item["step_key"]: item for item in evaluate_steps(steps, [])}
        self.assertEqual(evaluated["b"]["deadlocked_by_abandoned"], ["a"])

    def test_live_producer_does_not_deadlock(self):
        steps = [step("a", produces=["f1"]), step("b", requires=["f1"])]
        evaluated = {item["step_key"]: item for item in evaluate_steps(steps, [])}
        self.assertEqual(evaluated["b"]["deadlocked_by_abandoned"], [])

    def test_downstream_count_reflects_dependents(self):
        steps = [step("a", produces=["f1"]), step("b", requires=["f1"]),
                 step("c", requires=["f1"]), step("d")]
        evaluated = {item["step_key"]: item for item in evaluate_steps(steps, [])}
        self.assertEqual(evaluated["a"]["downstream_count"], 2)
        self.assertEqual(evaluated["d"]["downstream_count"], 0)

    def test_terminal_dependents_are_not_counted_as_downstream(self):
        steps = [step("a", produces=["f1"]),
                 step("b", requires=["f1"], status=unlock_step.DONE)]
        evaluated = {item["step_key"]: item for item in evaluate_steps(steps, [])}
        self.assertEqual(evaluated["a"]["downstream_count"], 0)

    def test_results_are_ordered_by_priority(self):
        steps = [step("late", priority=90), step("early", priority=10)]
        self.assertEqual([item["step_key"] for item in evaluate_steps(steps, [])],
                         ["early", "late"])


class ReadyStepTests(unittest.TestCase):
    def test_only_ready_steps_are_returned(self):
        steps = [step("a"), step("b", requires=["f1"])]
        self.assertEqual([item["step_key"] for item in ready_steps(steps, [])], ["a"])

    def test_ready_set_grows_when_the_fact_lands(self):
        steps = [step("a"), step("b", requires=["f1"])]
        self.assertEqual([item["step_key"] for item in ready_steps(steps, satisfied("f1"))],
                         ["a", "b"])


class BlockingSummaryTests(unittest.TestCase):
    def test_blocking_fact_is_ranked_by_how_much_it_blocks(self):
        steps = [step("b", requires=["f_common"]), step("c", requires=["f_common"]),
                 step("d", requires=["f_rare"])]
        summary = blocking_summary(steps, [])
        self.assertEqual(list(summary["blocked_by_fact"]), ["f_common", "f_rare"])
        self.assertEqual(summary["blocked_by_fact"]["f_common"], ["b", "c"])

    def test_terminal_steps_are_not_reported_as_blocked(self):
        steps = [step("b", requires=["f1"], status=unlock_step.DONE)]
        self.assertEqual(blocking_summary(steps, [])["blocked_by_fact"], {})

    def test_empty_plan_reports_zero_not_success(self):
        summary = blocking_summary([], [])
        self.assertEqual(summary["total_steps"], 0)
        self.assertEqual(summary["ready"], [])


class RecordFactTests(unittest.TestCase):
    def test_unknown_state_is_rejected(self):
        with self.assertRaises(ValueError):
            record_fact(fact_key="f1", state="probably-fine")

    @patch("apiAnalysis.tool.unlock_plan.precondition_fact.objects")
    def test_satisfied_fact_stores_evidence_and_timestamp(self, objects):
        record_fact(fact_key=FACT_ENTERPRISE_CONTEXT_TOKEN,
                    state=precondition_fact.SATISFIED, project_id="p1", env_id="e1",
                    evidence_ref="private://sha256/abc",
                    value_summary={"ent_id": "redacted"})
        calls = objects.return_value.update_one.call_args
        self.assertEqual(calls.kwargs["set__state"], precondition_fact.SATISFIED)
        self.assertEqual(calls.kwargs["set__evidence_ref"], "private://sha256/abc")
        self.assertIsNotNone(calls.kwargs["set__satisfied_at"])
        self.assertTrue(calls.kwargs.get("upsert"))

    @patch("apiAnalysis.tool.unlock_plan.precondition_fact.objects")
    def test_unsatisfied_fact_clears_the_satisfied_timestamp(self, objects):
        record_fact(fact_key=FACT_GRPC_BODY_SAMPLE, state=precondition_fact.UNSATISFIED)
        calls = objects.return_value.update_one.call_args
        self.assertIsNone(calls.kwargs["set__satisfied_at"])

    @patch("apiAnalysis.tool.unlock_plan.precondition_fact.objects")
    def test_satisfied_without_evidence_is_refused(self, objects):
        with self.assertRaises(ValueError):
            record_fact(fact_key=FACT_SQL_USERID_CONCATENATED,
                        state=precondition_fact.SATISFIED)
        objects.assert_not_called()

    @patch("apiAnalysis.tool.unlock_plan.precondition_fact.objects")
    def test_trace_id_counts_as_evidence(self, objects):
        record_fact(fact_key=FACT_SQL_USERID_CONCATENATED,
                    state=precondition_fact.SATISFIED,
                    evidence_trace_ids=[ObjectId()])
        self.assertIsNotNone(objects.return_value.update_one.call_args)

    @patch("apiAnalysis.tool.unlock_plan.precondition_fact.objects")
    def test_run_id_counts_as_evidence(self, objects):
        record_fact(fact_key=FACT_SQL_USERID_CONCATENATED,
                    state=precondition_fact.SATISFIED,
                    satisfied_by_run_id=ObjectId())
        self.assertIsNotNone(objects.return_value.update_one.call_args)

    @patch("apiAnalysis.tool.unlock_plan.precondition_fact.objects")
    def test_manual_confirmation_is_recorded_in_the_note(self, objects):
        record_fact(fact_key=FACT_SQL_USERID_CONCATENATED,
                    state=precondition_fact.SATISFIED, manual_confirmation=True)
        note = objects.return_value.update_one.call_args.kwargs["set__note"]
        self.assertIn("manual_confirmation", note)

    @patch("apiAnalysis.tool.unlock_plan.precondition_fact.objects")
    def test_unsatisfied_still_needs_no_evidence(self, objects):
        record_fact(fact_key=FACT_GRPC_BODY_SAMPLE,
                    state=precondition_fact.UNSATISFIED)
        self.assertIsNotNone(objects.return_value.update_one.call_args)

    @patch("apiAnalysis.tool.unlock_plan.precondition_fact.objects")
    def test_default_title_comes_from_the_registry(self, objects):
        record_fact(fact_key=FACT_SQL_USERID_CONCATENATED,
                    state=precondition_fact.SATISFIED, manual_confirmation=True)
        calls = objects.return_value.update_one.call_args
        self.assertEqual(calls.kwargs["set__title"],
                         unlock_plan.FACT_TITLES[FACT_SQL_USERID_CONCATENATED])

    @patch("apiAnalysis.tool.unlock_plan.precondition_fact.objects")
    def test_fact_is_scoped_by_project_and_env(self, objects):
        record_fact(fact_key="f1", state=precondition_fact.SATISFIED,
                    project_id="p1", env_id="e1", manual_confirmation=True)
        self.assertEqual(
            objects.call_args.kwargs,
            {"project_id": "p1", "env_id": "e1", "fact_key": "f1"},
        )


class EnterpriseChainTests(unittest.TestCase):
    """The motivating case: one fact should advance several downstream steps."""

    def test_minting_the_token_unlocks_both_tree_directions(self):
        steps = plan_as_steps()
        before = {item["step_key"]: item for item in evaluate_steps(steps, [])}
        after = {item["step_key"]: item
                 for item in evaluate_steps(steps, satisfied(FACT_ENTERPRISE_CONTEXT_TOKEN))}
        self.assertEqual(before["enterprise.read_org_tree"]["readiness"], unlock_step.BLOCKED)
        self.assertEqual(before["enterprise.write_org_tree"]["readiness"], unlock_step.BLOCKED)
        self.assertEqual(after["enterprise.read_org_tree"]["readiness"], unlock_step.READY)
        self.assertEqual(after["enterprise.write_org_tree"]["readiness"], unlock_step.READY)

    def test_owner_account_alone_does_not_unlock_the_tree(self):
        evaluated = {item["step_key"]: item for item in evaluate_steps(
            plan_as_steps(), satisfied(FACT_ENTERPRISE_OWNER_ACCOUNT))}
        self.assertEqual(evaluated["enterprise.mint_context_token"]["readiness"],
                         unlock_step.READY)
        self.assertEqual(evaluated["enterprise.read_org_tree"]["readiness"],
                         unlock_step.BLOCKED)

    def test_proven_sql_fact_unlocks_the_sibling_probe(self):
        evaluated = {item["step_key"]: item for item in evaluate_steps(
            plan_as_steps(), satisfied(FACT_SQL_USERID_CONCATENATED))}
        self.assertEqual(evaluated["sqli.sibling_family_probe"]["readiness"],
                         unlock_step.READY)

    def test_blocking_summary_ranks_the_enterprise_token_first(self):
        summary = blocking_summary(plan_as_steps(), [])
        self.assertIn(FACT_ENTERPRISE_CONTEXT_TOKEN, summary["blocked_by_fact"])


if __name__ == "__main__":
    unittest.main()
