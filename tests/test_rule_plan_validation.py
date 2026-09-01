import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from apiAnalysis.tool.rule_plan_validation import (
    RuleDraftValidationError,
    build_rule_draft_validation_plan,
    enqueue_rule_draft_validation,
)


class RulePlanValidationTests(unittest.TestCase):
    @patch("apiAnalysis.tool.rule_plan_validation.build_mutation_lifecycle_plan")
    @patch("apiAnalysis.tool.rule_plan_validation.raw_data")
    @patch("apiAnalysis.tool.rule_plan_validation.security_test_plan")
    def test_build_binds_immutable_drafts_to_preflight(self, plans, assets, build):
        plans.DRAFT = "draft"
        plans.objects.return_value.order_by.return_value = [
            SimpleNamespace(id="d1", scope={
                "pathids": [10, 11], "draft_sha256": "a" * 64,
                "execution_allowed": False,
            })
        ]
        assets.objects.return_value.only.return_value = [SimpleNamespace(ptah_id=10)]
        build.return_value = SimpleNamespace(plan_sha256="b" * 64, candidates=(1,), preflight_only=True)
        plan = build_rule_draft_validation_plan(
            "p", "e", "r", selected_pathids=(10,), archive_value_index=2,
        )
        self.assertEqual(plan.selected_mutation_pathids, (10,))
        self.assertEqual(len(plan.promotion_sha256), 64)
        build.assert_called_once()
        self.assertEqual(build.call_args.kwargs["archive_value_index"], 2)

    @patch("apiAnalysis.tool.rule_plan_validation.enqueue_mutation_lifecycle")
    def test_enqueue_requires_promotion_hash(self, enqueue):
        plan = SimpleNamespace(promotion_sha256="a" * 64)
        with self.assertRaises(RuleDraftValidationError):
            enqueue_rule_draft_validation(plan, "wrong")
        enqueue.assert_not_called()
