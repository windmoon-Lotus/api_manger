"""The gate that refuses a pass resting on an unestablished required value.

A placeholder-driven 4xx is indistinguishable from a correct rejection, so a
required parameter whose value was never established must never let an
execution land as a clean pass.
"""

import unittest
from pathlib import Path
from unittest.mock import patch

from apiAnalysis.tool.parameter_sources import (
    PLACEHOLDER_VALUE_LITERALS,
    REQUIRED_PARAMETER_GATE_REASON,
    SOURCE_EMPTY_DEFAULT,
    SOURCE_REQ_DATA,
    SOURCE_UNRESOLVED,
    VALUE_QUALITY_OBSERVED,
    VALUE_QUALITY_PLACEHOLDER,
    VALUE_QUALITY_SAMPLED,
    VALUE_QUALITY_UNKNOWN,
    apply_required_parameter_gate,
    is_placeholder_value,
    required_parameter_quality_summary,
)


ROOT = Path(__file__).resolve().parents[1]


def source_entry(source="", quality="", required=True, position="query"):
    return {
        "position": position,
        "source": source,
        "value_quality": quality,
        "required": required,
        "type": "",
        "dependency": {},
    }


class PlaceholderValueTests(unittest.TestCase):
    def test_documentation_literals_are_placeholders(self):
        for literal in ("string", "Example", "SAMPLE", "xxx", "null"):
            self.assertTrue(is_placeholder_value(literal), literal)

    def test_empty_and_none_are_placeholders(self):
        self.assertTrue(is_placeholder_value(None))
        self.assertTrue(is_placeholder_value(""))
        self.assertTrue(is_placeholder_value([]))
        self.assertTrue(is_placeholder_value({}))

    def test_real_looking_values_are_not_placeholders(self):
        for value in (0, False, 1001, "1001", "ent-user-88", "real_value"):
            self.assertFalse(is_placeholder_value(value), value)

    def test_matching_is_case_and_space_insensitive(self):
        self.assertTrue(is_placeholder_value("  String  "))


class RequiredParameterSummaryTests(unittest.TestCase):
    def test_synthetic_required_parameter_blocks_a_pass(self):
        summary = required_parameter_quality_summary({
            "userid": source_entry(source=SOURCE_EMPTY_DEFAULT, quality=VALUE_QUALITY_UNKNOWN),
        })
        self.assertTrue(summary["blocks_pass"])
        self.assertEqual(summary["synthetic_required"], ["userid"])

    def test_unresolved_required_parameter_blocks_a_pass(self):
        summary = required_parameter_quality_summary({
            "transfer_id": source_entry(source=SOURCE_UNRESOLVED, quality=VALUE_QUALITY_UNKNOWN),
        })
        self.assertTrue(summary["blocks_pass"])

    def test_placeholder_quality_blocks_a_pass(self):
        summary = required_parameter_quality_summary({
            "transfer_id": source_entry(source=SOURCE_REQ_DATA, quality=VALUE_QUALITY_PLACEHOLDER),
        })
        self.assertTrue(summary["blocks_pass"])
        self.assertEqual(summary["placeholder_required"], ["transfer_id"])

    def test_optional_synthetic_parameter_does_not_block(self):
        summary = required_parameter_quality_summary({
            "keyword": source_entry(source=SOURCE_EMPTY_DEFAULT, required=False),
        })
        self.assertFalse(summary["blocks_pass"])
        self.assertEqual(summary["synthetic_required"], [])

    def test_sample_only_is_surfaced_without_blocking(self):
        summary = required_parameter_quality_summary({
            "userid": source_entry(source=SOURCE_REQ_DATA, quality=VALUE_QUALITY_SAMPLED),
        })
        self.assertFalse(summary["blocks_pass"])
        self.assertEqual(summary["request_sample_only_required"], ["userid"])

    def test_observed_required_parameter_does_not_block(self):
        summary = required_parameter_quality_summary({
            "userid": source_entry(source=SOURCE_REQ_DATA, quality=VALUE_QUALITY_OBSERVED),
        })
        self.assertFalse(summary["blocks_pass"])
        self.assertEqual(summary, {
            "blocks_pass": False, "synthetic_required": [],
            "placeholder_required": [], "request_sample_only_required": [],
        })

    def test_missing_or_malformed_input_does_not_block(self):
        self.assertFalse(required_parameter_quality_summary(None)["blocks_pass"])
        self.assertFalse(required_parameter_quality_summary({})["blocks_pass"])
        self.assertFalse(required_parameter_quality_summary({"a": "not-a-dict"})["blocks_pass"])

    def test_name_lists_are_bounded(self):
        sources = {
            "param_{}".format(index): source_entry(source=SOURCE_EMPTY_DEFAULT)
            for index in range(40)
        }
        summary = required_parameter_quality_summary(sources)
        self.assertEqual(len(summary["synthetic_required"]), 20)

    def test_summary_never_carries_a_parameter_value(self):
        summary = required_parameter_quality_summary({
            "userid": dict(source_entry(source=SOURCE_REQ_DATA,
                                        quality=VALUE_QUALITY_PLACEHOLDER), value="secret"),
        })
        self.assertNotIn("value", str(summary))


class RequiredParameterGateTests(unittest.TestCase):
    def test_pass_on_synthetic_value_is_downgraded(self):
        summary = {"blocks_pass": True, "synthetic_required": ["userid"]}
        verdict, reasons, confidence = apply_required_parameter_gate(
            "no_vuln", ["anonymous_authentication_required"], 0.97, summary,
        )
        self.assertEqual(verdict, "not_evaluable")
        self.assertIn(REQUIRED_PARAMETER_GATE_REASON, reasons)
        self.assertLessEqual(confidence, 0.6)

    def test_non_pass_verdicts_are_never_discarded(self):
        summary = {"blocks_pass": True, "synthetic_required": ["userid"]}
        for verdict in ("potential_vuln", "need_review", "not_evaluable", "error"):
            kept, reasons, _ = apply_required_parameter_gate(verdict, ["r"], 0.9, summary)
            self.assertEqual(kept, verdict, verdict)
            self.assertEqual(reasons, ["r"], verdict)

    def test_pass_without_issues_is_untouched(self):
        for summary in (None, {}, {"blocks_pass": False}):
            verdict, reasons, confidence = apply_required_parameter_gate(
                "no_vuln", ["anonymous_authentication_required"], 0.97, summary,
            )
            self.assertEqual(verdict, "no_vuln")
            self.assertEqual(reasons, ["anonymous_authentication_required"])
            self.assertEqual(confidence, 0.97)

    def test_idor_style_passes_are_also_gated(self):
        for verdict in ("isolated_not_found", "isolated_blocked", "blocked_own_data"):
            kept, _, _ = apply_required_parameter_gate(
                verdict, ["r"], 0.9, {"blocks_pass": True},
            )
            self.assertEqual(kept, "not_evaluable", verdict)


class WiringTests(unittest.TestCase):
    def test_placeholder_is_a_registered_quality(self):
        from apiAnalysis.tool.parameter_sources import VALUE_QUALITIES
        self.assertIn(VALUE_QUALITY_PLACEHOLDER, VALUE_QUALITIES)

    def test_scheduler_applies_the_gate_after_judging(self):
        source = (ROOT / "apiAnalysis/tool/execution_scheduler.py").read_text(encoding="utf-8")
        self.assertIn("apply_required_parameter_gate(", source)
        gate_at = source.index("apply_required_parameter_gate(")
        self.assertGreater(gate_at, source.index("adapter.judge("))

    def test_sanitized_evidence_keeps_the_quality_summary(self):
        source = (ROOT / "apiAnalysis/tool/execution_scheduler.py").read_text(encoding="utf-8")
        self.assertIn('"parameter_quality"', source)

    def test_compose_labels_placeholder_values(self):
        source = (ROOT / "apiAnalysis/tool/compose_request.py").read_text(encoding="utf-8")
        self.assertIn("VALUE_QUALITY_PLACEHOLDER", source)
        self.assertIn("is_placeholder_value(value)", source)


if __name__ == "__main__":
    unittest.main()
