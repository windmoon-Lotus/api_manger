import unittest

from apiAnalysis.tool.execution_effectiveness import summarize_effectiveness


class EffectivenessTests(unittest.TestCase):
    def test_counts_all_records_without_promoting_legacy_pass(self):
        rows = [{"verdict": "not_evaluable"}] * 101 + [
            {"verdict": "no_vuln"}, {"verdict": "potential_vuln"},
            {"verdict": "relation_verified", "outcome_class": "pass"},
        ]
        result = summarize_effectiveness(iter(rows))
        self.assertEqual(result["total"], 104)
        self.assertEqual(result["machine_pass"], 1)
        self.assertEqual(result["other"], 1)
        self.assertEqual(result["undetermined_percent"], 97.1)

    def test_unknown_reasons_are_not_echoed_and_repeated_reasons_count_once(self):
        result = summarize_effectiveness([{
            "verdict": "not_evaluable", "reason_codes": [
                "secret-value", "adapter_judge_required", "adapter_judge_required",
            ],
        }])
        self.assertNotIn("secret-value", str(result))
        self.assertEqual(result["actions"][0]["count"], 1)

    def test_empty_has_no_misleading_success_rate(self):
        self.assertIsNone(summarize_effectiveness([])["undetermined_percent"])

    def test_unknown_verdict_and_malformed_reasons(self):
        result = summarize_effectiveness([
            {"verdict": "new_value", "outcome_class": "pass"},
            {"verdict": "error", "reason_codes": {"secret": "value"}},
        ])
        self.assertEqual(result["other"], 1)
        self.assertEqual(result["error"], 1)
        self.assertNotIn("secret", str(result))
