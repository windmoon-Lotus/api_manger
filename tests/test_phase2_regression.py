import unittest

from apiAnalysis.ai.schema import AiJudgeResult
from apiAnalysis.rule.scoring import score_rule_from_evidence
from apiAnalysis.rule.fusion import ai_score, fuse_rule_ai


class Phase2RegressionTest(unittest.TestCase):
    def test_ai_schema_normalization(self):
        payload = {
            "result": "vuln",
            "risk_level": "HIGH",
            "confidence": 90,
            "reason": "looks risky",
            "reason_codes": ["R1"],
            "model": "demo-model",
        }
        result = AiJudgeResult.from_payload(payload, prompt_ver="v1")
        self.assertEqual(result.verdict, "potential_vuln")
        self.assertEqual(result.risk_level, "high")
        self.assertAlmostEqual(result.confidence, 0.9)
        self.assertEqual(result.prompt_ver, "v1")

    def test_rule_scoring_high_risk_path(self):
        evidence = {
            "scenario": "unauth",
            "test_success": True,
            "baseline_status": 403,
            "baseline_success": False,
            "text_len_ratio": 1.0,
            "json_overlap": 0.9,
            "test_text_len": 120,
        }
        scored = score_rule_from_evidence(evidence)
        self.assertEqual(scored["rule_result"], "potential_vuln")
        self.assertGreaterEqual(scored["rule_score"], 75.0)

    def test_rule_scoring_unauth_no_baseline_not_escalated(self):
        # A public endpoint that returns 200 with a body, but with no baseline
        # comparison available, must not be auto-escalated to potential_vuln.
        evidence = {
            "scenario": "unauth",
            "test_success": True,
            "baseline_status": None,
            "baseline_success": False,
            "text_len_ratio": 0.0,
            "json_overlap": 0.0,
            "test_text_len": 320,
        }
        scored = score_rule_from_evidence(evidence)
        self.assertEqual(scored["rule_result"], "need_review")
        self.assertLess(scored["rule_score"], 75.0)

    def test_fusion_score_output(self):
        score = ai_score("potential_vuln", "high", 0.9)
        fused = fuse_rule_ai(rule_score=80.0, ai_score_value=score)
        self.assertIn(fused["final_result"], {"potential_vuln", "need_review", "no_vuln"})
        self.assertGreaterEqual(fused["final_score"], 0.0)
        self.assertLessEqual(fused["final_score"], 100.0)


if __name__ == "__main__":
    unittest.main()

