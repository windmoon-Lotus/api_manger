import unittest
from types import SimpleNamespace

from apiAnalysis.tool.vulnerability_lifecycle import classify_finding_retest


def checkpoint(value="done"):
    return SimpleNamespace(status=value)


def result(result_id, verdict, outcome):
    return SimpleNamespace(id=result_id, verdict=verdict, outcome_class=outcome)


class FindingRetestTests(unittest.TestCase):
    def test_all_complete_pass_results_verify_the_fix(self):
        decision = classify_finding_retest(
            [checkpoint(), checkpoint()],
            [result("r1", "no_vuln", "pass"), result("r2", "isolated_blocked", "pass")],
            2,
        )
        self.assertEqual(decision["decision"], "verified_fixed")

    def test_candidate_reopens_even_if_another_case_is_inconclusive(self):
        decision = classify_finding_retest(
            [checkpoint(), checkpoint("error")],
            [result("r1", "potential_vuln", "candidate")],
            2,
        )
        self.assertEqual(decision["decision"], "reopened")

    def test_review_or_incomplete_evidence_stays_pending(self):
        review = classify_finding_retest(
            [checkpoint()], [result("r1", "need_review", "review")], 1,
        )
        incomplete = classify_finding_retest(
            [checkpoint("error")], [result("r2", "error", "error")], 1,
        )
        self.assertEqual(review["decision"], "pending")
        self.assertEqual(incomplete["decision"], "pending")


if __name__ == "__main__":
    unittest.main()
