import datetime as dt
import unittest
from types import SimpleNamespace

from apiAnalysis.tool.result_review import (
    latest_review_candidates,
    review_result_identity,
    review_target_label,
    unresolved_review_candidates,
)


def result(identifier, verdict, *, account_id="", pathid=101, minutes=0, related=None):
    return SimpleNamespace(
        id=identifier,
        project_id="project-1",
        env_id="test",
        check_type="unauth_access",
        related_pathid=pathid,
        snapshot_id=None,
        case_name="anonymous list",
        target={},
        auth_mode="anonymous" if not account_id else "account",
        account_id=account_id,
        verdict=verdict,
        related_vuln_id=related,
        ctime=dt.datetime(2026, 1, 1) + dt.timedelta(minutes=minutes),
    )


class ResultReviewQueueTests(unittest.TestCase):
    def test_newer_pass_supersedes_older_review_candidate(self):
        rows = [
            result("new", "no_vuln", minutes=2),
            result("old", "need_review", minutes=1),
        ]

        self.assertEqual(latest_review_candidates(rows), [])

    def test_newer_candidate_is_kept_once_for_same_case(self):
        rows = [
            result("new", "potential_vuln", minutes=2),
            result("old", "need_review", minutes=1),
        ]

        self.assertEqual([item.id for item in latest_review_candidates(rows)], ["new"])

    def test_account_scope_prevents_cross_account_suppression(self):
        rows = [
            result("member-pass", "no_vuln", account_id="member", minutes=2),
            result("owner-review", "need_review", account_id="owner", minutes=1),
        ]

        self.assertNotEqual(review_result_identity(rows[0]), review_result_identity(rows[1]))
        self.assertEqual(
            [item.id for item in latest_review_candidates(rows)],
            ["owner-review"],
        )

    def test_terminal_event_and_existing_finding_leave_active_queue(self):
        candidates = [
            result("open", "need_review"),
            result("rejected", "need_review", pathid=102),
            result("linked", "potential_vuln", pathid=103, related="finding-1"),
        ]

        rows = unresolved_review_candidates(candidates, {"rejected"})

        self.assertEqual([item.id for item in rows], ["open"])

    def test_path_normalization_groups_concrete_resource_and_template(self):
        concrete = result("one", "need_review", pathid=None)
        concrete.target = {"url": "https://api.example.test/resources/123"}
        template = result("two", "no_vuln", pathid=None)
        template.target = {"path": "/resources/{resource_id}"}

        self.assertEqual(review_result_identity(concrete), review_result_identity(template))

    def test_target_label_drops_origin_and_query_values(self):
        row = result("one", "need_review", pathid=None)
        row.method = "get"
        row.target = {"url": "https://api.example.test/resources?token=test-secret"}

        self.assertEqual(review_target_label(row), "GET /resources")


if __name__ == "__main__":
    unittest.main()
