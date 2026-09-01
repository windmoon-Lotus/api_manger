import unittest
from types import SimpleNamespace

from apiAnalysis.tool.parameter_identity import (
    aggregate_occurrences,
    parameter_identity,
    preferred_parameter_name,
)


class ParameterIdentityTests(unittest.TestCase):
    def test_flattened_paths_and_known_aliases_share_one_identity(self):
        self.assertEqual(parameter_identity("credits[].user_id"), "userid")
        self.assertEqual(parameter_identity("user_id"), "userid")
        self.assertEqual(parameter_identity("userid"), "userid")
        self.assertEqual(parameter_identity("userId"), "userid")
        self.assertEqual(parameter_identity("cts[].count"), "count")

    def test_display_name_prefers_the_dominant_readable_alias(self):
        self.assertEqual(
            preferred_parameter_name("userid", {"user_id": 137, "userid": 66}),
            "user_id",
        )

    def test_occurrences_keep_raw_paths_as_evidence_after_grouping(self):
        rows = [
            SimpleNamespace(parameter="credits[].user_id", canonical_name="user_id"),
            SimpleNamespace(parameter="user_id", canonical_name="user_id"),
            SimpleNamespace(parameter="userid", canonical_name="userid"),
        ]
        groups = aggregate_occurrences(rows)
        self.assertEqual(set(groups), {"userid"})
        self.assertEqual(groups["userid"]["parameter"], "user_id")
        self.assertEqual(
            groups["userid"]["raw_paths"],
            {"credits[].user_id", "user_id", "userid"},
        )


if __name__ == "__main__":
    unittest.main()
