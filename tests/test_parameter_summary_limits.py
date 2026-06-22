import unittest

from apiAnalysis.db.save import _append_unique


class ParameterSummaryLimitsTest(unittest.TestCase):
    def test_append_unique_respects_limit(self):
        values = []
        seen = None
        for index in range(10):
            seen = _append_unique(values, index, seen, limit=3)

        self.assertEqual(values, [0, 1, 2])

    def test_append_unique_deduplicates_before_limit(self):
        values = []
        seen = None
        for value in [1, 1, 2, 2, 3]:
            seen = _append_unique(values, value, seen, limit=3)

        self.assertEqual(values, [1, 2, 3])


if __name__ == "__main__":
    unittest.main()
