"""Unit tests for the standalone white-hat SQLi first-pass screener.

Covers the pure functions only - no network. The request loop is exercised
indirectly via evaluate_param with synthetic response tuples.
"""
import unittest
from urllib.parse import urlparse, parse_qsl

from tools.whitehat_sqli_screen import (
    BOOLEAN_DIFF_THRESHOLD_PCT,
    PAYLOADS,
    ERROR_RE,
    diff_pct,
    evaluate_param,
    load_headers,
    load_targets,
    set_param,
)


def resp(status=200, length=100, ms=50, body=""):
    return {"statusCode": status, "elapsedMs": ms, "responseLength": length,
            "bodySample": body}


class SetParamTest(unittest.TestCase):
    URL = "https://api.example.test/items?keep=1&candidate=7&lang=en"

    def test_replaces_only_target_param(self):
        out = set_param(self.URL, "candidate", "' OR '1'='1")
        pairs = dict(parse_qsl(urlparse(out).query, keep_blank_values=True))
        self.assertEqual(pairs["candidate"], "' OR '1'='1")
        self.assertEqual(pairs["keep"], "1")
        self.assertEqual(pairs["lang"], "en")

    def test_preserves_pair_order(self):
        out = set_param(self.URL, "candidate", "x")
        keys = [k for k, _ in parse_qsl(urlparse(out).query, keep_blank_values=True)]
        self.assertEqual(keys, ["keep", "candidate", "lang"])

    def test_missing_param_raises(self):
        with self.assertRaises(ValueError):
            set_param(self.URL, "nope", "x")


class DiffPctTest(unittest.TestCase):
    def test_zero_baseline(self):
        self.assertEqual(diff_pct(0, 0), 0.0)

    def test_symmetric(self):
        self.assertAlmostEqual(diff_pct(100, 80), 20.0)
        self.assertAlmostEqual(diff_pct(80, 100), 20.0)


class ErrorPatternTest(unittest.TestCase):
    def test_mysql_syntax_error(self):
        self.assertTrue(ERROR_RE.search("You have an error in your SQL syntax; check the manual"))

    def test_ora_error(self):
        self.assertTrue(ERROR_RE.search("ORA-00942: table or view does not exist"))

    def test_clean_json_no_match(self):
        self.assertIsNone(ERROR_RE.search('{"code":0,"data":{"list":[]}}'))


class EvaluateParamTest(unittest.TestCase):
    BASELINE = resp(status=200, length=1000, ms=50, body='{"code":0,"data":{"total":42}}')

    def _all_payloads(self, **overrides):
        out = []
        for name, value in PAYLOADS:
            out.append((name, value, overrides.get(name, resp(status=200, length=1000, ms=50))))
        return out

    def test_identical_responses_no_signal(self):
        ev = evaluate_param(self.BASELINE, self._all_payloads())
        self.assertEqual(ev["verdict"], "no_signal")
        self.assertEqual(ev["signals"], [])

    def test_boolean_signal(self):
        results = self._all_payloads(
            bool_true=resp(status=200, length=2000),
            bool_false=resp(status=200, length=1000),
        )
        ev = evaluate_param(self.BASELINE, results)
        self.assertIn("boolean_based", ev["signals"])
        self.assertEqual(ev["verdict"], "signal")

    def test_boolean_requires_both_diffs(self):
        # true/false differ but true equals baseline -> control failed, no signal.
        results = self._all_payloads(
            bool_true=resp(status=200, length=1000),
            bool_false=resp(status=200, length=800),
        )
        ev = evaluate_param(self.BASELINE, results)
        self.assertNotIn("boolean_based", ev["signals"])

    def test_error_based_signal(self):
        results = self._all_payloads(
            mysql_extractvalue=resp(status=500, length=300, body="SQLSTATE[HY000]: syntax error"),
        )
        ev = evaluate_param(self.BASELINE, results)
        self.assertIn("error_based", ev["signals"])
        self.assertEqual(ev["error_hits"][0]["payload"], "mysql_extractvalue")

    def test_union_column_count_signal(self):
        results = self._all_payloads(
            union_probe=resp(status=500, body="each UNION query must have the same number of columns"),
        )
        ev = evaluate_param(self.BASELINE, results)
        self.assertIn("union_column_count", ev["signals"])

    def test_time_based_signal(self):
        from tools.whitehat_sqli_screen import TIME_BASED_PAYLOADS
        results = self._all_payloads(time_sleep=resp(status=200, length=1000, ms=3200))
        for name, value in TIME_BASED_PAYLOADS:
            results.append((name, value, resp(status=200, length=1000, ms=3200)))
        ev = evaluate_param(self.BASELINE, results)
        self.assertIn("time_based", ev["signals"])

    def test_time_below_threshold_not_signal(self):
        from tools.whitehat_sqli_screen import TIME_BASED_PAYLOADS
        results = self._all_payloads()
        for name, value in TIME_BASED_PAYLOADS:
            results.append((name, value, resp(status=200, length=1000, ms=900)))
        ev = evaluate_param(self.BASELINE, results)
        self.assertNotIn("time_based", ev["signals"])

    def test_empty_baseline_observability_note(self):
        baseline = resp(status=200, length=2, body="[]")
        ev = evaluate_param(baseline, self._all_payloads())
        self.assertEqual(ev["verdict"], "no_signal")
        self.assertTrue(any("observability" in n for n in ev["notes"]),
                        "empty baseline must produce an observability caveat")

    def test_status_anomaly_recorded(self):
        results = self._all_payloads(quote_break=resp(status=500, length=10))
        ev = evaluate_param(self.BASELINE, results)
        names = [a["payload"] for a in ev["code_anomalies"]]
        self.assertIn("quote_break", names)


class ThresholdTest(unittest.TestCase):
    def test_threshold_is_five_percent(self):
        self.assertEqual(BOOLEAN_DIFF_THRESHOLD_PCT, 5.0)


class LoadTargetsTest(unittest.TestCase):
    def _write(self, tmp, payload):
        import json
        path = tmp / "targets.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path

    def test_accepts_list_and_dict(self):
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            t1 = self._write(tmp, [{"url": "https://h.test/a?x=1", "param": "x"}])
            t2 = self._write(tmp, {"targets": [{"url": "https://h.test/a?x=1", "param": "x"}]})
            self.assertEqual(len(load_targets(t1)), 1)
            self.assertEqual(len(load_targets(t2)), 1)

    def test_rejects_missing_url_or_param(self):
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as d:
            path = self._write(Path(d), [{"url": "https://h.test/a?x=1"}])
            with self.assertRaises(SystemExit):
                load_targets(path)

    def test_rejects_param_not_in_query(self):
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as d:
            path = self._write(Path(d), [{"url": "https://h.test/a?x=1", "param": "y"}])
            with self.assertRaises(SystemExit):
                load_targets(path)


class LoadHeadersTest(unittest.TestCase):
    def test_headers_file_and_explicit_override(self):
        import json
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "headers.json"
            path.write_text(json.dumps({"Authorization": "private", "X-A": "1"}),
                            encoding="utf-8")
            headers = load_headers(["X-A: 2"], str(path))
        self.assertEqual(headers["Authorization"], "private")
        self.assertEqual(headers["X-A"], "2")
        self.assertEqual(headers["User-Agent"], "whitehat-sqli-screen/1.0")

    def test_headers_file_must_be_object(self):
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "headers.json"
            path.write_text("[]", encoding="utf-8")
            with self.assertRaises(SystemExit):
                load_headers([], str(path))

if __name__ == "__main__":
    unittest.main()
