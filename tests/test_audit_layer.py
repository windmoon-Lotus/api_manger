"""Unit tests for the post-run audit layer (tools/audit/).

All tests are offline: network calls are injected, transcripts are synthetic
stream-json lines.
"""
import json
import tempfile
import unittest
from pathlib import Path

from tools.audit.boundary_audit import (
    audit_transcript,
    extract_requests,
    host_allowed,
    host_of,
    url_exempt,
)
from tools.audit.cleanup_audit import (
    EXIT_CLEAN,
    EXIT_NOT_EVALUABLE,
    EXIT_RESIDUE,
    find_prefix_hits,
    run_sweeps,
    verdict_exit_code,
)
from tools.audit.coverage_report import coverage, extract_keys
from tools.audit.evidence_verify import verify_evidence


def transcript_line(tool_name, tool_input):
    return json.dumps({"type": "assistant", "message": {"content": [
        {"type": "tool_use", "name": tool_name, "input": tool_input},
    ]}})


class BoundaryAuditTest(unittest.TestCase):
    SCOPE = {"allowed_hosts": ["*.example.test", "api.ok.test"],
             "allowed_methods": ["GET"]}

    def _audit(self, *lines):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "t.jsonl"
            p.write_text("\n".join(lines), encoding="utf-8")
            return audit_transcript(p, self.SCOPE)

    def test_in_scope_get_passes(self):
        r = self._audit(transcript_line("Bash", {
            "command": "curl 'https://api.example.test/v1/items?a=1'"}))
        self.assertEqual(r["verdict"], "pass")
        self.assertEqual(r["distinctRequests"], 1)

    def test_out_of_scope_host_fails(self):
        r = self._audit(transcript_line("Bash", {
            "command": "curl https://evil.example.org/steal"}))
        self.assertEqual(r["verdict"], "fail")
        self.assertEqual(r["violations"][0]["kind"], "host_out_of_scope")
        self.assertEqual(r["violations"][0]["host"], "evil.example.org")

    def test_disallowed_method_fails(self):
        r = self._audit(transcript_line("Bash", {
            "command": "curl -X DELETE https://api.example.test/v1/items/1"}))
        self.assertEqual(r["verdict"], "fail")
        self.assertEqual(r["violations"][0]["kind"], "method_not_allowed")
        self.assertEqual(r["violations"][0]["method"], "DELETE")

    def test_requests_post_detected(self):
        r = self._audit(transcript_line("Bash", {
            "command": "python -c \"requests.post('https://api.example.test/v1/x')\""}))
        self.assertEqual(r["violations"][0]["method"], "POST")

    def test_write_tool_content_scanned(self):
        # .org host is outside the *.example.test allowlist
        r = self._audit(transcript_line("Write", {
            "content": "url = 'https://prod.example.org:8443/admin'"}))
        self.assertEqual(r["verdict"], "fail")
        self.assertEqual(r["violations"][0]["kind"], "host_out_of_scope")

    def test_non_tool_lines_ignored(self):
        lines = [json.dumps({"type": "user", "message": {"content": "curl https://x.example.org/a"}}),
                 json.dumps({"type": "result", "result": "done"})]
        r = self._audit(*lines)
        self.assertEqual(r["distinctRequests"], 0)
        self.assertEqual(r["verdict"], "pass")

    def test_wildcard_and_exact_hosts(self):
        self.assertTrue(host_allowed("a.example.com", ["*.example.com"], [], ""))
        self.assertTrue(host_allowed("api.ok.test", ["api.ok.test"], [], ""))
        self.assertFalse(host_allowed("example.com", ["*.example.com"], [], ""))

    def test_host_of(self):
        self.assertEqual(host_of("https://api.example.test:8443/x?y=1"),
                         "api.example.test")

    def test_extract_defaults_to_get(self):
        reqs = extract_requests("curl https://api.example.test/1")
        self.assertEqual(reqs[0]["methods"], ["GET"])

    def test_exempt_url_downgrades_to_review(self):
        # auth-chain POST on a read-only round: exempted, but still visible
        scope = dict(self.SCOPE, exempt_urls=["https://auth.example.test/"])
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "t.jsonl"
            p.write_text(transcript_line("Bash", {
                "command": "curl -X POST https://auth.example.test/ -d 'u=1'"}),
                encoding="utf-8")
            r = audit_transcript(p, scope)
        self.assertEqual(r["verdict"], "review")
        self.assertEqual(r["violations"], [])
        self.assertEqual(r["needsReview"][0]["kind"], "url_exempted")

    def test_url_exempt_matching(self):
        self.assertTrue(url_exempt("https://api.example.test/", ["https://api.example.test/"]))
        self.assertTrue(url_exempt("https://api.example.test/x?y=1",
                                   ["https://api.example.test/*"]))
        self.assertFalse(url_exempt("https://api2.example.test/",
                                    ["https://api.example.test/*"]))
        self.assertFalse(url_exempt("https://other.example.test/",
                                    ["https://api.example.test/"]))

    def test_report_redacts_sensitive_query_values(self):
        r = self._audit(transcript_line("Bash", {
            "command": "curl https://outside.example.org/x?access_token=private-value",
        }))
        self.assertEqual(r["verdict"], "fail")
        self.assertNotIn("private-value", r["violations"][0]["url"])
        self.assertIn("REDACTED", r["violations"][0]["url"])


class CleanupAuditTest(unittest.TestCase):
    def test_find_prefix_hits(self):
        body = '{"list":[{"name":"evalrun1_group_a"},{"name":"other"}]}'
        hits = find_prefix_hits(body, ["evalrun1_", "missing_"])
        self.assertEqual(len(hits), 1)
        self.assertIn("evalrun1_group_a", hits[0]["context"])

    def test_many_hits_truncated(self):
        body = "[" + ",".join(f'"evalrun1_x{i}"' for i in range(20)) + "]"
        hits = find_prefix_hits(body, ["evalrun1_"])
        previews = [h for h in hits if "context" in h]
        truncated = [h for h in hits if h.get("truncated")]
        self.assertEqual(len(previews), 5)
        self.assertEqual(truncated[0]["totalMatches"], 20)

    def test_run_sweeps_clean(self):
        config = {"sweeps": [{"url": "https://api.example.test/list", "prefixes": ["p_"]}]}
        r = run_sweeps(config, {}, 5.0, fetch=lambda url, headers, timeout: (200, '{"list":[]}'))
        self.assertEqual(r["verdict"], "clean")

    def test_run_sweeps_residue(self):
        config = {"sweeps": [{"url": "https://api.example.test/list", "prefixes": ["p_"]}]}
        r = run_sweeps(config, {}, 5.0, fetch=lambda url, headers, timeout: (200, '{"list":[{"n":"p_a"}]}'))
        self.assertEqual(r["verdict"], "residue")
        self.assertEqual(r["sweeps"][0]["hitCount"], 1)

    def test_non_200_is_not_clean(self):
        config = {"sweeps": [{"url": "https://api.example.test/list", "prefixes": ["p_"]}]}
        r = run_sweeps(config, {}, 5.0, fetch=lambda url, headers, timeout: (403, '{"forbidden": true}'))
        self.assertEqual(r["verdict"], "not_evaluable")
        self.assertEqual(r["sweeps"][0]["result"], "not_evaluable")
        self.assertIn("could not verify", r["sweeps"][0]["note"])

    def test_fetch_exception_reported(self):
        def boom(url, headers, timeout):
            raise TimeoutError("slow")
        config = {"sweeps": [{"url": "https://api.example.test/list", "prefixes": ["p_"]}]}
        r = run_sweeps(config, {}, 5.0, fetch=boom)
        self.assertEqual(r["verdict"], "not_evaluable")
        self.assertIn("TimeoutError", r["sweeps"][0]["error"])

    def test_residue_wins_over_not_evaluable(self):
        config = {"sweeps": [
            {"url": "https://api.example.test/list", "prefixes": ["p_"]},
            {"url": "https://other.example.test/list", "prefixes": ["p_"]},
        ]}

        def fetch(url, headers, timeout):
            return (200, "p_left") if "api.example.test" in url else (403, "")

        self.assertEqual(run_sweeps(config, {}, 5.0, fetch=fetch)["verdict"],
                         "residue")

    def test_clean_plus_not_evaluable_is_not_evaluable(self):
        config = {"sweeps": [
            {"url": "https://api.example.test/list", "prefixes": ["p_"]},
            {"url": "https://other.example.test/list", "prefixes": ["p_"]},
        ]}

        def fetch(url, headers, timeout):
            return (200, "[]") if "api.example.test" in url else (403, "")

        self.assertEqual(run_sweeps(config, {}, 5.0, fetch=fetch)["verdict"],
                         "not_evaluable")

    def test_verdict_exit_codes_fail_closed(self):
        self.assertEqual(verdict_exit_code("clean"), EXIT_CLEAN)
        self.assertEqual(verdict_exit_code("residue"), EXIT_RESIDUE)
        self.assertEqual(verdict_exit_code("not_evaluable"), EXIT_NOT_EVALUABLE)
        self.assertEqual(verdict_exit_code("no_sweeps"), EXIT_NOT_EVALUABLE)
        self.assertEqual(verdict_exit_code("unexpected"), EXIT_NOT_EVALUABLE)


class CoverageReportTest(unittest.TestCase):
    def test_extract_keys_shapes(self):
        self.assertEqual(extract_keys(["GET /a", "POST /b"]), ["GET /a", "POST /b"])
        self.assertEqual(extract_keys({"endpoints": ["GET /a"]}), ["GET /a"])
        self.assertEqual(extract_keys({"items": [{"method": "get", "path": "/a"}]}),
                         ["GET /a"])
        self.assertEqual(extract_keys({"results": [
            {"url": "https://api.example.test/a?x=1"},
        ]}), ["https://api.example.test/a?x=1"])
        self.assertEqual(extract_keys(None), [])

    def test_coverage_full_tiering(self):
        total = ["GET /a", "GET /b", "GET /c", "GET /d"]
        candidates = ["GET /a", "GET /b", "GET /c"]
        tested = ["GET /a", "GET /b"]
        r = coverage(total, candidates, tested)
        self.assertEqual(r["counts"], {"total": 4, "candidate": 3,
                                       "tested": 2, "tested_in_candidate": 2})
        self.assertEqual(r["ratios"]["tested_of_candidate_pct"], 66.7)
        self.assertEqual(r["ratios"]["candidate_of_total_pct"], 75.0)
        self.assertEqual(r["untested_candidates"], ["GET /c"])
        self.assertEqual(r["untested_non_candidates"], ["GET /d"])
        self.assertEqual(r["tested_outside_total"], [])
        self.assertEqual([w for w in r["warnings"] if w], [])

    def test_tested_outside_total_flagged(self):
        r = coverage(["GET /a"], ["GET /a"], ["GET /a", "GET /zzz"])
        self.assertEqual(r["tested_outside_total"], ["GET /zzz"])
        self.assertTrue(any("boundary audit" in w for w in r["warnings"] if w))

    def test_empty_denominators(self):
        r = coverage([], [], [])
        self.assertIsNone(r["ratios"]["tested_of_candidate_pct"])
        self.assertEqual(r["counts"]["total"], 0)


class EvidenceVerifyTest(unittest.TestCase):
    def _screen_evidence(self, verdict="no_signal", signals=None, true_len=1000, false_len=1000):
        def payload(name, value, length=1000, status=200, ms=50):
            return {"name": name, "value": value, "statusCode": status,
                    "elapsedMs": ms, "responseLength": length,
                    "bodyPreview": ""}
        payloads = [payload(n, v) for n, v in [
            ("quote_break", "'"), ("bool_true", "' OR '1'='1"),
            ("bool_false", "' OR '1'='2"), ("paren_bool_true", "') OR ('1'='1"),
            ("union_probe", "' UNION SELECT NULL-- -"),
            ("mysql_extractvalue", "' AND extractvalue(1,concat(0x7e,version()))-- -"),
        ]]
        payloads[1]["responseLength"] = true_len
        payloads[2]["responseLength"] = false_len
        return {"tool": "whitehat_sqli_screen",
                "results": [{
                    "url": "https://api.example.test/1?x=1", "param": "x",
                    "baseline": {"statusCode": 200, "elapsedMs": 50, "responseLength": 1000},
                    "verdict": verdict, "signals": signals or [],
                    "payloads": payloads,
                }]}

    def test_consistent_evidence_passes(self):
        r = verify_evidence(self._screen_evidence())
        self.assertEqual(r["verdict"], "pass")
        self.assertEqual(r["mismatches"], 0)

    def test_tampered_verdict_fails(self):
        # metrics show a boolean signal but stored verdict says no_signal
        ev = self._screen_evidence(verdict="no_signal", signals=[],
                                   true_len=2000, false_len=1000)
        r = verify_evidence(ev)
        self.assertEqual(r["verdict"], "fail")
        self.assertEqual(r["checks"][0]["stored"], "no_signal")
        self.assertEqual(r["checks"][0]["recomputed"], "signal")

    def test_understated_signals_fail(self):
        # verdict matches but recorded signals omit the recomputed one
        ev = self._screen_evidence(verdict="signal", signals=[],
                                   true_len=2000, false_len=1000)
        r = verify_evidence(ev)
        self.assertEqual(r["verdict"], "fail")

    def test_unknown_kind_rejected(self):
        r = verify_evidence({"tool": "something_else"})
        self.assertEqual(r["verdict"], "unsupported")

    def test_error_row_short_circuit_ok(self):
        ev = {"tool": "whitehat_sqli_screen", "results": [{
            "url": "https://api.example.test/1?x=1", "param": "x",
            "baseline": {"statusCode": 404}, "verdict": "error"}]}
        r = verify_evidence(ev)
        self.assertEqual(r["verdict"], "pass")


if __name__ == "__main__":
    unittest.main()
