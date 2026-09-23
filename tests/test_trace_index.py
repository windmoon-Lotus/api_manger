import datetime as dt
import unittest
from bson import ObjectId
from unittest.mock import patch

from apiAnalysis.tool import trace_index
from apiAnalysis.tool.trace_index import (
    MAX_RESPONSE_TEXT_CHARS,
    TRUNCATION_MARKER,
    body_sha256,
    bounded_snippet,
    bound_response_text,
    build_search_query,
    derive_signal_class,
    describe_hit,
    detect_error_evidence,
    detect_error_signatures,
    new_trace_id,
    record_trace,
    render_response_text,
    search_prior_evidence,
    summarize_hits,
)
from apiAnalysis.db.collection import request_trace


MSSQL_ERROR = (
    "System.Web.Services.Protocols.SoapException: Server was unable to process request. "
    "---&gt; System.Data.SqlClient.SqlException: Unclosed quotation mark after the "
    "character string ''."
)
MYSQL_ERROR = (
    "You have an error in your SQL syntax; check the manual that corresponds to your "
    "MySQL server version for the right syntax to use near '''' at line 1"
)


class ErrorSignatureTests(unittest.TestCase):
    def test_sql_server_signal_is_detected(self):
        self.assertIn("sql_syntax_mssql", detect_error_signatures(MSSQL_ERROR))

    def test_mysql_signal_is_detected(self):
        self.assertIn("sql_syntax_mysql", detect_error_signatures(MYSQL_ERROR))

    def test_dialects_do_not_cross_contaminate(self):
        mssql_classes = detect_error_signatures(MSSQL_ERROR)
        mysql_classes = detect_error_signatures(MYSQL_ERROR)
        self.assertNotIn("sql_syntax_mysql", mssql_classes)
        self.assertNotIn("sql_syntax_mssql", mysql_classes)

    def test_evidence_keeps_the_matched_token(self):
        evidence = detect_error_evidence(MSSQL_ERROR)
        self.assertIn("unclosed quotation mark", evidence["sql_syntax_mssql"])

    def test_clean_response_has_no_signature(self):
        self.assertEqual(detect_error_signatures('{"data": []}'), [])
        self.assertEqual(detect_error_signatures(""), [])

    def test_detection_is_case_insensitive(self):
        self.assertIn("sql_syntax_mssql", detect_error_signatures("UNCLOSED QUOTATION MARK"))


class TextBoundTests(unittest.TestCase):
    def test_short_text_is_kept_whole(self):
        text, truncated = bound_response_text("abc", limit=10)
        self.assertEqual(text, "abc")
        self.assertFalse(truncated)

    def test_long_text_is_bounded_and_marked(self):
        text, truncated = bound_response_text("x" * 50, limit=10)
        self.assertTrue(truncated)
        self.assertTrue(text.startswith("x" * 10))
        self.assertTrue(text.endswith(TRUNCATION_MARKER))

    def test_truncation_never_claims_completeness(self):
        text, _ = bound_response_text("x" * (MAX_RESPONSE_TEXT_CHARS + 1))
        self.assertTrue(text.endswith(TRUNCATION_MARKER))

    def test_structured_body_renders_to_searchable_text(self):
        self.assertEqual(render_response_text({"a": 1}), '{"a": 1}')
        self.assertEqual(render_response_text("already text"), "already text")
        self.assertEqual(render_response_text(None), "")


class TraceIdentityTests(unittest.TestCase):
    def test_identity_is_stable_for_the_same_observation(self):
        arguments = dict(engine="sqli", run_id="r1", host="api.example.com",
                         path="/users", method="get", parameter_name="id",
                         payload="1'", observed_at="2026-09-16T00:00:00", response_hash="h")
        self.assertEqual(new_trace_id(**arguments), new_trace_id(**arguments))

    def test_identity_changes_with_payload(self):
        base = dict(engine="sqli", run_id="r1", host="h", path="/p", method="GET")
        self.assertNotEqual(new_trace_id(payload="1'", **base),
                            new_trace_id(payload="1\"", **base))

    def test_identity_is_case_insensitive_on_method_and_host(self):
        self.assertEqual(
            new_trace_id(host="API.example.com", method="get", path="/p"),
            new_trace_id(host="api.example.com", method="GET", path="/p"),
        )


class SignalClassTests(unittest.TestCase):
    def test_error_signature_forces_error_class(self):
        self.assertEqual(
            derive_signal_class(["sql_syntax_mssql"], 500), request_trace.ERROR_SIGNAL
        )

    def test_explicit_class_wins(self):
        self.assertEqual(
            derive_signal_class(["sql_syntax_mssql"], 500, "boolean_signal"),
            "boolean_signal",
        )

    def test_no_status_is_undetermined_not_safe(self):
        self.assertEqual(derive_signal_class([], None), request_trace.UNDETERMINED)

    def test_clean_response_with_status_is_no_signal(self):
        self.assertEqual(derive_signal_class([], 200), request_trace.NO_SIGNAL)


class SearchQueryTests(unittest.TestCase):
    def test_text_search_passes_through_unescaped_for_mongoengine(self):
        query = build_search_query(text=MSSQL_ERROR)
        self.assertEqual(query["response_text__icontains"], MSSQL_ERROR)

    def test_signature_and_status_filters_are_combined(self):
        query = build_search_query(
            error_signatures=["sql_syntax_mssql"], signal_classes=["error_signal"],
            host="API.example.com", stable_only=True,
        )
        self.assertEqual(query["error_signatures__in"], ["sql_syntax_mssql"])
        self.assertEqual(query["signal_class__in"], ["error_signal"])
        self.assertEqual(query["host"], "api.example.com")
        self.assertTrue(query["baseline_stable"])

    def test_empty_filters_produce_empty_query(self):
        self.assertEqual(build_search_query(), {})

    def test_exclusion_accepts_object_id_and_hex_string(self):
        oid = ObjectId()
        self.assertEqual(build_search_query(exclude_run_id=oid)["run_id__ne"], oid)
        self.assertEqual(build_search_query(exclude_run_id=str(oid))["run_id__ne"], oid)

    def test_malformed_exclusion_raises_instead_of_failing_open(self):
        with self.assertRaises(ValueError):
            build_search_query(exclude_run_id="not-an-object-id")
        with self.assertRaises(ValueError):
            build_search_query(exclude_run_ids=["also-bad"])

    def test_repository_local_style_absent_exclusion_is_omitted(self):
        self.assertNotIn("run_id__ne", build_search_query(exclude_run_id=None))


class PriorEvidenceTests(unittest.TestCase):
    @patch("apiAnalysis.tool.trace_index.search_traces", return_value=[])
    def test_calling_run_is_excluded(self, search):
        own_run = ObjectId()
        search_prior_evidence(run_id=own_run, error_signatures=["sql_syntax_mssql"])
        self.assertEqual(search.call_args.kwargs["exclude_run_id"], own_run)

    @patch("apiAnalysis.tool.trace_index.search_traces", return_value=[])
    def test_caller_cannot_widen_away_the_guard(self, search):
        own_run = ObjectId()
        search_prior_evidence(run_id=own_run, exclude_run_id=ObjectId(),
                              exclude_run_ids=[ObjectId()])
        self.assertEqual(search.call_args.kwargs["exclude_run_id"], own_run)
        self.assertNotIn("exclude_run_ids", search.call_args.kwargs)

    def test_searching_without_a_run_is_refused(self):
        with self.assertRaises(ValueError):
            search_prior_evidence(run_id=None)

    @patch("apiAnalysis.tool.trace_index.search_traces", return_value=[])
    def test_account_exclusion_is_forwarded(self, search):
        search_prior_evidence(run_id=ObjectId(), exclude_account_id="peer")
        self.assertEqual(search.call_args.kwargs["exclude_account_id"], "peer")


class RecordTraceTests(unittest.TestCase):
    @patch("apiAnalysis.tool.trace_index.request_trace.save")
    def test_record_bounds_text_and_classifies_signal(self, save):
        trace = record_trace(
            engine="fullsqli_screen", host="API.example.com", path="/users",
            method="get", response_status=500, response_text=MSSQL_ERROR,
            parameter_name="userid", payload="1'", account_id="owner",
            check_type="sqli",
        )
        self.assertEqual(trace.host, "api.example.com")
        self.assertEqual(trace.method, "GET")
        self.assertEqual(trace.error_signatures, ["sql_syntax_mssql"])
        self.assertEqual(trace.signal_class, request_trace.ERROR_SIGNAL)
        self.assertFalse(trace.response_truncated)
        save.assert_called_once()

    @patch("apiAnalysis.tool.trace_index.request_trace.save")
    def test_record_marks_truncation(self, save):
        trace = record_trace(
            engine="sqli", host="h", path="/p", method="GET", response_status=200,
            response_text="y" * 100, text_limit=5,
        )
        self.assertTrue(trace.response_truncated)
        self.assertTrue(trace.response_text.endswith(TRUNCATION_MARKER))
        self.assertEqual(trace.response_len, 100)
        save.assert_called_once()

    @patch("apiAnalysis.tool.trace_index.request_trace.save")
    def test_record_keeps_provenance_dimensions(self, save):
        run_id = ObjectId()
        trace = record_trace(
            engine="phase2_nonget", host="h", path="/p", method="POST",
            response_status=400, response_text="bad", run_id=run_id,
            project_id="p1", env_id="e1", account_id="owner",
            auth_profile_revision_id="rev-1", payload="1'", parameter_name="sn",
        )
        self.assertEqual(trace.run_id, run_id)
        self.assertEqual(trace.project_id, "p1")
        self.assertEqual(trace.auth_profile_revision_id, "rev-1")
        self.assertEqual(trace.payload, "1'")
        save.assert_called_once()

    @patch("apiAnalysis.tool.trace_index.request_trace.save")
    def test_record_rejects_malformed_run_id(self, save):
        with self.assertRaises(ValueError):
            record_trace(engine="sqli", host="h", path="/p", method="GET",
                         response_status=200, response_text="ok", run_id="bad-id")
        save.assert_not_called()

    @patch("apiAnalysis.tool.trace_index.request_trace.save")
    def test_record_derives_text_from_structured_body(self, save):
        trace = record_trace(
            engine="sqli", host="h", path="/p", method="GET", response_status=500,
            response_body={"error": "Unclosed quotation mark"},
        )
        self.assertIn("unclosed quotation mark", trace.response_text.lower())
        self.assertEqual(trace.error_signatures, ["sql_syntax_mssql"])
        self.assertEqual(trace.body_sha256, body_sha256(trace.response_text))
        save.assert_called_once()


class SnippetTests(unittest.TestCase):
    def test_snippet_centres_on_the_match(self):
        text = "A" * 300 + "Unclosed quotation mark" + "B" * 300
        snippet = bounded_snippet(text, "unclosed quotation mark", window=20)
        self.assertIn("Unclosed quotation mark", snippet)
        self.assertTrue(snippet.startswith("..."))
        self.assertTrue(snippet.endswith("..."))

    def test_snippet_without_a_needle_returns_a_bounded_head(self):
        snippet = bounded_snippet("A" * 500, "", window=10)
        self.assertEqual(snippet, "A" * 20)

    def test_snippet_of_empty_text_is_empty(self):
        self.assertEqual(bounded_snippet("", "x"), "")


class SummarizeTests(unittest.TestCase):
    @staticmethod
    def _hit(**overrides):
        defaults = dict(
            error_signatures=["sql_syntax_mssql"], signal_class="error_signal",
            engine="fullsqli_screen", host="api.example.com", account_id="owner",
            run_id=ObjectId(),
        )
        defaults.update(overrides)
        return request_trace(**defaults)

    def test_counts_are_grouped_by_provenance(self):
        hits = [
            self._hit(),
            self._hit(engine="slapi_fuzz_sqli", account_id="peer",
                      host="other.example.com",
                      error_signatures=["sql_syntax_mysql"]),
        ]
        summary = summarize_hits(hits)
        self.assertEqual(summary["hit_count"], 2)
        self.assertEqual(summary["distinct_runs"], 2)
        self.assertEqual(summary["by_engine"],
                         {"fullsqli_screen": 1, "slapi_fuzz_sqli": 1})
        self.assertEqual(summary["by_account"], {"owner": 1, "peer": 1})
        self.assertEqual(summary["by_signature"],
                         {"sql_syntax_mssql": 1, "sql_syntax_mysql": 1})

    def test_unattributed_account_is_labelled_not_hidden(self):
        summary = summarize_hits([self._hit(account_id="")])
        self.assertEqual(summary["by_account"], {"unattributed": 1})

    def test_empty_result_reports_zero_not_success(self):
        summary = summarize_hits([])
        self.assertEqual(summary["hit_count"], 0)
        self.assertEqual(summary["distinct_runs"], 0)


class DescribeHitTests(unittest.TestCase):
    def test_describe_returns_provenance_and_bounded_excerpt(self):
        run_id = ObjectId()
        hit = request_trace(
            trace_id="t1", run_id=run_id, engine="fullsqli_screen",
            host="api.example.com", path="/users", method="GET",
            parameter_name="userid", payload="1'", account_id="owner",
            response_status=500, response_text="prefix " + MSSQL_ERROR + " suffix",
            error_signatures=["sql_syntax_mssql"], signal_class="error_signal",
            observed_at=dt.datetime(2026, 9, 16, 12, 0, 0),
        )
        described = describe_hit(hit, needle="unclosed quotation mark", snippet_window=10)
        self.assertEqual(described["run_id"], str(run_id))
        self.assertEqual(described["engine"], "fullsqli_screen")
        self.assertEqual(described["account_id"], "owner")
        self.assertEqual(described["observed_at"], "2026-09-16T12:00:00")
        self.assertIn("Unclosed quotation mark", described["snippet"])
        self.assertNotIn("suffix", described["snippet"])

    def test_describe_exposes_truncation_and_supersede_link(self):
        replacement = ObjectId()
        hit = request_trace(
            trace_id="t2", host="h", path="/p", method="GET",
            response_text="cut" + TRUNCATION_MARKER, response_truncated=True,
            superseded_by=replacement,
        )
        described = describe_hit(hit)
        self.assertTrue(described["response_truncated"])
        self.assertEqual(described["superseded_by"], str(replacement))

    def test_describe_does_not_expose_the_whole_body(self):
        hit = request_trace(
            trace_id="t3", host="h", path="/p", method="GET",
            response_text="SENSITIVE-HEAD " + "x" * 5000 + " SENSITIVE-TAIL",
        )
        described = describe_hit(hit, snippet_window=10)
        self.assertLess(len(described["snippet"]), 200)
        self.assertNotIn("SENSITIVE-TAIL", described["snippet"])


if __name__ == "__main__":
    unittest.main()
