"""Wiring tests for trace capture and plan seeding.

These cover the glue added so the retrieval and planning capabilities actually
run during an execution, rather than only being callable by hand.
"""

import inspect
import json
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from bson import ObjectId

from apiAnalysis.tool import trace_capture, unlock_plan
from apiAnalysis.tool.execution_scheduler import ExecutionWorker
from apiAnalysis.tool.snapshot_runner import replay_snapshot


ROOT = Path(__file__).resolve().parents[1]


def make_run(**overrides):
    base = dict(
        id=ObjectId(),
        adapter_id="snapshot_batch",
        check_type="sqli_screen",
        project_id="proj-1",
        env_id="env-1",
        account_id="acct-1",
        auth_mode="inherit",
    )
    base.update(overrides)
    return SimpleNamespace(**base)


def make_snapshot(**overrides):
    base = dict(
        id=ObjectId(),
        pathid=4242,
        method="GET",
        url="https://example.test/api/users",
        path="/api/users",
        domain="example.test",
        query={"page": "1"},
        headers={"Accept": "application/json"},
        cookies={},
        body=None,
        content_type="application/json",
        expected_status_codes=[200],
        auth_mode="inherit",
        project_id="proj-1",
        env_id="env-1",
        account_id="acct-1",
        auth_profile_revision_id="rev-1",
        auth_context_ref="ctx-1",
        metadata={},
        parameter_sources={},
    )
    base.update(overrides)
    return SimpleNamespace(**base)


class FakeResponse:
    def __init__(self, status_code=200, text='{"ok": true}',
                 content_type="application/json"):
        self.status_code = status_code
        self.text = text
        self.content = text.encode("utf-8")
        self.headers = {"Content-Type": content_type}

    def json(self):
        return json.loads(self.text)


class TraceFieldMappingTests(unittest.TestCase):
    def test_provenance_is_taken_from_the_execution(self):
        run = make_run()
        snapshot = make_snapshot()
        fields = trace_capture.build_trace_fields(
            run=run, snapshot=snapshot,
            evidence={"status_code": 200, "domain": "example.test"},
        )
        self.assertEqual(fields["run_id"], run.id)
        self.assertEqual(fields["project_id"], "proj-1")
        self.assertEqual(fields["env_id"], "env-1")
        self.assertEqual(fields["account_id"], "acct-1")
        self.assertEqual(fields["auth_profile_revision_id"], "rev-1")
        self.assertEqual(fields["snapshot_id"], snapshot.id)
        self.assertEqual(fields["pathid"], 4242)

    def test_engine_defaults_to_the_adapter_that_ran(self):
        fields = trace_capture.build_trace_fields(
            run=make_run(adapter_id="authenticated_snapshot_batch"),
            snapshot=make_snapshot(), evidence={},
        )
        self.assertEqual(fields["engine"], "authenticated_snapshot_batch")

    def test_host_and_path_are_normalised(self):
        fields = trace_capture.build_trace_fields(
            run=make_run(), snapshot=make_snapshot(domain="EXAMPLE.TEST"),
            evidence={"domain": "EXAMPLE.TEST"},
        )
        self.assertEqual(fields["host"], "example.test")
        self.assertEqual(fields["path"], "/api/users")
        self.assertEqual(fields["method"], "GET")

    def test_path_falls_back_to_the_url_path(self):
        snapshot = make_snapshot(path="", url="https://example.test/a/b?c=1")
        fields = trace_capture.build_trace_fields(
            run=make_run(), snapshot=snapshot, evidence={},
        )
        self.assertEqual(fields["path"], "/a/b")

    def test_attributable_parameter_is_recorded(self):
        snapshot = make_snapshot(metadata={"parameter_name": "userid"})
        fields = trace_capture.build_trace_fields(
            run=make_run(), snapshot=snapshot, evidence={},
        )
        self.assertEqual(fields["parameter_name"], "userid")

    def test_unattributable_parameter_is_empty_not_guessed(self):
        fields = trace_capture.build_trace_fields(
            run=make_run(), snapshot=make_snapshot(), evidence={},
        )
        self.assertEqual(fields["parameter_name"], "")
        self.assertEqual(fields["payload"], "")

    def test_parameter_sources_are_consulted_after_metadata(self):
        snapshot = make_snapshot(parameter_sources={"parameter": "tenant_id"})
        fields = trace_capture.build_trace_fields(
            run=make_run(), snapshot=snapshot, evidence={},
        )
        self.assertEqual(fields["parameter_name"], "tenant_id")

    def test_transport_failure_is_marked_unstable(self):
        fields = trace_capture.build_trace_fields(
            run=make_run(), snapshot=make_snapshot(),
            evidence={"status_code": None, "error_type": "ConnectTimeout"},
        )
        self.assertFalse(fields["baseline_stable"])
        self.assertEqual(fields["note"], "ConnectTimeout")

    def test_successful_response_does_not_claim_stability(self):
        fields = trace_capture.build_trace_fields(
            run=make_run(), snapshot=make_snapshot(), evidence={"status_code": 200},
        )
        self.assertFalse(fields["baseline_stable"])


class ResponseTextPreferenceTests(unittest.TestCase):
    def test_captured_body_wins_over_the_bounded_sample(self):
        text, source_len, complete = trace_capture.searchable_response_text(
            {"text_sample": "short", "response_len": 6},
            "a much longer captured body",
        )
        self.assertEqual(text, "a much longer captured body")
        self.assertEqual(source_len, len("a much longer captured body"))
        self.assertTrue(complete)

    def test_sample_of_a_larger_body_is_not_complete(self):
        text, source_len, complete = trace_capture.searchable_response_text(
            {"text_sample": "x" * 300, "response_len": 5000},
        )
        self.assertEqual(text, "x" * 300)
        self.assertEqual(source_len, 5000)
        self.assertFalse(complete)

    def test_sample_that_covers_the_whole_body_is_complete(self):
        text, source_len, complete = trace_capture.searchable_response_text(
            {"text_sample": '{"ok": true}', "response_len": 12},
        )
        self.assertTrue(complete)
        self.assertEqual(source_len, 12)

    def test_transport_error_text_is_still_searchable(self):
        text, source_len, complete = trace_capture.searchable_response_text(
            {"text_sample": "", "error": "host refused connection"},
        )
        self.assertEqual(text, "host refused connection")
        self.assertTrue(complete)


class TruncationHonestyTests(unittest.TestCase):
    """A sample must never be stored as if it were the whole body."""

    def test_sample_of_larger_body_marks_the_trace_truncated(self):
        stored = {}

        def fake_record_trace(**fields):
            stored.update(fields)
            return SimpleNamespace(derived_finding_ids=[])

        run = make_run()
        snapshot = make_snapshot()
        evidence = {"status_code": 200, "domain": "example.test",
                    "text_sample": "x" * 300, "response_len": 5000}
        with patch.object(trace_capture, "record_trace", side_effect=fake_record_trace):
            trace_capture.ExecutionTraceRecorder().record(
                run=run, snapshot=snapshot, evidence=evidence,
            )
        self.assertFalse(stored["source_complete"])
        self.assertEqual(stored["source_len"], 5000)

    def test_captured_full_body_is_marked_complete(self):
        stored = {}

        def fake_record_trace(**fields):
            stored.update(fields)
            return SimpleNamespace(derived_finding_ids=[])

        evidence = {"status_code": 200, "text_sample": "x" * 300, "response_len": 5000}
        with patch.object(trace_capture, "record_trace",
                          side_effect=lambda **f: stored.update(f) or SimpleNamespace()):
            trace_capture.ExecutionTraceRecorder().record(
                run=make_run(), snapshot=make_snapshot(), evidence=evidence,
                response_text="y" * 5000,
            )
        self.assertTrue(stored["source_complete"])
        self.assertEqual(stored["source_len"], 5000)


class BaselineStableSemanticsTests(unittest.TestCase):
    """Capture never claims stability; only a baseline comparison may."""

    def test_http_500_is_not_marked_stable(self):
        fields = trace_capture.build_trace_fields(
            run=make_run(), snapshot=make_snapshot(),
            evidence={"status_code": 500, "error_type": ""},
        )
        self.assertFalse(fields["baseline_stable"])

    def test_transport_failure_is_not_marked_stable(self):
        fields = trace_capture.build_trace_fields(
            run=make_run(), snapshot=make_snapshot(),
            evidence={"status_code": None, "error_type": "ConnectTimeout"},
        )
        self.assertFalse(fields["baseline_stable"])

    def test_even_a_200_is_not_marked_stable(self):
        fields = trace_capture.build_trace_fields(
            run=make_run(), snapshot=make_snapshot(),
            evidence={"status_code": 200},
        )
        self.assertFalse(fields["baseline_stable"])

    def test_status_is_still_recorded_for_a_later_comparison(self):
        fields = trace_capture.build_trace_fields(
            run=make_run(), snapshot=make_snapshot(),
            evidence={"status_code": 200},
        )
        self.assertEqual(fields["response_status"], 200)


class RecorderTests(unittest.TestCase):
    def test_disabled_recorder_never_touches_storage(self):
        recorder = trace_capture.ExecutionTraceRecorder(enabled=False)
        with patch.object(trace_capture, "record_trace") as store:
            self.assertIsNone(recorder.record(
                run=make_run(), snapshot=make_snapshot(), evidence={},
            ))
        store.assert_not_called()
        self.assertEqual(recorder.stats()["skipped"], 1)

    def test_missing_run_id_is_skipped(self):
        recorder = trace_capture.ExecutionTraceRecorder()
        with patch.object(trace_capture, "record_trace") as store:
            self.assertIsNone(recorder.record(
                run=make_run(id=None), snapshot=make_snapshot(), evidence={},
            ))
        store.assert_not_called()
        self.assertEqual(recorder.stats()["skipped"], 1)

    def test_storage_failure_is_counted_not_raised(self):
        recorder = trace_capture.ExecutionTraceRecorder()
        with patch.object(trace_capture, "record_trace", side_effect=RuntimeError("db down")):
            self.assertIsNone(recorder.record(
                run=make_run(), snapshot=make_snapshot(), evidence={},
            ))
        stats = recorder.stats()
        self.assertEqual(stats["failed"], 1)
        self.assertIn("RuntimeError", stats["last_error"])

    def test_successful_record_is_counted(self):
        recorder = trace_capture.ExecutionTraceRecorder()
        stored = SimpleNamespace(derived_finding_ids=[])
        with patch.object(trace_capture, "record_trace", return_value=stored):
            result = recorder.record(
                run=make_run(), snapshot=make_snapshot(), evidence={},
            )
        self.assertIs(result, stored)
        self.assertEqual(recorder.stats()["recorded"], 1)

    def test_trace_is_linked_to_the_result_it_produced(self):
        recorder = trace_capture.ExecutionTraceRecorder()
        stored = SimpleNamespace(derived_finding_ids=[])
        result = SimpleNamespace(id=ObjectId())
        with patch.object(trace_capture, "record_trace", return_value=stored):
            recorder.record(
                run=make_run(), snapshot=make_snapshot(), evidence={}, result=result,
            )
        self.assertEqual(stored.derived_finding_ids, [result.id])


class ReplayCallbackTests(unittest.TestCase):
    """The capture hook must not change the evidence contract."""

    def test_callback_receives_the_full_response_text(self):
        body = '{"error": "Unclosed quotation mark after the character string"}'
        seen = []
        with patch("apiAnalysis.tool.snapshot_runner.requests_request",
                   return_value=FakeResponse(text=body)):
            replay_snapshot(make_snapshot(), response_text_callback=seen.append)
        self.assertEqual(seen, [body])

    def test_evidence_stays_body_free(self):
        body = "x" * 5000
        with patch("apiAnalysis.tool.snapshot_runner.requests_request",
                   return_value=FakeResponse(text=body)):
            evidence = replay_snapshot(make_snapshot(), response_text_callback=lambda _: None)
        self.assertNotIn("response_text", evidence)
        self.assertLessEqual(len(evidence["text_sample"]), 300)

    def test_evidence_is_unchanged_when_no_callback_is_given(self):
        with patch("apiAnalysis.tool.snapshot_runner.requests_request",
                   return_value=FakeResponse()):
            evidence = replay_snapshot(make_snapshot())
        self.assertNotIn("response_text", evidence)
        self.assertEqual(evidence["status_code"], 200)

    def test_a_failing_callback_does_not_break_the_replay(self):
        def boom(_text):
            raise RuntimeError("recorder exploded")

        with patch("apiAnalysis.tool.snapshot_runner.requests_request",
                   return_value=FakeResponse()):
            evidence = replay_snapshot(make_snapshot(), response_text_callback=boom)
        self.assertEqual(evidence["status_code"], 200)


class PlanSeedingTests(unittest.TestCase):
    def test_disabled_is_a_noop(self):
        with patch.object(unlock_plan, "seed_default_plan") as seed:
            report = unlock_plan.ensure_plan_seeded(
                project_id="p", env_id="e", enabled=False,
            )
        self.assertFalse(report["seeded"])
        self.assertEqual(report["reason"], "disabled")
        seed.assert_not_called()

    def test_incomplete_scope_is_refused(self):
        with patch.object(unlock_plan, "seed_default_plan") as seed:
            report = unlock_plan.ensure_plan_seeded(project_id="p", env_id="")
        self.assertEqual(report["reason"], "incomplete_scope")
        seed.assert_not_called()

    def test_existing_plan_takes_the_fast_path(self):
        query = MagicMock()
        query.only.return_value.first.return_value = object()
        with patch.object(unlock_plan, "unlock_step") as model:
            model.objects.return_value = query
            with patch.object(unlock_plan, "seed_default_plan") as seed:
                report = unlock_plan.ensure_plan_seeded(project_id="p", env_id="e")
        self.assertEqual(report["reason"], "already_seeded")
        seed.assert_not_called()

    def test_missing_plan_is_seeded(self):
        query = MagicMock()
        query.only.return_value.first.return_value = None
        with patch.object(unlock_plan, "unlock_step") as model:
            model.objects.return_value = query
            with patch.object(unlock_plan, "seed_default_plan",
                              return_value={"created_steps": 10, "created_facts": 5}) as seed:
                report = unlock_plan.ensure_plan_seeded(project_id="p", env_id="e")
        self.assertTrue(report["seeded"])
        self.assertEqual(report["created_steps"], 10)
        self.assertEqual(report["created_facts"], 5)
        seed.assert_called_once_with(project_id="p", env_id="e")

    def test_failure_is_reported_not_raised(self):
        query = MagicMock()
        query.only.return_value.first.return_value = None
        with patch.object(unlock_plan, "unlock_step") as model:
            model.objects.return_value = query
            with patch.object(unlock_plan, "seed_default_plan",
                              side_effect=RuntimeError("db down")):
                report = unlock_plan.ensure_plan_seeded(project_id="p", env_id="e")
        self.assertFalse(report["seeded"])
        self.assertIn("RuntimeError", report["reason"])


class PerRequestTraceTests(unittest.TestCase):
    """A lifecycle replay fires several requests; each must get its own trace."""

    def test_each_captured_response_is_recorded_separately(self):
        recorder = trace_capture.ExecutionTraceRecorder()
        with patch.object(trace_capture, "record_trace",
                          return_value=SimpleNamespace(derived_finding_ids=[])) as store:
            for ordinal, text in enumerate(("before", "mutated", "after", "final")):
                recorder.record(run=make_run(), snapshot=make_snapshot(),
                                evidence={}, response_text=text, ordinal=ordinal)
        self.assertEqual(store.call_count, 4)
        notes = [call.kwargs["note"] for call in store.call_args_list]
        self.assertEqual(notes, ["request#0", "request#1", "request#2", "request#3"])

    def test_ordinal_is_visible_in_the_note(self):
        recorder = trace_capture.ExecutionTraceRecorder()
        with patch.object(trace_capture, "record_trace",
                          return_value=SimpleNamespace(derived_finding_ids=[])) as store:
            recorder.record(run=make_run(), snapshot=make_snapshot(),
                            evidence={}, response_text="body", ordinal=2)
        self.assertEqual(store.call_args.kwargs["note"], "request#2")


class WiringTests(unittest.TestCase):
    def test_worker_accepts_a_trace_recorder(self):
        self.assertIn("trace_recorder", inspect.signature(ExecutionWorker.__init__).parameters)

    def test_scheduler_records_after_the_result_is_stored(self):
        source = (ROOT / "apiAnalysis/tool/execution_scheduler.py").read_text(encoding="utf-8")
        self.assertIn("self.trace_recorder.record(", source)
        self.assertIn("RESPONSE_TEXT_ADAPTER_IDS", source)
        record_at = source.index("self.trace_recorder.record(")
        self.assertGreater(record_at, source.index("record_execution_result("))

    def test_scheduler_appends_captured_responses_instead_of_overwriting(self):
        source = (ROOT / "apiAnalysis/tool/execution_scheduler.py").read_text(encoding="utf-8")
        self.assertIn("captured_response_text.append(", source)
        self.assertNotIn("captured_response_text[:] = [", source)

    def test_response_text_is_only_requested_from_adapters_that_accept_it(self):
        self.assertEqual(
            trace_capture.RESPONSE_TEXT_ADAPTER_IDS,
            frozenset({"snapshot_batch", "authenticated_snapshot_batch"}),
        )

    def test_project_context_seeds_the_plan_on_binding(self):
        source = (ROOT / "apiAnalysis/project_context.py").read_text(encoding="utf-8")
        self.assertIn("ensure_plan_seeded", source)

    def test_worker_cli_defaults_to_recording(self):
        source = (ROOT / "tools/run_execution_worker.py").read_text(encoding="utf-8")
        self.assertIn("--no-record-traces", source)
        self.assertIn("ExecutionTraceRecorder", source)


if __name__ == "__main__":
    unittest.main()
