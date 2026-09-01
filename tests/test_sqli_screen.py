import unittest
from types import SimpleNamespace
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from bson import ObjectId

from apiAnalysis.tool.sqli_screen import (
    SQLI_PAYLOADS,
    _screen_judge,
    _screen_replay,
    _targets,
    build_sqli_screen_adapter,
)


class ReplayStub:
    def __init__(self, baseline=None, probes=None):
        self.baseline = dict(baseline or evidence())
        self.probes = dict(probes or {})
        self.calls = []

    def __call__(self, snapshot, **_kwargs):
        self.calls.append(snapshot)
        value = ""
        query = parse_qs(urlsplit(snapshot.url).query, keep_blank_values=True)
        if "candidate" in query:
            value = query["candidate"][0]
        elif isinstance(snapshot.body, dict):
            value = str(snapshot.body.get("candidate") or "")
        payload_name = next(
            (name for name, payload in SQLI_PAYLOADS.items() if payload == value),
            None,
        )
        response = dict(self.probes.get(payload_name) or self.baseline)
        captured_json = response.pop("captured_json", None)
        return response, captured_json


def evidence(status=200, *, ok=None, elapsed_ms=20, response_len=40,
             response_sha256="basehash", text_sample="", error_type="",
             error="", captured_json=None):
    return {
        "status_code": status,
        "ok": (200 <= status < 300) if ok is None and status is not None else bool(ok),
        "elapsed_ms": elapsed_ms,
        "response_len": response_len,
        "response_sha256": response_sha256,
        "response_content_type": "application/json",
        "text_sample": text_sample,
        "error_type": error_type,
        "error": error,
        "domain": "api.example.test",
        "captured_json": captured_json,
    }


def snapshot(method="GET", *, body=None, positions=("query",)):
    spec = [
        {"name": "candidate", "position": position, "base": "1"}
        for position in positions
    ]
    query = {"candidate": "1"} if "query" in positions else {}
    url = "https://api.example.test/items"
    if query:
        url += "?candidate=1"
    return SimpleNamespace(
        id=ObjectId(),
        pathid=1,
        method=method,
        url=url,
        path="/items",
        domain="api.example.test",
        project_id="project",
        auth_mode="account",
        expected_status_codes=[],
        headers={},
        cookies={},
        body=body if body is not None else {},
        content_type="application/json",
        query=query,
        metadata={"sqli_screen": {"spec": spec}},
        parameter_sources={},
    )


def run_screen(replay_stub, target=None):
    with patch(
            "apiAnalysis.tool.sqli_screen.replay_snapshot_with_json",
            side_effect=replay_stub):
        return _screen_replay(target or snapshot(), auth_mode="account")


class SqliScreenTests(unittest.TestCase):
    def test_non_get_query_and_body_targets_are_supported_after_confirmation(self):
        target = snapshot("POST", body={"body_value": "1"})
        target.url = "https://api.example.test/items?query_value=1"
        target.query = {"query_value": "1"}
        target.metadata = {"sqli_screen": {"spec": [
            {"name": "query_value", "position": "query", "base": "1"},
            {"name": "body_value", "position": "body", "base": "1"},
        ]}}
        positions = {row["position"] for row in _targets(target)}
        self.assertEqual(positions, {"query", "body"})

        adapter = build_sqli_screen_adapter()
        run = SimpleNamespace(
            adapter_id=adapter.adapter_id,
            adapter_version=adapter.adapter_version,
            auth_mode="account",
        )
        adapter.validate(run, allow_mutation=True)
        self.assertTrue(adapter.supports_mutation)
        self.assertEqual(adapter.request_policy_scope, "request")

    def test_baseline_transport_error_stops_before_payloads(self):
        replay = ReplayStub(evidence(
            status=None,
            ok=False,
            error_type="ReadTimeout",
            error="timed out",
        ))
        result = run_screen(replay)
        self.assertEqual(len(replay.calls), 1)
        self.assertEqual(result["error_type"], "ReadTimeout")
        self.assertEqual(result["sqli_screen"]["screened"], 0)
        self.assertEqual(
            _screen_judge(result, "sqli_payload_screen", "account")[0],
            "error",
        )

    def test_baseline_not_found_is_not_evaluable_and_sends_no_payloads(self):
        replay = ReplayStub(evidence(status=404, ok=False))
        result = run_screen(replay)
        self.assertEqual(len(replay.calls), 1)
        self.assertEqual(result["sqli_screen"]["baseline_reason"], "baseline_not_found")
        self.assertEqual(
            _screen_judge(result, "sqli_payload_screen", "account")[0],
            "not_evaluable",
        )

    def test_probe_transport_error_is_not_a_status_difference(self):
        replay = ReplayStub(probes={
            "orig_true": evidence(
                status=None,
                ok=False,
                error_type="ConnectTimeout",
                error="timed out",
            ),
        })
        result = run_screen(replay)
        row = result["sqli_screen"]["params"][0]
        true_probe = next(
            probe for probe in row["probes"] if probe["payload"] == "orig_true"
        )
        self.assertIsNone(true_probe["status"])
        self.assertEqual(true_probe["flags"], ["transport_error"])
        self.assertEqual(row["signals"], [])
        self.assertEqual(row["verdict"], "NOT_EVALUABLE")

    def test_rate_limit_does_not_create_boolean_or_strong_signal(self):
        replay = ReplayStub(probes={
            "orig_true": evidence(status=429, ok=False),
            "orig_false": evidence(),
        })
        result = run_screen(replay)
        row = result["sqli_screen"]["params"][0]
        self.assertEqual(row["signals"], [])
        self.assertFalse(row["strong_signature"])
        self.assertEqual(row["verdict"], "NOT_EVALUABLE")

    def test_only_markers_new_relative_to_baseline_create_signal(self):
        unchanged = ReplayStub(baseline=evidence(text_sample="Exception"))
        unchanged_result = run_screen(unchanged)
        self.assertEqual(unchanged_result["sqli_screen"]["interest"], [])

        added = ReplayStub(
            baseline=evidence(text_sample="Exception"),
            probes={"quote": evidence(text_sample="Exception SQL syntax")},
        )
        added_result = run_screen(added)
        row = added_result["sqli_screen"]["params"][0]
        self.assertIn("new_error_marker", row["signals"])
        self.assertEqual(row["verdict"], "INTEREST")

    def test_timing_requires_ratio_and_absolute_delay(self):
        tiny = ReplayStub(
            baseline=evidence(elapsed_ms=1),
            probes={"waitfor": evidence(elapsed_ms=4)},
        )
        tiny_result = run_screen(tiny)
        self.assertNotIn(
            "waitfor_time_anomaly",
            tiny_result["sqli_screen"]["params"][0]["signals"],
        )

        delayed = ReplayStub(
            baseline=evidence(elapsed_ms=100),
            probes={"waitfor": evidence(elapsed_ms=3100)},
        )
        delayed_result = run_screen(delayed)
        self.assertIn(
            "waitfor_time_anomaly",
            delayed_result["sqli_screen"]["params"][0]["signals"],
        )

    def test_report_status_pair_is_strong_only_in_expected_direction(self):
        replay = ReplayStub(probes={
            "orig_true": evidence(status=500, ok=False, response_len=100,
                                  response_sha256="truehash"),
            "orig_false": evidence(),
        })
        result = run_screen(replay)
        row = result["sqli_screen"]["params"][0]
        self.assertIn("boolean_status_divergence", row["signals"])
        self.assertEqual(
            row["strong_signals"], ["report_true_500_false_baseline"]
        )
        self.assertEqual(
            _screen_judge(result, "sqli_payload_screen", "account")[:2],
            ("need_review", ["sqli_report_signature"]),
        )

        arbitrary = ReplayStub(probes={
            "orig_true": evidence(status=400, ok=False),
            "orig_false": evidence(),
        })
        arbitrary_result = run_screen(arbitrary)
        arbitrary_row = arbitrary_result["sqli_screen"]["params"][0]
        self.assertIn("boolean_status_divergence", arbitrary_row["signals"])
        self.assertFalse(arbitrary_row["strong_signature"])

    def test_same_status_meaningful_body_pair_is_detected(self):
        replay = ReplayStub(probes={
            "orig_true": evidence(response_len=100, response_sha256="truehash"),
            "orig_false": evidence(),
        })
        result = run_screen(replay)
        row = result["sqli_screen"]["params"][0]
        self.assertIn("boolean_body_divergence", row["signals"])
        self.assertEqual(row["verdict"], "INTEREST")

    def test_small_dynamic_body_difference_is_ignored(self):
        replay = ReplayStub(probes={
            "orig_true": evidence(response_len=45, response_sha256="dynamic"),
            "orig_false": evidence(),
        })
        result = run_screen(replay)
        row = result["sqli_screen"]["params"][0]
        self.assertNotIn("boolean_body_divergence", row["signals"])
        self.assertEqual(row["verdict"], "CLEAN")

    def test_blocked_screen_is_not_reported_as_no_vulnerability(self):
        replay = ReplayStub(probes={
            name: evidence(status=400, ok=False)
            for name in SQLI_PAYLOADS
        })
        result = run_screen(replay)
        row = result["sqli_screen"]["params"][0]
        self.assertEqual(row["verdict"], "BLOCKED")
        verdict, reasons, _ = _screen_judge(
            result, "sqli_payload_screen", "account"
        )
        self.assertEqual(verdict, "not_evaluable")
        self.assertEqual(reasons, ["payload_screen_blocked"])

    def test_complete_clean_screen_has_limited_no_signal_conclusion(self):
        result = run_screen(ReplayStub())
        verdict, reasons, confidence = _screen_judge(
            result, "sqli_payload_screen", "account"
        )
        self.assertEqual(verdict, "no_vuln")
        self.assertEqual(reasons, ["no_sqli_signal_in_payload_screen"])
        self.assertEqual(confidence, 0.7)


if __name__ == "__main__":
    unittest.main()
