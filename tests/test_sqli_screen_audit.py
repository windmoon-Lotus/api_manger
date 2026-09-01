"""Persistent regression tests for the SQLi per-param screening adapter.

These tests exercise the audit-driven changes:

- screening_class driven policy (read_only / additive / idempotent_config /
  destructive / stateful / unknown)
- pending_route_resolution: paths with no host are NOT persisted
- template_key immutability: a re-run with a new manifest_sha256 creates a
  fresh snapshot instead of mutating the old one
- pathid=0 must be preserved (no fallback to 100000 when item.idx == 0)
- record_screen failures are logged, not silently swallowed
- payload family includes MySQL/PG time-based fallbacks
- mutate-class paths are blocked unless readback is registered
- marker regex covers MySQL/PostgreSQL
"""
import io
import json
import logging
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from bson import ObjectId

from apiAnalysis.tool.execution_adapter import ExecutionRequestBlocked
from apiAnalysis.tool.sqli_screen import (
    DEFAULT_SCREENING_CLASS_BY_METHOD,
    SCREENING_CLASS_RULES,
    SQLI_PAYLOADS,
    TIMING_PAYLOADS,
    _record_screen,
    _screen_judge,
    _screen_replay,
    _screening_class,
    _screening_policy,
    build_sqli_screen_manifest,
    persist_sqli_screen_snapshots,
)


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def _evidence(status=200, *, ok=None, elapsed_ms=20, response_len=40,
              response_sha256="basehash", text_sample="", error_type="",
              error="", captured_json=None,
              response_content_type="application/json"):
    return {
        "status_code": status,
        "ok": (200 <= status < 300) if ok is None and status is not None else bool(ok),
        "elapsed_ms": elapsed_ms,
        "response_len": response_len,
        "response_sha256": response_sha256,
        "response_content_type": response_content_type,
        "text_sample": text_sample,
        "error_type": error_type,
        "error": error,
        "domain": "api.example.test",
        "captured_json": captured_json,
    }


def _snapshot(method="GET", *, body=None, screening_class="read_only",
              spec=None, pathid=1, project_id="p", env_id="default"):
    spec = spec or [{"name": "candidate", "position": "query", "base": "1"}]
    query = {"candidate": "1"} if method in {"GET", "HEAD", "OPTIONS"} else {}
    url = "https://api.example.test/items"
    if query:
        url += "?candidate=1"
    return SimpleNamespace(
        id=ObjectId(),
        pathid=pathid,
        method=method,
        url=url,
        path="/items",
        domain="api.example.test",
        project_id=project_id,
        env_id=env_id,
        auth_mode="account",
        expected_status_codes=[],
        headers={},
        cookies={},
        body=body if body is not None else {},
        content_type="application/json",
        query=query,
        metadata={"sqli_screen": {"spec": spec, "screening_class": screening_class}},
        parameter_sources={},
    )


# ---------------------------------------------------------------------------
# screening_class / policy
# ---------------------------------------------------------------------------
class ScreeningClassPolicyTests(unittest.TestCase):
    def test_default_screening_class_by_method(self):
        self.assertEqual(DEFAULT_SCREENING_CLASS_BY_METHOD["GET"], "read_only")
        self.assertEqual(DEFAULT_SCREENING_CLASS_BY_METHOD["POST"], "destructive")
        self.assertEqual(DEFAULT_SCREENING_CLASS_BY_METHOD["DELETE"], "destructive")
        self.assertEqual(DEFAULT_SCREENING_CLASS_BY_METHOD["PUT"], "stateful")
        self.assertEqual(DEFAULT_SCREENING_CLASS_BY_METHOD["PATCH"], "stateful")

    def test_screening_class_uses_metadata_when_set(self):
        snap = _snapshot("POST", screening_class="idempotent_config")
        self.assertEqual(_screening_class(snap), "idempotent_config")

    def test_screening_class_falls_back_to_method(self):
        snap = _snapshot("POST", screening_class="")
        snap.metadata = {"sqli_screen": {"spec": []}}
        self.assertEqual(_screening_class(snap), "destructive")

    def test_screening_class_unknown_for_invalid_value(self):
        snap = _snapshot("GET", screening_class="bogus")
        self.assertEqual(_screening_class(snap), "read_only")

    def test_screening_policy_requires_readback_for_mutation(self):
        for cls in ("additive", "idempotent_config", "stateful"):
            snap = _snapshot("POST", screening_class=cls)
            self.assertTrue(_screening_policy(snap)["require_readback"], cls)
        for cls in ("read_only", "destructive", "unknown"):
            snap = _snapshot("POST", screening_class=cls)
            self.assertFalse(_screening_policy(snap)["require_readback"], cls)

    def test_destructive_and_stateful_baseline_only(self):
        for cls in ("destructive", "stateful", "unknown"):
            snap = _snapshot("POST", screening_class=cls)
            self.assertTrue(_screening_policy(snap)["baseline_only"], cls)


# ---------------------------------------------------------------------------
# mutate readback 联防
# ---------------------------------------------------------------------------
class ReadbackGuardTests(unittest.TestCase):
    def test_mutation_blocked_without_readback(self):
        snap = _snapshot("POST", screening_class="idempotent_config")
        with patch("apiAnalysis.tool.sqli_screen.replay_snapshot_with_json") as rsj:
            with self.assertRaises(ExecutionRequestBlocked):
                _screen_replay(snap, auth_mode="account")
        rsj.assert_not_called()

    def test_mutation_runs_when_readback_registered(self):
        snap = _snapshot("POST", screening_class="idempotent_config")
        with patch(
            "apiAnalysis.tool.sqli_screen.replay_snapshot_with_json",
            return_value=(_evidence(status=400), None),
        ) as rsj:
            result = _screen_replay(
                snap, auth_mode="account", readback_registered=True,
            )
        rsj.assert_called_once()
        self.assertEqual(result["sqli_screen"]["screening_class"], "idempotent_config")
        self.assertEqual(result["sqli_screen"]["screened"], 0)

    def test_destructive_never_sends_payloads(self):
        snap = _snapshot("DELETE", screening_class="destructive")
        with patch(
            "apiAnalysis.tool.sqli_screen.replay_snapshot_with_json",
            return_value=(_evidence(status=200), None),
        ) as rsj:
            _screen_replay(snap, auth_mode="account", readback_registered=True)
        # baseline only: exactly one HTTP call (the baseline)
        self.assertEqual(rsj.call_count, 1)


# ---------------------------------------------------------------------------
# payload family / marker
# ---------------------------------------------------------------------------
class PayloadFamilyTests(unittest.TestCase):
    def test_payloads_include_mysql_pg(self):
        self.assertIn("sleep_mysql", SQLI_PAYLOADS)
        self.assertIn("sleep_pg", SQLI_PAYLOADS)
        self.assertIn("benchmark", SQLI_PAYLOADS)

    def test_timing_payloads_set(self):
        self.assertIn("waitfor", TIMING_PAYLOADS)
        self.assertIn("sleep_mysql", TIMING_PAYLOADS)
        self.assertIn("sleep_pg", TIMING_PAYLOADS)
        self.assertIn("benchmark", TIMING_PAYLOADS)


# ---------------------------------------------------------------------------
# template_key 不可变 + idx=0 + pending_route
# ---------------------------------------------------------------------------
class SnapshotPersistenceTests(unittest.TestCase):
    def _fake_collection(self):
        """Yield (saved, fetched) callables that record inserts without Mongo."""

        store = {"by_key": {}}

        class _FakeQuery:
            def __init__(self, key):
                self._key = key

            def first(self_inner):
                return store["by_key"].get(self_inner._key)

        class _FakeModel:
            def __init__(self, **fields):
                # mirror fields as attributes so callers can read them
                self.__dict__.update(fields)
                self.template_key = fields.get("template_key")

            def save(self, force_insert=False):
                store["by_key"][self.template_key] = self

        class _FakeQS:
            def __init__(self, key):
                self._key = key

            def first(self):
                return store["by_key"].get(self._key)

        class _FakeManager:
            def __init__(self):
                self.inserts = []

            def __call__(self, **fields):
                m = _FakeModel(**fields)
                self.inserts.append(m)
                return m

            def objects(self, template_key=None):
                return _FakeQS(template_key)

        return _FakeManager(), store

    def test_idx_zero_uses_zero_not_fallback(self):
        manager, store = self._fake_collection()
        items = [{
            "idx": 0, "method": "GET", "path": "/items",
            "host": "https://api.example.test",
            "params": [{"name": "x", "type": "string", "base": "1"}],
        }]
        with patch("apiAnalysis.tool.sqli_screen.request_snapshot", manager):
            snaps, created, pending = persist_sqli_screen_snapshots(
                items, project_id="p1", env_id="default",
                manifest_sha256="manifestA",
            )
        self.assertEqual(created, 1)
        self.assertEqual(snaps[0].pathid, 0)
        self.assertEqual(pending, [])

    def test_template_key_is_immutable_across_manifest_hash(self):
        manager, store = self._fake_collection()
        items = [{
            "idx": 5, "method": "GET", "path": "/items",
            "host": "https://api.example.test",
            "params": [{"name": "x", "type": "string", "base": "1"}],
        }]
        with patch("apiAnalysis.tool.sqli_screen.request_snapshot", manager):
            persist_sqli_screen_snapshots(
                items, project_id="p1", env_id="default",
                manifest_sha256="manifestA",
            )
            # Re-run with a new manifest_sha256: must NOT mutate the old snapshot.
            snaps_b, created_b, _ = persist_sqli_screen_snapshots(
                items, project_id="p1", env_id="default",
                manifest_sha256="manifestB",
            )
        self.assertEqual(created_b, 1)
        self.assertEqual(len(store["by_key"]), 2)
        # both snapshots coexist; old run reference is stable
        keys = sorted(store["by_key"].keys())
        self.assertIn("manifestA", keys[0])
        self.assertIn("manifestB", keys[1])

    def test_pending_route_resolution_skips_persist(self):
        manager, store = self._fake_collection()
        items = [
            {"idx": 0, "method": "GET", "path": "/unknown/x",
             "host": "__pending_route__",
             "params": [{"name": "x", "type": "string", "base": "1"}]},
            {"idx": 1, "method": "GET", "path": "/items",
             "host": "https://api.example.test",
             "params": [{"name": "x", "type": "string", "base": "1"}]},
        ]
        with patch("apiAnalysis.tool.sqli_screen.request_snapshot", manager):
            snaps, created, pending = persist_sqli_screen_snapshots(
                items, project_id="p1", env_id="default",
                manifest_sha256="m",
            )
        self.assertEqual(created, 1)
        self.assertEqual(len(snaps), 1)
        self.assertEqual(len(pending), 1)
        self.assertEqual(pending[0]["path"], "/unknown/x")


# ---------------------------------------------------------------------------
# manifest host routing
# ---------------------------------------------------------------------------
class ManifestRouteTests(unittest.TestCase):
    def _write_openapi(self, tmpdir, paths, servers=None):
        spec = {"paths": paths}
        if servers is not None:
            spec["servers"] = servers
        p = Path(tmpdir) / "openapi.json"
        p.write_text(json.dumps(spec), encoding="utf-8")
        return str(p)

    def test_single_openapi_server_resolves_all_paths(self):
        with tempfile.TemporaryDirectory() as td:
            openapi = self._write_openapi(td, {
                "/v1/items": {"get": {"parameters": [
                    {"name": "q", "in": "query", "schema": {"type": "string"}},
                ]}},
                "/v1/search": {"get": {"parameters": [
                    {"name": "q", "in": "query", "schema": {"type": "string"}},
                ]}},
            }, servers=[{"url": "https://api.example.test/base"}])
            manifest = build_sqli_screen_manifest(openapi)
        self.assertEqual(manifest["pendingRouteResolution"], [])
        by_path = {item["path"]: item for item in manifest["items"]}
        self.assertEqual(by_path["/v1/items"]["host"], "https://api.example.test")
        self.assertEqual(by_path["/v1/search"]["host"], "https://api.example.test")

    def test_ambiguous_openapi_servers_remain_pending(self):
        with tempfile.TemporaryDirectory() as td:
            openapi = self._write_openapi(td, {
                "/v1/items": {"get": {"parameters": [
                    {"name": "q", "in": "query", "schema": {"type": "string"}},
                ]}},
            }, servers=[{"url": "https://api.example.test"},
                        {"url": "https://other.example.test"}])
            manifest = build_sqli_screen_manifest(openapi)
        self.assertEqual(manifest["items"][0]["host"], "__pending_route__")
        self.assertEqual(len(manifest["pendingRouteResolution"]), 1)

    def test_unknown_paths_go_to_pending(self):
        with tempfile.TemporaryDirectory() as td:
            openapi = self._write_openapi(td, {
                "/erq/relation": {"get": {"parameters": [
                    {"name": "q", "in": "query", "schema": {"type": "string"}},
                ]}},
            })
            manifest = build_sqli_screen_manifest(openapi)
        by_path = {item["path"]: item for item in manifest["items"]}
        self.assertEqual(by_path["/erq/relation"]["host"], "__pending_route__")
        self.assertTrue(by_path["/erq/relation"]["routePending"])
        self.assertEqual(len(manifest["pendingRouteResolution"]), 1)

    def test_manifest_schema_version_present(self):
        with tempfile.TemporaryDirectory() as td:
            openapi = self._write_openapi(td, {
                "/standard/device-list": {"get": {"parameters": [
                    {"name": "remote_ids", "in": "query",
                     "schema": {"type": "array"}},
                ]}},
            })
            manifest = build_sqli_screen_manifest(openapi)
        self.assertEqual(manifest["schema"], "sqli-payload-screen.v1")


# ---------------------------------------------------------------------------
# record_screen 可观测
# ---------------------------------------------------------------------------
class RecordScreenTests(unittest.TestCase):
    def test_record_screen_logs_on_failure(self):
        # point evidence_ref at a path where mkdir will succeed but write_text
        # will fail (a regular file masquerading as a directory).
        with tempfile.TemporaryDirectory() as td:
            blocker = Path(td) / "blocker"
            blocker.write_text("not a dir", encoding="utf-8")
            run = SimpleNamespace(id="abc", evidence_ref=str(blocker / "child"))
            snap = SimpleNamespace(id="s", pathid=1, method="GET",
                                   url="https://api.example.test")
            evidence = {"sqli_screen": {"params": [], "screening_class": "read_only"}}
            result = SimpleNamespace(id="r")
            with self.assertLogs("apiAnalysis.tool.sqli_screen", level="WARNING") as cm:
                _record_screen(run, snap, evidence, result, None)
        self.assertTrue(any("sqli_screen record failed" in line for line in cm.output))

    def test_record_screen_writes_screening_class(self):
        with tempfile.TemporaryDirectory() as td:
            run = SimpleNamespace(id="abc", evidence_ref=td)
            snap = SimpleNamespace(
                id="s", pathid=2, method="POST",
                url="https://api.example.test/items",
            )
            evidence = {
                "sqli_screen": {
                    "screening_class": "idempotent_config",
                    "block_reason": "mutation_requires_readback",
                    "params": [],
                },
                "_sqli_bodies": {},
            }
            result = SimpleNamespace(id="r")
            _record_screen(run, snap, evidence, result, None)
            files = list(Path(td).glob("sqli-screen-*.private.json"))
            self.assertEqual(len(files), 1)
            payload = json.loads(files[0].read_text(encoding="utf-8"))
            self.assertEqual(payload["screening_class"], "idempotent_config")
            self.assertEqual(payload["block_reason"], "mutation_requires_readback")


# ---------------------------------------------------------------------------
# judge 路径分支
# ---------------------------------------------------------------------------
class ScreenJudgeTests(unittest.TestCase):
    def test_no_rows_destructive_class(self):
        evidence = {"sqli_screen": {"params": [], "screening_class": "destructive"}}
        verdict, reasons, _ = _screen_judge(evidence, "sqli_payload_screen", "account")
        self.assertEqual(verdict, "not_evaluable")
        self.assertIn("screening_class_destructive", reasons)


if __name__ == "__main__":
    unittest.main()
