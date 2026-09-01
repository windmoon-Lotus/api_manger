"""Offline dry-run stubs for the SQLi per-parameter screening adapter.

This module is intentionally network-free: it lets us exercise
`_screen_replay`, `_screen_judge`, and `_record_screen` against a controllable
response sequence (200/400/401/403/404/429/500/timeout) without any HTTP I/O.

Use ``install_replay_stub`` to patch ``replay_snapshot_with_json`` and
``install_record_stub`` to capture ``_record_screen`` invocations.
"""
from __future__ import annotations

import json
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple


# Preset canned response factories. Each returns ``(evidence, captured_json)``
# shaped like the production ``replay_snapshot_with_json`` contract.
def _ok(status: int, *, body: Any = None, elapsed_ms: int = 20,
        response_len: Optional[int] = None,
        response_sha256: str = "basehash",
        text_sample: str = "",
        response_content_type: str = "application/json",
        marker: Optional[str] = None) -> Tuple[Dict[str, Any], Any]:
    sample = text_sample
    if marker:
        sample = (sample + " " + marker).strip()
    captured = body
    if captured is None and not sample:
        captured = {"ok": True}
    return {
        "status_code": status,
        "ok": 200 <= status < 300,
        "elapsed_ms": elapsed_ms,
        "response_len": response_len if response_len is not None else len(sample) or 16,
        "response_sha256": response_sha256,
        "response_content_type": response_content_type,
        "text_sample": sample,
        "error_type": "",
        "error": "",
        "domain": "api.example.test",
    }, captured


def _err(status: Optional[int] = None, *,
         error_type: str = "ReadTimeout",
         error: str = "timed out",
         elapsed_ms: int = 0) -> Tuple[Dict[str, Any], Any]:
    return {
        "status_code": status,
        "ok": False,
        "elapsed_ms": elapsed_ms,
        "response_len": 0,
        "response_sha256": "",
        "response_content_type": "",
        "text_sample": "",
        "error_type": error_type,
        "error": error,
        "domain": "api.example.test",
    }, None


# Verdict-driving scenarios. Each scenario is a callable ``(payload_name,
# snapshot, baseline) -> (evidence, captured_json)``; ``baseline`` is a dict
# returned for the very first invocation per snapshot.
def baseline_then_payload(baseline: Tuple[Dict[str, Any], Any],
                          payload_responses: Dict[str, Tuple[Dict[str, Any], Any]]):
    """Return a stub factory: baseline on first call, then by payload name."""

    def _stub(snapshot, **_kwargs):
        from urllib.parse import parse_qs, urlsplit
        query = parse_qs(urlsplit(snapshot.url).query, keep_blank_values=True)
        candidate = ""
        for name in ("candidate", "userid", "remote_ids"):
            if name in query:
                candidate = query[name][0]
                break
        if not candidate and isinstance(snapshot.body, dict):
            candidate = str(snapshot.body.get("candidate") or "")
        # baseline call: snapshot has no payload injected
        if candidate in (None, "", "1") and not query:
            return baseline
        from apiAnalysis.tool.sqli_screen import SQLI_PAYLOADS
        payload_name = next(
            (n for n, p in SQLI_PAYLOADS.items() if p == candidate),
            None,
        )
        if payload_name and payload_name in payload_responses:
            return payload_responses[payload_name]
        return baseline

    return _stub


@dataclass
class StubRecord:
    run_id: str
    snapshot_id: str
    pathid: int
    method: str
    url: str
    payload_count: int = 0
    body_samples_keys: List[str] = field(default_factory=list)


@dataclass
class RecordCapture:
    records: List[StubRecord] = field(default_factory=list)
    failures: List[str] = field(default_factory=list)

    def install(self):
        """Return a record hook that appends to this capture."""
        def _hook(run, snapshot, evidence, result, _checkpoint):
            try:
                self.records.append(StubRecord(
                    run_id=str(getattr(run, "id", "") or ""),
                    snapshot_id=str(getattr(snapshot, "id", "") or ""),
                    pathid=int(getattr(snapshot, "pathid", 0) or 0),
                    method=str(getattr(snapshot, "method", "") or ""),
                    url=str(getattr(snapshot, "url", "") or ""),
                    payload_count=len(
                        (evidence.get("sqli_screen") or {}).get("params") or []
                    ),
                    body_samples_keys=list(
                        (evidence.get("_sqli_bodies") or {}).keys()
                    ),
                ))
            except Exception as exc:  # mirror the real except-pass contract
                self.failures.append("{}: {}".format(type(exc).__name__, exc))
        return _hook


# Public helpers. Tests import these and ``with``-patch via ``unittest.mock``.
def install_replay_stub(monkeypatch, replay_stub: Callable[..., Any]) -> None:
    monkeypatch.setattr(
        "apiAnalysis.tool.sqli_screen.replay_snapshot_with_json",
        replay_stub,
    )


def install_request_executor(monkeypatch, executor: Callable[[Callable[[], Any]], Any]) -> None:
    """Adapter prefers ``request_executor`` over the patched function if set."""

    def _wrap(snapshot, **kwargs):
        request_executor = kwargs.get("request_executor")
        if request_executor is not None:
            return request_executor(
                lambda: replay_stub(snapshot, **kwargs)
            )
        return replay_stub(snapshot, **kwargs)

    install_replay_stub(monkeypatch, _wrap)
