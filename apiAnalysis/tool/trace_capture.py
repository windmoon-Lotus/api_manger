"""Persist one searchable trace per executed request.

Why this exists
---------------
``sanitize_execution_evidence`` keeps transport metadata only and drops body
samples on purpose, so a stored deterministic result can never leak a target's
response body.  That decision is correct -- but it is also exactly why an error
signature sweep could not be answered after the fact: the response text that
would have shown a SQL Server syntax error was discarded at the moment it was
seen, and no later query could recover it.

This module writes that text into the append-only trace chain instead, where it
is searchable across runs.  The deterministic result document is untouched, so
the redaction guarantee for stored results still holds.

A recorder, not a judge
-----------------------
Nothing here participates in severity, coverage, deduplication keys or parameter
roles, and no model output is involved (see
``docs/deterministic_vs_model_boundary.md``).  A trace records *what was seen*.

Storing a trace must never change an execution
----------------------------------------------
A trace is an observation about a run.  It therefore fails soft: any error while
recording is counted and reported, never raised, so trace storage can never
fail, retry or reclassify the execution that produced it.
"""

from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import urlsplit

from apiAnalysis.tool.trace_index import MAX_RESPONSE_TEXT_CHARS, record_trace


ENGINE_EXECUTION = "execution"

# Adapters whose replay callable accepts ``response_text_callback``.  Passing
# that keyword to any other adapter raises TypeError, so the wiring is an
# explicit allowlist rather than a blanket pass-through.  Adapters outside this
# set are still traced, using the bounded ``text_sample`` they already return;
# they simply get a narrower searchable window.
RESPONSE_TEXT_ADAPTER_IDS = frozenset({
    "snapshot_batch",
    "authenticated_snapshot_batch",
})

# Parameter attribution is best effort.  A snapshot does not always know which
# parameter was under test.  When it does not, the trace stores an empty string,
# which means "not attributable" -- never a guessed parameter name.
PARAMETER_NAME_KEYS = ("parameter_name", "parameter", "parameter_key")
PAYLOAD_KEYS = ("payload", "parameter_value", "value")


def _text(value: Any) -> str:
    return str(value if value is not None else "").strip()


def _first_text(sources: Iterable[Any], keys: Iterable[str]) -> str:
    for source in sources:
        if not isinstance(source, dict):
            continue
        for key in keys:
            found = source.get(key)
            if found not in (None, ""):
                return str(found)
    return ""


def snapshot_path(snapshot: Any) -> str:
    """The request path, falling back to the URL path when none is stored."""
    path = _text(getattr(snapshot, "path", ""))
    if path:
        return path
    url = _text(getattr(snapshot, "url", ""))
    if not url:
        return ""
    try:
        return urlsplit(url).path or ""
    except ValueError:
        return ""


def searchable_response_text(evidence: Dict[str, Any],
                             response_text: str = "") -> tuple:
    """Return ``(text, source_len, complete)`` for one observation.

    ``complete`` says whether ``text`` is the *whole* body, and ``source_len``
    is how long that body was.  Both matter: a bounded sample of a 5000-byte
    response must never be stored as a complete 300-byte body, because a later
    sweep that misses a signature would then conclude the full response did not
    contain it.

    Preference order: the full body captured during the request, then the
    bounded sample already carried by the evidence, then the transport error
    string.  A connection failure has no body, but its error text is still worth
    indexing -- and there the error text is everything there is, so it counts as
    complete.
    """
    if response_text:
        return str(response_text), len(response_text), True
    evidence = evidence or {}
    sample = str(evidence.get("text_sample") or "")
    if sample:
        try:
            source_len = int(evidence.get("response_len") or 0)
        except (TypeError, ValueError):
            source_len = 0
        # Byte length versus character length can disagree for non-ASCII bodies,
        # so only claim completeness when the sample cannot be a cut-down copy.
        return sample, source_len, source_len <= len(sample)
    error = str(evidence.get("error") or "")
    return error, len(error), True


def build_trace_fields(*, run: Any, snapshot: Any, evidence: Dict[str, Any],
                       result: Any = None, response_text: str = "") -> Dict[str, Any]:
    """Map one execution into ``record_trace`` fields.

    Pure function: no database access, no model output, no side effects.  Every
    provenance dimension the retrieval indexes rely on (run, engine, account,
    host, path, parameter, payload) is filled from the execution that produced
    the observation, never from a later lookup.
    """
    evidence = dict(evidence or {})
    metadata = dict(getattr(snapshot, "metadata", None) or {})
    sources: List[Any] = [
        metadata,
        dict(getattr(snapshot, "parameter_sources", None) or {}),
    ]
    host = (_text(evidence.get("domain")) or _text(getattr(snapshot, "domain", "")))
    text, source_len, complete = searchable_response_text(evidence, response_text)
    return {
        "engine": _text(getattr(run, "adapter_id", "")) or ENGINE_EXECUTION,
        "host": host.lower(),
        "path": snapshot_path(snapshot),
        "method": _text(getattr(snapshot, "method", "")),
        "response_status": evidence.get("status_code"),
        "response_text": text,
        "source_len": source_len,
        "source_complete": complete,
        "parameter_name": _first_text(sources, PARAMETER_NAME_KEYS),
        "payload": _first_text(sources, PAYLOAD_KEYS),
        "run_id": getattr(run, "id", None),
        "check_type": _text(getattr(run, "check_type", "")),
        "project_id": (
            _text(getattr(run, "project_id", ""))
            or _text(getattr(snapshot, "project_id", ""))
        ),
        "env_id": (
            _text(getattr(run, "env_id", ""))
            or _text(getattr(snapshot, "env_id", ""))
        ),
        "account_id": (
            _text(getattr(run, "account_id", ""))
            or _text(getattr(snapshot, "account_id", ""))
        ),
        "auth_profile_revision_id": _text(
            getattr(snapshot, "auth_profile_revision_id", "")
        ),
        "auth_context_ref": _text(getattr(snapshot, "auth_context_ref", "")),
        "pathid": getattr(snapshot, "pathid", None),
        "snapshot_id": getattr(snapshot, "id", None),
        "request_query": dict(getattr(snapshot, "query", None) or {}),
        "request_body": getattr(snapshot, "body", None),
        # Capture cannot establish stability.  A completed transport is not a
        # stable baseline -- an HTTP 500 completes just fine -- and no baseline
        # comparison has run here.  Conservative by construction: only a real
        # baseline comparison may flip this to True, so ``stable_only``
        # retrieval never trusts a stability this layer never earned.
        "baseline_stable": False,
        "note": _text(evidence.get("error_type")),
    }


class ExecutionTraceRecorder:
    """Write one trace per executed request, failing soft.

    ``enabled=False`` turns every call into a no-op, which is what tests and dry
    runs use so they never touch the trace collection.
    """

    def __init__(self, enabled: bool = True,
                 text_limit: int = MAX_RESPONSE_TEXT_CHARS) -> None:
        self.enabled = bool(enabled)
        self.text_limit = int(text_limit)
        self.recorded = 0
        self.skipped = 0
        self.failed = 0
        self.last_error = ""

    def record(self, *, run: Any, snapshot: Any, evidence: Dict[str, Any],
               result: Any = None, response_text: str = "",
               ordinal: int = 0) -> Optional[Any]:
        """Store one trace; return it, or ``None`` when nothing was stored.

        ``ordinal`` is the request's position within one replay call.  A
        lifecycle replay fires several requests, and without the position their
        traces would be indistinguishable from each other.
        """
        if not self.enabled:
            self.skipped += 1
            return None
        if not getattr(run, "id", None):
            # Without a run id the self-confirmation guard cannot exclude this
            # row, so the trace would be unusable for cross-run retrieval.
            self.skipped += 1
            return None
        try:
            fields = build_trace_fields(
                run=run, snapshot=snapshot, evidence=evidence,
                result=result, response_text=response_text,
            )
            fields["text_limit"] = self.text_limit
            note = fields.get("note") or ""
            fields["note"] = "request#{}".format(ordinal) if not note else "{}|request#{}".format(note, ordinal)
            trace = record_trace(**fields)
            result_id = getattr(result, "id", None) if result is not None else None
            if result_id is not None and trace is not None:
                # Link the observation to the deterministic result it produced,
                # so a finding can be traced back to the response it came from.
                trace.derived_finding_ids = [result_id]
                trace.save()
        except Exception as exc:
            self.failed += 1
            self.last_error = "{}: {}".format(exc.__class__.__name__, exc)
            return None
        self.recorded += 1
        return trace

    def stats(self) -> Dict[str, Any]:
        return {
            "enabled": self.enabled,
            "recorded": self.recorded,
            "skipped": self.skipped,
            "failed": self.failed,
            "last_error": self.last_error,
        }
