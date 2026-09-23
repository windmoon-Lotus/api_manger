"""Cross-run retrieval over observed request/response pairs.

Purpose
-------
Turn the question "has any earlier run already seen this response?" into a
query instead of a re-run.  The motivating case is an error-signature sweep:
two engines in this project used different SQL error dictionaries, and the
narrower one ran against the larger workload, so the gap was only found by a
manual four-way read of report, script, ``progress.jsonl`` and private
evidence.  With a cross-run index that read becomes one query.

This module is an evidence chain, never a value source
------------------------------------------------------
Read ``request_trace`` in ``apiAnalysis.db.collection`` first.  In short: the
same URL returns different bodies as accounts rotate, as target data changes
and as the authenticated principal changes, so a stored response is a record of
what *was* seen, not a current value.  Nothing here returns a value for request
construction.  Values come from the graded paths (``parameter_archive`` with
``value_quality`` observed/sampled, or a fresh read).

Self-confirmation guard
-----------------------
Retrieval must exclude the caller's own run, otherwise a stored trace can be
reused to confirm the very conclusion that produced it.  Use
:func:`search_prior_evidence`, which excludes by construction.  The guard fails
loudly: a malformed or missing run id raises instead of being silently dropped,
because dropping it would silently defeat the guard.
"""

import datetime as dt
import hashlib
import json
from typing import Any, Dict, Iterable, List, Optional, Sequence

from bson import ObjectId

from apiAnalysis.db.collection import request_trace


# Bound for the searchable text copy.  A truncated record always says so; it
# never claims to be complete.
MAX_RESPONSE_TEXT_CHARS = 262144

TRUNCATION_MARKER = "\n...[truncated by trace_index]"


# Error-signature dictionary.  Classes are stored on the trace so a later sweep
# can ask "which runs already saw a SQL Server syntax error" without re-running
# anything.  Keep this list dialect-complete: the original defect was a
# MySQL-only dictionary running against targets that also had a SQL Server
# backend, which produced false negatives in a boolean screen.
ERROR_SIGNATURES = {
    "sql_syntax_mysql": (
        "you have an error in your sql syntax",
        "check the manual that corresponds to your mysql server version",
        "warning: mysql",
        "mysql_fetch",
        "mysqli_",
    ),
    "sql_syntax_mssql": (
        "unclosed quotation mark",
        "system.data.sqlclient.",
        "microsoft ole db provider for sql server",
        "incorrect syntax near",
        "microsoft sql server",
        "sqlserver.jdbc",
    ),
    "sql_syntax_postgres": (
        "syntax error at or near",
        "org.postgresql",
        "pg_query",
        "pg_exec",
        "postgresql",
    ),
    "sql_syntax_oracle": (
        "quoted string not properly terminated",
        "oracle error",
        "ora-00",
        "ora-01",
    ),
    "sql_syntax_sqlite": (
        "unrecognized token:",
        "sqlite error",
        "sqlite3.",
    ),
}


def detect_error_evidence(text: str) -> Dict[str, List[str]]:
    """Return ``{signature_class: [matched token, ...]}`` for one response text."""
    haystack = str(text or "").lower()
    if not haystack:
        return {}
    evidence = {}
    for signature_class, tokens in ERROR_SIGNATURES.items():
        matched = [token for token in tokens if token in haystack]
        if matched:
            evidence[signature_class] = matched
    return evidence


def detect_error_signatures(text: str) -> List[str]:
    """Return the sorted signature classes present in one response text."""
    return sorted(detect_error_evidence(text).keys())


def bound_response_text(text: str, limit: int = MAX_RESPONSE_TEXT_CHARS):
    """Bound the searchable text copy and report whether it was cut."""
    raw = str(text or "")
    if limit <= 0 or len(raw) <= limit:
        return raw, False
    return raw[:limit] + TRUNCATION_MARKER, True


def render_response_text(response_body: Any) -> str:
    """Produce searchable text from a structured body when no raw text exists."""
    if response_body is None:
        return ""
    if isinstance(response_body, str):
        return response_body
    try:
        return json.dumps(response_body, ensure_ascii=False, default=str)
    except (TypeError, ValueError):
        return str(response_body)


def new_trace_id(*, engine: str = "", run_id: str = "", host: str = "",
                 path: str = "", method: str = "", parameter_name: str = "",
                 payload: str = "", observed_at: Any = "", response_hash: str = "") -> str:
    """Deterministic identity for one observation.

    ``observed_at`` participates so two identical observations from the same run
    stay distinct; the identity is stable if the same observation is replayed
    with the same timestamp.
    """
    material = json.dumps(
        [
            str(engine or ""),
            str(run_id or ""),
            str(host or "").lower(),
            str(path or ""),
            str(method or "").upper(),
            str(parameter_name or ""),
            str(payload or ""),
            str(observed_at or ""),
            str(response_hash or ""),
        ],
        ensure_ascii=False,
        separators=(",", ":"),
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def body_sha256(text: str) -> str:
    return hashlib.sha256(str(text or "").encode("utf-8", errors="replace")).hexdigest()


def derive_signal_class(error_signatures: Sequence[str], response_status: Any = None,
                        explicit: Optional[str] = None) -> str:
    """Classify a trace when the caller did not classify it itself."""
    if explicit:
        return str(explicit)
    if error_signatures:
        return request_trace.ERROR_SIGNAL
    if response_status is None:
        return request_trace.UNDETERMINED
    return request_trace.NO_SIGNAL


def bounded_snippet(text: str, needle: str, window: int = 160) -> str:
    """Return a bounded window around the first occurrence of ``needle``.

    Retrieval output shows the matched context rather than the whole body: the
    point of a hit is where and as whom it was seen, and the surrounding bytes
    are what make that interpretable.
    """
    haystack = str(text or "")
    if not haystack:
        return ""
    target = str(needle or "")
    index = haystack.lower().find(target.lower()) if target else -1
    if index < 0:
        return haystack[:window * 2]
    start = max(0, index - window)
    end = min(len(haystack), index + len(target) + window)
    prefix = "..." if start > 0 else ""
    suffix = "..." if end < len(haystack) else ""
    return "{}{}{}".format(prefix, haystack[start:end], suffix)


def summarize_hits(hits: Sequence[request_trace]) -> Dict[str, Any]:
    """Group hits so "which runs already saw this" is answerable at a glance.

    Counts are derived from stored provenance, never estimated.
    """
    by_signature: Dict[str, int] = {}
    by_signal_class: Dict[str, int] = {}
    by_engine: Dict[str, int] = {}
    by_host: Dict[str, int] = {}
    by_account: Dict[str, int] = {}
    run_ids = set()
    for hit in hits:
        for signature in (getattr(hit, "error_signatures", None) or []):
            by_signature[signature] = by_signature.get(signature, 0) + 1
        signal_class = str(getattr(hit, "signal_class", "") or "unknown")
        by_signal_class[signal_class] = by_signal_class.get(signal_class, 0) + 1
        engine = str(getattr(hit, "engine", "") or "unknown")
        by_engine[engine] = by_engine.get(engine, 0) + 1
        host = str(getattr(hit, "host", "") or "unknown")
        by_host[host] = by_host.get(host, 0) + 1
        account = str(getattr(hit, "account_id", "") or "unattributed")
        by_account[account] = by_account.get(account, 0) + 1
        run_id = getattr(hit, "run_id", None)
        if run_id:
            run_ids.add(str(run_id))
    return {
        "hit_count": len(hits),
        "distinct_runs": len(run_ids),
        "by_signature": dict(sorted(by_signature.items())),
        "by_signal_class": dict(sorted(by_signal_class.items())),
        "by_engine": dict(sorted(by_engine.items())),
        "by_host": dict(sorted(by_host.items())),
        "by_account": dict(sorted(by_account.items())),
    }


def describe_hit(hit: request_trace, needle: str = "", snippet_window: int = 160) -> Dict[str, Any]:
    """Compact provenance view of one hit.

    Returns provenance and a bounded snippet, never a value for reuse.  The
    snippet is what makes the hit interpretable; it is not a source of request
    parameters.
    """
    observed_at = getattr(hit, "observed_at", None)
    superseded_by = getattr(hit, "superseded_by", None)
    return {
        "trace_id": str(getattr(hit, "trace_id", "") or ""),
        "observed_at": observed_at.isoformat() if observed_at else "",
        "run_id": str(getattr(hit, "run_id", "") or ""),
        "engine": str(getattr(hit, "engine", "") or ""),
        "check_type": str(getattr(hit, "check_type", "") or ""),
        "project_id": str(getattr(hit, "project_id", "") or ""),
        "env_id": str(getattr(hit, "env_id", "") or ""),
        "account_id": str(getattr(hit, "account_id", "") or ""),
        "pathid": getattr(hit, "pathid", None),
        "host": str(getattr(hit, "host", "") or ""),
        "path": str(getattr(hit, "path", "") or ""),
        "method": str(getattr(hit, "method", "") or ""),
        "parameter_name": str(getattr(hit, "parameter_name", "") or ""),
        "payload": str(getattr(hit, "payload", "") or ""),
        "response_status": getattr(hit, "response_status", None),
        "signal_class": str(getattr(hit, "signal_class", "") or ""),
        "error_signatures": list(getattr(hit, "error_signatures", None) or []),
        "baseline_stable": bool(getattr(hit, "baseline_stable", True)),
        "response_truncated": bool(getattr(hit, "response_truncated", False)),
        "superseded_by": str(superseded_by or ""),
        "snippet": bounded_snippet(
            getattr(hit, "response_text", "") or "", needle, snippet_window
        ),
    }


def _require_object_id(value: Any, field_name: str) -> ObjectId:
    """Coerce to ObjectId or fail loudly.

    Never silently drop a provided value: a dropped run id would defeat the
    self-confirmation guard without any visible symptom.
    """
    if not value:
        raise ValueError("{} is required".format(field_name))
    if isinstance(value, ObjectId):
        return value
    text = str(value).strip()
    if len(text) != 24:
        raise ValueError(
            "{} must be a 24-character ObjectId hex string, got {!r}".format(
                field_name, value
            )
        )
    try:
        return ObjectId(text)
    except Exception as exc:
        raise ValueError(
            "{} is not a valid ObjectId: {!r}".format(field_name, value)
        ) from exc


def _object_id_list(values: Iterable[Any], field_name: str) -> List[ObjectId]:
    if values is None:
        return []
    return [_require_object_id(value, field_name) for value in values]


def build_search_query(*, text: str = None, error_signatures: Sequence[str] = None,
                       signal_classes: Sequence[str] = None,
                       project_id: str = None, env_id: str = None,
                       account_id: str = None, host: str = None, path: str = None,
                       pathid: int = None, parameter_name: str = None,
                       engine: str = None, check_type: str = None,
                       response_status: int = None, stable_only: bool = False,
                       observed_after: Any = None, observed_before: Any = None,
                       exclude_run_id: Any = None, exclude_run_ids: Sequence[Any] = None,
                       exclude_account_id: str = None,
                       exclude_trace_ids: Sequence[Any] = None) -> Dict[str, Any]:
    """Build the MongoEngine filter dict for one trace search.

    Pure function so the filter shape is testable without a database.
    ``icontains`` escapes regex metacharacters, so SQL error text containing
    quotes, dots and parentheses is safe to pass as ``text``.
    """
    query: Dict[str, Any] = {}
    if text:
        query["response_text__icontains"] = str(text)
    if error_signatures:
        query["error_signatures__in"] = list(error_signatures)
    if signal_classes:
        query["signal_class__in"] = list(signal_classes)
    if project_id:
        query["project_id"] = str(project_id)
    if env_id:
        query["env_id"] = str(env_id)
    if account_id:
        query["account_id"] = str(account_id)
    if host:
        query["host"] = str(host).lower()
    if path:
        query["path"] = str(path)
    if pathid is not None:
        query["pathid"] = int(pathid)
    if parameter_name:
        query["parameter_name"] = str(parameter_name)
    if engine:
        query["engine"] = str(engine)
    if check_type:
        query["check_type"] = str(check_type)
    if response_status is not None:
        query["response_status"] = int(response_status)
    if stable_only:
        query["baseline_stable"] = True
    if observed_after is not None:
        query["observed_at__gte"] = observed_after
    if observed_before is not None:
        query["observed_at__lte"] = observed_before

    # Self-confirmation guard.  A malformed value raises rather than being
    # dropped, so the guard cannot fail open.
    if exclude_run_id is not None:
        query["run_id__ne"] = _require_object_id(exclude_run_id, "exclude_run_id")
    excluded_runs = _object_id_list(exclude_run_ids, "exclude_run_ids")
    if excluded_runs:
        query["run_id__nin"] = excluded_runs
    if exclude_account_id:
        query["account_id__ne"] = str(exclude_account_id)
    excluded_traces = _object_id_list(exclude_trace_ids, "exclude_trace_ids")
    if excluded_traces:
        query["pk__nin"] = excluded_traces
    return query


def search_traces(*, order: str = "-observed_at", limit: int = None,
                  **filters) -> List[request_trace]:
    """Search stored traces.  Returns evidence records, never usable values."""
    queryset = request_trace.objects(**build_search_query(**filters))
    if order:
        queryset = queryset.order_by(order)
    if limit:
        queryset = queryset.limit(int(limit))
    return list(queryset)


def search_prior_evidence(*, run_id: Any, exclude_account_id: str = None,
                          order: str = "-observed_at", limit: int = None,
                          **filters) -> List[request_trace]:
    """Search evidence recorded by *other* runs.

    The calling run is excluded by construction, so a stored trace can never be
    reused to confirm the conclusion it produced.  Caller-supplied exclusion
    filters are discarded rather than merged, so the guard cannot be widened
    away by accident.
    """
    if not run_id:
        raise ValueError(
            "run_id is required: searching without excluding your own run would "
            "allow a stored trace to confirm the conclusion it produced"
        )
    for reserved in ("exclude_run_id", "exclude_run_ids"):
        filters.pop(reserved, None)
    return search_traces(
        exclude_run_id=run_id,
        exclude_account_id=exclude_account_id,
        order=order,
        limit=limit,
        **filters
    )


def record_trace(*, engine: str, host: str, path: str, method: str,
                 response_status: Any, response_body: Any = None,
                 response_text: str = None, parameter_name: str = "",
                 payload: str = "", run_id: Any = None, check_type: str = "",
                 project_id: str = "", env_id: str = "", account_id: str = "",
                 auth_profile_revision_id: str = "", auth_context_ref: str = "",
                 pathid: int = None, snapshot_id: Any = None,
                 request_query: Dict[str, Any] = None, request_body: Any = None,
                 signal_class: str = None, baseline_stable: bool = True,
                 observed_at: Any = None, note: str = "",
                 text_limit: int = MAX_RESPONSE_TEXT_CHARS,
                 source_len: int = None, source_complete: bool = None) -> request_trace:
    """Append one observation to the evidence chain.

    Append-only: callers must not edit a stored trace to reflect a newer
    attempt.  Store a new trace and link the older one with ``superseded_by``.

    ``source_len`` / ``source_complete`` describe the body the text came from,
    not the stored copy.  They exist because a caller may only hold a sample:
    storing a 300-character sample with ``response_len=300`` and
    ``response_truncated=False`` would tell a later sweep that the *whole*
    response was searched, when only its head was.  A miss would then read as
    evidence of absence -- exactly the false negative this index exists to
    remove.  A caller who captured the full body passes nothing and gets the
    previous behaviour.
    """
    observed_at = observed_at or dt.datetime.utcnow()
    raw_text = response_text if response_text is not None else render_response_text(response_body)
    bounded_text, bounded_truncated = bound_response_text(raw_text, text_limit)
    if source_complete is None:
        stored_truncated = bounded_truncated
    else:
        stored_truncated = (not source_complete) or bounded_truncated
    stored_len = int(source_len) if source_len is not None else len(raw_text)
    signatures = detect_error_signatures(raw_text)
    run_id_text = str(run_id or "")

    trace = request_trace(
        trace_id=new_trace_id(
            engine=engine, run_id=run_id_text, host=host, path=path, method=method,
            parameter_name=parameter_name, payload=payload, observed_at=observed_at,
            response_hash=body_sha256(bounded_text),
        ),
        run_id=_require_object_id(run_id, "run_id") if run_id else None,
        engine=str(engine or ""),
        check_type=str(check_type or ""),
        project_id=str(project_id or ""),
        env_id=str(env_id or ""),
        account_id=str(account_id or ""),
        auth_profile_revision_id=str(auth_profile_revision_id or ""),
        auth_context_ref=str(auth_context_ref or ""),
        pathid=int(pathid) if pathid is not None else None,
        snapshot_id=_require_object_id(snapshot_id, "snapshot_id") if snapshot_id else None,
        method=str(method or "").upper(),
        host=str(host or "").lower(),
        path=str(path or ""),
        parameter_name=str(parameter_name or ""),
        payload=str(payload or ""),
        observed_at=observed_at,
        request_query=dict(request_query or {}),
        request_body=request_body,
        response_status=int(response_status) if response_status is not None else None,
        response_body=response_body,
        response_text=bounded_text,
        response_truncated=stored_truncated,
        response_len=stored_len,
        response_hash=body_sha256(bounded_text),
        body_sha256=body_sha256(raw_text),
        signal_class=derive_signal_class(signatures, response_status, signal_class),
        error_signatures=signatures,
        baseline_stable=bool(baseline_stable),
        note=str(note or ""),
    )
    trace.save()
    return trace
