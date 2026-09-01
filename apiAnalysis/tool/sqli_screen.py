"""Framework-native per-parameter SQLi payload screening adapter."""
from __future__ import annotations

import hashlib
import json
import logging
import re
import types
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from apiAnalysis.db.collection import request_snapshot
from apiAnalysis.tool.execution_adapter import ExecutionAdapter, ExecutionRequestBlocked
from apiAnalysis.tool.execution_contract import ExecutionContext
from apiAnalysis.tool.snapshot_runner import replay_snapshot_with_json


logger = logging.getLogger(__name__)


SQLI_SCREEN_ADAPTER_ID = "sqli_payload_screen"
SQLI_SCREEN_ADAPTER_VERSION = "1"
SQLI_SCREEN_SCHEMA_VERSION = "sqli-payload-screen.v1"

# screening_class -> (sql_screening, baseline_only, require_readback)
# read_only       : 走 SQLi payload 筛查
# additive        : 部分加/减一项（如添加 tag、添加成员），可回滚，需 readback
# idempotent_config: 整体替换设置类（toggle、改限额、改绑定），需 readback
# stateful        : 状态变更需单独审批
# destructive     : 不可逆，默认不发送 payload
# unknown         : 缺省按 destructive 处理
SCREENING_CLASS_RULES: Dict[str, Dict[str, Any]] = {
    "read_only":         {"sql_screening": True,  "baseline_only": False, "require_readback": False},
    "additive":          {"sql_screening": True,  "baseline_only": False, "require_readback": True},
    "idempotent_config": {"sql_screening": True,  "baseline_only": False, "require_readback": True},
    "stateful":          {"sql_screening": False, "baseline_only": True,  "require_readback": True},
    "destructive":       {"sql_screening": False, "baseline_only": True,  "require_readback": False},
    "unknown":           {"sql_screening": False, "baseline_only": True,  "require_readback": False},
}

# 默认按 method 推断 screening_class（plan builder 写死的优先级更高）
DEFAULT_SCREENING_CLASS_BY_METHOD: Dict[str, str] = {
    "GET": "read_only",
    "HEAD": "read_only",
    "OPTIONS": "read_only",
    "POST": "destructive",
    "PUT": "stateful",
    "PATCH": "stateful",
    "DELETE": "destructive",
}

SQLI_PAYLOADS: Dict[str, str] = {
    "orig_true":        "0)or len(user)>1-- A",
    "orig_false":       "0)or len(user)>100-- A",
    "quote":            "1'",
    "paren_close":      "1)",
    "or_true":          "1) or 1=1-- A",
    "noparen_or":       "1 or 1=1-- A",
    "union_null":       "1 UNION SELECT NULL-- A",
    "waitfor":          "1; WAITFOR DELAY '0:0:3'-- A",
    "subquery":         "1 and (select 1)=1-- A",
    "comment_or":       "1/**/or/**/1=1-- A",
    "dquote":           '1"',
    "backslash":        "1\\",
    # MySQL/PostgreSQL time-based fallbacks; only the matching dialect is screened
    "sleep_mysql":      "1 OR SLEEP(3)-- A",
    "sleep_pg":         "1; SELECT pg_sleep(3)-- A",
    "benchmark":        "1 OR BENCHMARK(20000000,SHA1(1))-- A",
}

# param names that are auth/transport scaffolding, never SQL-reachable values
SKIP_NAMES = {
    "token", "access_token", "authorization", "auth", "sign", "signature",
    "timestamp", "ts", "nonce", "sessionid", "session_id", "cookie",
    "apifox_uid", "_token", "traceid", "requestid", "pageId", "lang",
}

# named marker groups: only group NAMES enter evidence, never response text
_MARKER_PATTERN = re.compile(
    r"(?P<fatal>Fatal error)|(?P<warning>Warning:)|(?P<sql_syntax>SQL syntax|syntax error)"
    r"|(?P<pdo>PDOException)|(?P<yaf>Yaf_Exception)|(?P<generic_exception>Exception)"
    r"|(?P<odbc>ODBC)|(?P<mssql>mssql)|(?P<mysql>MySQL|mysql_)|(?P<pg>PostgreSQL|pg_sleep|pg_query)"
    r"|(?P<near>near \"\")"
    r"|(?P<dbqccom>dbqccom)|(?P<peanut>peanut)|(?P<uncaught>uncaught)"
    r"|(?P<traceback>traceback)|(?P<boom>SQL/COM_INIT_DB_FAILED|sqlsrv)",
    re.IGNORECASE,
)

TIMING_MULTIPLE = 3.0
TIMING_MIN_DELTA_MS = 2500.0
# MySQL/PostgreSQL time-based payloads may trigger on shorter delays on local
# databases; this multiplier is the absolute floor before we consider it a signal.
TIMING_MIN_DELTA_MS_FAST = 1500.0
BODY_DIFF_MIN_BYTES = 32
BODY_DIFF_MIN_RATIO = 0.10
BASELINE_LENGTH_TOLERANCE_RATIO = 0.05
BASELINE_LENGTH_TOLERANCE_BYTES = 8
_BODY_BYTE_LIMIT = 1200

# Default timing anomaly settings; mutation paths should disable timing to
# avoid accidentally exercising time-based sinks on production traffic.
TIMING_PAYLOADS: frozenset = frozenset({"waitfor", "sleep_mysql", "sleep_pg", "benchmark"})


def _marker_names(text: str) -> List[str]:
    names = []
    for match in _MARKER_PATTERN.finditer(text or ""):
        for group, value in match.groupdict().items():
            if value:
                if group not in names:
                    names.append(group)
                break
    return names


def _sha256(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True,
                                     default=str).encode("utf-8")).hexdigest()


def _bounded_response_json(value: Any, byte_limit: int = _BODY_BYTE_LIMIT) -> Optional[str]:
    """Valid representative JSON subtree, never a truncated document."""

    def shrink(node: Any, *, string_limit: int, dict_limit: int,
               list_limit: int, depth: int = 0) -> Any:
        if depth >= 8:
            return None
        if isinstance(node, dict):
            return {
                str(key)[:100]: shrink(
                    node[key], string_limit=string_limit, dict_limit=dict_limit,
                    list_limit=list_limit, depth=depth + 1,
                )
                for key in list(node)[:dict_limit]
            }
        if isinstance(node, list):
            return [
                shrink(item, string_limit=string_limit, dict_limit=dict_limit,
                       list_limit=list_limit, depth=depth + 1)
                for item in node[:list_limit]
            ]
        if isinstance(node, str):
            return node[:string_limit]
        if node is None or isinstance(node, (bool, int, float)):
            return node
        return str(node)[:string_limit]

    for string_limit, dict_limit, list_limit in (
        (100, 40, 2), (50, 24, 1), (24, 12, 1),
    ):
        candidate = shrink(value, string_limit=string_limit, dict_limit=dict_limit,
                           list_limit=list_limit)
        encoded = json.dumps(candidate, ensure_ascii=False, separators=(",", ":"))
        if len(encoded.encode("utf-8")) <= byte_limit:
            return encoded
    return None


def _set_query_value(url: str, name: str, value: str) -> str:
    parsed = urlsplit(url)
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    replaced = False
    kept = []
    for key, _old in pairs:
        if key == name:
            if not replaced:
                kept.append((name, value))
                replaced = True
        else:
            kept.append((key, _old))
    if not replaced:
        kept.append((name, value))
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path,
                       urlencode(kept, doseq=True), parsed.fragment))


def _bounded_json(value: Any) -> Optional[str]:
    """Return a bounded JSON for a body param (top-level sets merge)."""
    return _bounded_response_json(value)


def _set_body_value(body: Any, name: str, value: str) -> Any:
    """Return a shallow-copied body with param=value (top-level; json pointer fallback)."""
    import copy
    if isinstance(body, dict):
        copied = dict(body)
        copied[name] = value
        return copied
    return body


def _clone_variant(snapshot: Any, url: Optional[str] = None,
                   body: Any = None, query: Optional[Dict[str, Any]] = None) -> Any:
    return types.SimpleNamespace(
        id=snapshot.id, pathid=snapshot.pathid, method=snapshot.method,
        url=url if url is not None else getattr(snapshot, "url", "") or "",
        domain=snapshot.domain, project_id=getattr(snapshot, "project_id", "") or "",
        auth_mode=getattr(snapshot, "auth_mode", "") or "account",
        expected_status_codes=snapshot.expected_status_codes or [],
        headers=snapshot.headers or {}, cookies=snapshot.cookies or {},
        body=body if body is not None else snapshot.body,
        content_type=snapshot.content_type or "application/json",
        query=query if query is not None else (getattr(snapshot, "query", None) or {}),
    )


def _targets(snapshot: Any) -> List[Dict[str, str]]:
    """Return reachable query and body parameters for the snapshot."""
    meta = dict(getattr(snapshot, "metadata", None) or {})
    spec = list((meta.get("sqli_screen") or {}).get("spec") or [])
    explicit = {}
    for row in spec:
        name = str(row.get("name") or "")
        if not name:
            continue
        explicit[name] = {
            "position": str(row.get("position") or "query"),
            "base": str(row.get("base") or "1"),
        }
    sources = dict(getattr(snapshot, "parameter_sources", None) or {})
    derived = {}
    for name, entry in sources.items():
        if not isinstance(entry, Mapping):
            continue
        position = str(entry.get("position") or "")
        if position not in {"query", "body"}:
            continue
        if str(entry.get("source") or "") == "omitted_empty_optional":
            continue
        derived[name] = {"position": position, "base": ""}
    merged = dict(explicit)
    merged.update({k: v for k, v in derived.items() if k not in merged})
    screened = []
    for name, cfg in sorted(merged.items()):
        if not name or name in SKIP_NAMES:
            continue
        if cfg["position"] == "body" and not isinstance(snapshot.body, dict):
            continue
        screened.append({"name": name, "position": cfg["position"], "base": cfg["base"] or "1"})
    return screened


def _run_request(request_executor: Optional[Callable[[Callable[[], Any]], Any]],
                 request_call: Callable[[], Any]) -> Any:
    return request_executor(request_call) if request_executor is not None else request_call()


def _status_code(evidence: Mapping[str, Any]) -> Optional[int]:
    value = evidence.get("status_code")
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _response_markers(evidence: Mapping[str, Any], captured_json: Any) -> List[str]:
    sample = str(evidence.get("text_sample") or "")
    captured_text = (
        json.dumps(captured_json, ensure_ascii=False)
        if captured_json is not None else ""
    )
    return _marker_names(sample + "\n" + captured_text[:2000])


def _request_problem(evidence: Mapping[str, Any]) -> str:
    if evidence.get("error_type") or evidence.get("error"):
        return "transport_error"
    status = _status_code(evidence)
    if status is None:
        return "transport_error"
    if status in {401, 403}:
        return "auth_denied"
    if status == 429:
        return "rate_limited"
    return ""


def _baseline_problem(evidence: Mapping[str, Any]) -> str:
    problem = _request_problem(evidence)
    if problem:
        return "baseline_{}".format(problem)
    status = _status_code(evidence)
    if status == 404:
        return "baseline_not_found"
    if status is not None and 300 <= status < 400:
        return "baseline_redirected"
    if status is not None and status >= 500:
        return "baseline_server_error"
    if evidence.get("ok") is False:
        return "baseline_unexpected_status"
    return ""


def _probe_matches_baseline(probe: Mapping[str, Any],
                            baseline: Mapping[str, Any]) -> bool:
    if probe.get("status") != _status_code(baseline):
        return False
    probe_hash = str(probe.get("sha12") or "")
    baseline_hash = str(baseline.get("response_sha256") or "")[:12]
    if probe_hash and baseline_hash and probe_hash == baseline_hash:
        return True
    baseline_len = int(baseline.get("response_len") or 0)
    if baseline_len <= 0:
        return False
    tolerance = max(
        BASELINE_LENGTH_TOLERANCE_BYTES,
        round(baseline_len * BASELINE_LENGTH_TOLERANCE_RATIO),
    )
    return abs(int(probe.get("len") or 0) - baseline_len) <= tolerance


def _meaningful_body_difference(true_probe: Mapping[str, Any],
                                false_probe: Mapping[str, Any],
                                baseline: Mapping[str, Any]) -> bool:
    true_status = true_probe.get("status")
    if true_status != false_probe.get("status") or true_status is None:
        return False
    if not 200 <= int(true_status) < 300:
        return False
    true_hash = str(true_probe.get("sha12") or "")
    false_hash = str(false_probe.get("sha12") or "")
    if not true_hash or not false_hash or true_hash == false_hash:
        return False
    true_len = int(true_probe.get("len") or 0)
    false_len = int(false_probe.get("len") or 0)
    difference = abs(true_len - false_len)
    if difference < BODY_DIFF_MIN_BYTES:
        return False
    if difference / max(true_len, false_len, 1) < BODY_DIFF_MIN_RATIO:
        return False
    return (
        _probe_matches_baseline(true_probe, baseline)
        != _probe_matches_baseline(false_probe, baseline)
    )


def _timing_anomaly(evidence: Mapping[str, Any],
                    baseline: Mapping[str, Any],
                    *,
                    payload_name: str = "",
                    min_delta_ms: float = TIMING_MIN_DELTA_MS) -> bool:
    try:
        elapsed = float(evidence.get("elapsed_ms") or 0)
        baseline_elapsed = float(baseline.get("elapsed_ms") or 0)
    except (TypeError, ValueError):
        return False
    return (
        baseline_elapsed > 0
        and elapsed >= TIMING_MULTIPLE * baseline_elapsed
        and elapsed - baseline_elapsed >= min_delta_ms
    )


def _screening_class(snapshot: Any) -> str:
    """Read the screening_class from snapshot metadata; fall back to method default."""
    meta = dict(getattr(snapshot, "metadata", None) or {})
    screen = dict(meta.get("sqli_screen") or {})
    cls = str(screen.get("screening_class") or "").strip().lower()
    if cls in SCREENING_CLASS_RULES:
        return cls
    method = str(getattr(snapshot, "method", "") or "GET").upper()
    return DEFAULT_SCREENING_CLASS_BY_METHOD.get(method, "unknown")


def _screening_policy(snapshot: Any) -> Dict[str, Any]:
    cls = _screening_class(snapshot)
    return dict(SCREENING_CLASS_RULES.get(cls, SCREENING_CLASS_RULES["unknown"]))


def _screen_one_param(snapshot: Any, target: Dict[str, str],
                      baseline: Mapping[str, Any], *,
                      auth_mode: str, request_options: Any,
                      account_context: Any,
                      request_executor: Optional[
                          Callable[[Callable[[], Any]], Any]
                      ] = None) -> Tuple[Dict[str, Any], Dict[str, Dict[str, Any]]]:
    name, position, base = target["name"], target["position"], target["base"]
    base_status = _status_code(baseline)
    baseline_markers = set(baseline.get("marker_names") or [])
    screening_policy = _screening_policy(snapshot)
    allow_payloads = bool(screening_policy.get("sql_screening", True))
    timing_allowed = bool(screening_policy.get("sql_screening", True))
    probes = []
    bodies = {}
    for payload_name, payload in SQLI_PAYLOADS.items():
        if not allow_payloads:
            probes.append({
                "payload": payload_name,
                "status": None,
                "error_type": "",
                "flags": ["blocked_by_screening_class"],
                "markers": [],
            })
            continue
        if position == "query":
            variant_query = dict(getattr(snapshot, "query", None) or {})
            variant_query[name] = payload
            variant = _clone_variant(
                snapshot,
                url=_set_query_value(snapshot.url, name, payload),
                query=variant_query,
            )
        else:
            variant = _clone_variant(
                snapshot,
                body=_set_body_value(snapshot.body, name, payload),
            )
        try:
            evidence, captured_json = _run_request(
                request_executor,
                lambda variant=variant: replay_snapshot_with_json(
                    variant, auth_mode=auth_mode,
                    request_options=request_options, account_context=account_context,
                    request_trace_phase="sqli_screen",
                ),
            )
        except ExecutionRequestBlocked:
            raise
        except Exception as exc:
            probes.append({
                "payload": payload_name,
                "status": None,
                "error_type": exc.__class__.__name__,
                "flags": ["transport_error"],
                "markers": [],
            })
            continue

        status = _status_code(evidence)
        problem = _request_problem(evidence)
        all_markers = _response_markers(evidence, captured_json)
        markers = [marker for marker in all_markers if marker not in baseline_markers]
        flags = [problem] if problem else []
        if not problem:
            if status != base_status:
                flags.append("status_diff")
            if markers:
                flags.append("new_error_marker")
            if (
                timing_allowed
                and payload_name in TIMING_PAYLOADS
                and _timing_anomaly(evidence, baseline, payload_name=payload_name)
            ):
                flags.append("time_anomaly")
        sample = str(evidence.get("text_sample") or "")
        probes.append({
            "payload": payload_name,
            "status": status,
            "error_type": str(evidence.get("error_type") or ""),
            "ms": round(float(evidence.get("elapsed_ms") or 0)),
            "len": int(evidence.get("response_len") or 0),
            "content_type": str(evidence.get("response_content_type") or ""),
            "sha12": str(evidence.get("response_sha256") or "")[:12],
            "flags": flags,
            "markers": markers,
        })
        if flags and (captured_json is not None or sample):
            bodies[payload_name] = {
                "json": _bounded_response_json(captured_json) if captured_json is not None else None,
                "text": sample[:160],
            }

    problems = sorted({
        flag
        for probe in probes
        for flag in probe.get("flags") or []
        if flag in {"transport_error", "auth_denied", "rate_limited"}
    })
    by_payload = {probe.get("payload"): probe for probe in probes}
    true_probe = by_payload.get("orig_true")
    false_probe = by_payload.get("orig_false")

    def usable(probe: Optional[Mapping[str, Any]]) -> bool:
        return bool(
            probe
            and probe.get("status") is not None
            and not any(
                flag in {"transport_error", "auth_denied", "rate_limited"}
                for flag in probe.get("flags") or []
            )
        )

    signals = []
    strong_signals = []
    if usable(true_probe) and usable(false_probe):
        if true_probe["status"] != false_probe["status"] and (
                true_probe["status"] == base_status
                or false_probe["status"] == base_status):
            signals.append("boolean_status_divergence")
            if true_probe["status"] == 500 and false_probe["status"] == base_status:
                strong_signals.append("report_true_500_false_baseline")
        elif _meaningful_body_difference(true_probe, false_probe, baseline):
            signals.append("boolean_body_divergence")

    if any("new_error_marker" in (probe.get("flags") or []) for probe in probes):
        signals.append("new_error_marker")
    if any("time_anomaly" in (probe.get("flags") or []) for probe in probes):
        signals.append("waitfor_time_anomaly")
    if any(
            usable(probe)
            and probe.get("status") is not None
            and 500 <= int(probe["status"]) < 600
            and not (base_status is not None and 500 <= base_status < 600)
            for probe in probes):
        signals.append("server_error_divergence")

    signals = list(dict.fromkeys(signals))
    if signals:
        verdict = "INTEREST"
    elif problems:
        verdict = "NOT_EVALUABLE"
    else:
        statuses = [probe.get("status") for probe in probes]
        uniformly_rejected = bool(statuses) and all(
            status is not None and 400 <= int(status) < 500 and status != base_status
            for status in statuses
        )
        verdict = "BLOCKED" if uniformly_rejected else "CLEAN"

    return {
        "name": name,
        "position": position,
        "base_used": base,
        "base_status": base_status,
        "verdict": verdict,
        "probes": probes,
        "signals": signals,
        "reason_codes": problems,
        "strong_signature": bool(strong_signals),
        "strong_signals": strong_signals,
        "complete": not problems,
    }, bodies


def _screen_replay(snapshot: Any, **kwargs: Any) -> Dict[str, Any]:
    auth_mode = kwargs.get("auth_mode") or getattr(snapshot, "auth_mode", None) or "inherit"
    request_options = kwargs.get("request_options")
    account_context = kwargs.get("account_context")
    request_executor = kwargs.get("request_executor")
    screening_policy = _screening_policy(snapshot)
    screening_class = _screening_class(snapshot)
    baseline_only = bool(screening_policy.get("baseline_only", False))
    # TODO-11 联防: mutate 路径必须配 readback adapter，否则拒绝执行
    if (
        screening_policy.get("require_readback", False)
        and not kwargs.get("readback_registered", False)
    ):
        raise ExecutionRequestBlocked(
            "mutation_requires_readback:{}".format(screening_class)
        )
    targets = _targets(snapshot)
    if baseline_only and not targets:
        return {
            "status_code": None,
            "ok": False,
            "response_len": 0,
            "domain": getattr(snapshot, "domain", ""),
            "auth_mode": auth_mode,
            "sqli_screen": {
                "schema": SQLI_SCREEN_SCHEMA_VERSION,
                "screening_class": screening_class,
                "param_targets": 0,
                "screened": 0,
                "baseline_status": None,
                "baseline_reason": "no_targets",
                "block_reason": "baseline_only_no_targets",
                "params": [],
                "interest": [],
                "strong": [],
                "blocked": [],
                "not_evaluable": [],
            },
        }

    base_kwargs = {
        "auth_mode": auth_mode,
        "request_options": request_options,
        "account_context": account_context,
    }
    try:
        baseline, baseline_json = _run_request(
            request_executor,
            lambda: replay_snapshot_with_json(
                snapshot,
                **base_kwargs,
                request_trace_phase="sqli_screen_baseline",
            ),
        )
    except ExecutionRequestBlocked:
        raise
    except Exception as exc:
        return {
            "status_code": None,
            "ok": False,
            "response_len": 0,
            "domain": getattr(snapshot, "domain", ""),
            "auth_mode": auth_mode,
            "error_type": exc.__class__.__name__,
            "error": str(exc)[:160],
            "sqli_screen": {
                "schema": SQLI_SCREEN_SCHEMA_VERSION,
                "screening_class": screening_class,
                "param_targets": len(targets),
                "screened": 0,
                "baseline_status": None,
                "baseline_reason": "baseline_transport_error",
                "block_reason": "baseline_only" if baseline_only else "",
                "params": [],
                "interest": [],
                "strong": [],
                "blocked": [],
                "not_evaluable": [target["name"] for target in targets],
            },
        }

    baseline = dict(baseline or {})
    baseline["marker_names"] = _response_markers(baseline, baseline_json)
    baseline_reason = _baseline_problem(baseline)
    if baseline_reason:
        return {
            "status_code": _status_code(baseline),
            "ok": False,
            "elapsed_ms": baseline.get("elapsed_ms"),
            "response_len": int(baseline.get("response_len") or 0),
            "domain": baseline.get("domain") or getattr(snapshot, "domain", ""),
            "auth_mode": auth_mode,
            "error_type": str(baseline.get("error_type") or ""),
            "error": str(baseline.get("error") or "")[:160],
            "sqli_screen": {
                "schema": SQLI_SCREEN_SCHEMA_VERSION,
                "screening_class": screening_class,
                "param_targets": len(targets),
                "screened": 0,
                "baseline_status": _status_code(baseline),
                "baseline_reason": baseline_reason,
                "baseline_markers": baseline["marker_names"],
                "block_reason": "baseline_only" if baseline_only else "",
                "params": [],
                "interest": [],
                "strong": [],
                "blocked": [],
                "not_evaluable": [target["name"] for target in targets],
            },
        }

    rows = []
    body_samples = {}
    interest = []
    strong = []
    blocked = []
    not_evaluable = []
    clean = []
    for target in targets:
        row, bodies = _screen_one_param(
            snapshot,
            target,
            baseline,
            auth_mode=auth_mode,
            request_options=request_options,
            account_context=account_context,
            request_executor=request_executor,
        )
        rows.append(row)
        name = row["name"]
        if row["verdict"] == "INTEREST":
            interest.append(name)
            body_samples[name] = bodies
        elif row["verdict"] == "BLOCKED":
            blocked.append(name)
        elif row["verdict"] == "NOT_EVALUABLE":
            not_evaluable.append(name)
        else:
            clean.append(name)
        if row.get("strong_signature"):
            strong.append(name)

    return {
        "status_code": _status_code(baseline),
        "ok": bool(baseline.get("ok")),
        "elapsed_ms": baseline.get("elapsed_ms"),
        "response_len": int(baseline.get("response_len") or 0),
        "domain": baseline.get("domain"),
        "auth_mode": auth_mode,
        "sqli_screen": {
            "schema": SQLI_SCREEN_SCHEMA_VERSION,
            "screening_class": screening_class,
            "param_targets": len(targets),
            "screened": len(rows),
            "baseline_status": _status_code(baseline),
            "baseline_markers": baseline["marker_names"],
            "params": rows,
            "interest": interest,
            "strong": strong,
            "blocked": blocked,
            "not_evaluable": not_evaluable,
            "clean": clean,
            "block_reason": (
                "baseline_only_no_payloads" if baseline_only and not rows
                else ""
            ),
        },
        "_sqli_bodies": body_samples,
    }


def _screen_judge(evidence: Mapping[str, Any], _check_type: str,
                  _auth_mode: str) -> Tuple[str, List[str], float]:
    screen = dict(evidence.get("sqli_screen") or {})
    baseline_reason = str(screen.get("baseline_reason") or "")
    screening_class = str(screen.get("screening_class") or "unknown")
    block_reason = str(screen.get("block_reason") or "")
    if evidence.get("error_type") or evidence.get("error"):
        return "error", [baseline_reason or "transport_error"], 0.9
    if baseline_reason:
        return "not_evaluable", [baseline_reason], 0.9

    rows = list(screen.get("params") or [])
    interest = [row for row in rows if row.get("verdict") == "INTEREST"]
    if interest:
        reasons = [
            "sqli_report_signature"
            if any(row.get("strong_signature") for row in interest)
            else "sqli_observable_signal"
        ]
        if any(not row.get("complete", True) for row in rows):
            reasons.append("partial_probe_coverage")
        return "need_review", reasons, 0.8 if "sqli_report_signature" in reasons else 0.6

    not_evaluable = [row for row in rows if row.get("verdict") == "NOT_EVALUABLE"]
    if not_evaluable:
        reason = (
            "probe_not_evaluable"
            if len(not_evaluable) == len(rows)
            else "partial_probe_not_evaluable"
        )
        return "not_evaluable", [reason], 0.75
    if any(row.get("verdict") == "BLOCKED" for row in rows):
        return "not_evaluable", ["payload_screen_blocked"], 0.75
    if not rows:
        # mutate 路径不发 payload 时直接归类为 not_evaluable 并指明 block_reason
        if screening_class in {"destructive", "stateful", "unknown"} or block_reason:
            return "not_evaluable", [
                block_reason or "screening_class_{}".format(screening_class)
            ], 0.7
        return "not_evaluable", ["no_parameters_screened"], 0.8
    return "no_vuln", ["no_sqli_signal_in_payload_screen"], 0.7


def _record_screen(run: Any, snapshot: Any, evidence: Mapping[str, Any],
                   result: Any, _checkpoint: Any) -> None:
    """Persist bounded per-param detail + flagged body samples to a private file.

    Bodies never go to Mongo; sanitize strips them from run evidence anyway.
    Failures are logged but never break checkpoint finishing.
    """
    try:
        screen = dict(evidence.get("sqli_screen") or {})
        if not screen:
            return
        dir_path = str(getattr(run, "evidence_ref", "") or "").strip()
        if not dir_path:
            return
        target = Path(dir_path)
        if not target.is_dir():
            target.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        out = target / "sqli-screen-{}-pathid{}-{}.private.json".format(
            str(getattr(run, "id", "") or "run")[:12],
            int(getattr(snapshot, "pathid", 0) or 0),
            stamp,
        )
        out.write_text(json.dumps({
            "schema": SQLI_SCREEN_SCHEMA_VERSION,
            "run_id": str(getattr(run, "id", "") or ""),
            "result_id": str(getattr(result, "id", "") or ""),
            "snapshot_id": str(getattr(snapshot, "id", "") or ""),
            "pathid": int(getattr(snapshot, "pathid", 0) or 0),
            "method": str(getattr(snapshot, "method", "") or ""),
            "url": str(getattr(snapshot, "url", "") or ""),
            "screening_class": str(screen.get("screening_class") or "unknown"),
            "block_reason": str(screen.get("block_reason") or ""),
            "created": stamp,
            "params": screen.get("params") or [],
            "body_samples_flags_only": evidence.get("_sqli_bodies") or {},
        }, ensure_ascii=False, indent=1), encoding="utf-8")
    except Exception as exc:
        run_id = str(getattr(run, "id", "") or "")
        logger.warning(
            "sqli_screen record failed: run=%s pathid=%s error=%s",
            run_id,
            int(getattr(snapshot, "pathid", 0) or 0),
            "{}: {}".format(type(exc).__name__, exc),
        )


def build_sqli_screen_adapter() -> ExecutionAdapter:
    return ExecutionAdapter(
        adapter_id=SQLI_SCREEN_ADAPTER_ID,
        adapter_version=SQLI_SCREEN_ADAPTER_VERSION,
        replay=_screen_replay,
        judge=_screen_judge,
        auth_modes=frozenset({"account"}),
        requires_account_context=True,
        supports_mutation=True,
        request_policy_scope="request",
        record=_record_screen,
    )


def build_sqli_screen_manifest(openapi_path: str, out_path: str = "") -> Dict[str, Any]:
    """Build the screening manifest (endpoint->param universe) from an OpenAPI export.

    Every operation with documented text query params / JSON body props is
    included. A single concrete root-level OpenAPI server supplies the origin;
    absent, templated or ambiguous servers remain pending for an explicit,
    private route-resolution artifact.
    """
    openapi_path = str(openapi_path or "").strip()
    if not openapi_path or not Path(openapi_path).is_file():
        raise ValueError("openapi export path is required")
    spec = json.loads(Path(openapi_path).read_text(encoding="utf-8-sig"))
    PENDING_ROUTE_MARKER = "__pending_route__"

    server_origins = []
    for server in spec.get("servers") or []:
        raw = str(server.get("url") or "") if isinstance(server, Mapping) else ""
        if not raw or "{" in raw or "}" in raw:
            continue
        parsed = urlsplit(raw)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            continue
        server_origins.append(urlunsplit((parsed.scheme, parsed.netloc, "", "", "")))
    unique_origins = sorted(set(server_origins))
    default_origin = unique_origins[0] if len(unique_origins) == 1 else ""

    def route_host() -> Tuple[str, bool]:
        return (default_origin, False) if default_origin else (PENDING_ROUTE_MARKER, True)

    def base_for(ptype: str) -> str:
        return "1,2" if ptype == "array" else "1"

    def text_type(ptype: str) -> bool:
        return ptype in ("string", "integer", "array", "number", None)

    def body_props(op: Mapping[str, Any]) -> Dict[str, Any]:
        content = (op.get("requestBody") or {}).get("content") or {}
        schema = (content.get("application/json") or {}).get("schema") or {}
        props = schema.get("properties") or {}
        return {
            str(key): (value.get("type") if isinstance(value, Mapping) else None)
            for key, value in props.items()
        }

    manifest = []
    pending: List[Dict[str, Any]] = []
    for path, ops in sorted((spec.get("paths") or {}).items()):
        for method, op in ops.items():
            if not isinstance(op, Mapping):
                continue
            params = []
            for pr in op.get("parameters") or []:
                if pr.get("in") != "query":
                    continue
                name = str(pr.get("name") or "")
                if not name or name in SKIP_NAMES:
                    continue
                ptype = (pr.get("schema") or {}).get("type") if isinstance(pr.get("schema"), Mapping) else None
                if not text_type(ptype):
                    continue
                params.append({"name": name, "type": ptype or "string", "base": base_for(ptype)})
            for name, ptype in body_props(op).items():
                if not name or name in SKIP_NAMES or ptype in ("boolean", "object"):
                    continue
                params.append({"name": name, "type": ptype or "string", "base": base_for(ptype), "body": True})
            if params:
                host, is_pending = route_host()
                item = {
                    "idx": len(manifest),
                    "method": str(method).upper(),
                    "path": path,
                    "host": host,
                    "params": params,
                }
                if is_pending:
                    item["routePending"] = True
                    pending.append({
                        "method": str(method).upper(),
                        "path": path,
                        "host": "",
                        "paramCount": len(params),
                    })
                manifest.append(item)
    counts: Dict[str, int] = {}
    for item in manifest:
        for pr in item["params"]:
            key = "{}{}".format(pr.get("type") or "string", "/body" if pr.get("body") else "")
            counts[key] = counts.get(key, 0) + 1
    result = {
        "source": openapi_path,
        "schema": SQLI_SCREEN_SCHEMA_VERSION,
        "builtAt": datetime.now().isoformat(timespec="seconds"),
        "endpointCount": len(manifest),
        "paramCount": sum(len(item["params"]) for item in manifest),
        "paramTypeCounts": counts,
        "pendingRouteResolution": pending,
        "items": manifest,
    }
    if out_path:
        Path(out_path).parent.mkdir(parents=True, exist_ok=True)
        Path(out_path).write_text(json.dumps(result, ensure_ascii=False, indent=1), encoding="utf-8")
    return result


def persist_sqli_screen_snapshots(items: Sequence[Mapping[str, Any]], *,
                                  project_id: str, env_id: str,
                                  auth_mode: str = "account",
                                  manifest_sha256: str = "",
                                  screening_class_overrides: Optional[Mapping[str, str]] = None) -> Tuple[List[Any], int, List[Any]]:
    """Persist one snapshot per manifest item with its planned parameter spec.

    Returns ``(snapshots, created, skipped_pending)``. The third entry is the
    list of items whose host could not be resolved at build time; they are not
    persisted until a route resolver assigns a real host.

    Immutability: snapshots are keyed by ``sqli:{project}:{method}:{path}:
    {host}:{screening_class}:{manifest_sha256}``. Re-running with a new
    manifest_sha256 (or after host/screening_class changes) creates a fresh
    snapshot instead of mutating the old one, so historical run references
    remain stable.
    """
    snapshots: List[Any] = []
    created = 0
    skipped_pending: List[Mapping[str, Any]] = []
    overrides = dict(screening_class_overrides or {})
    for fallback_idx, item in enumerate(items, start=100000):
        method = str(item.get("method") or "GET").upper()
        host = str(item.get("host") or "").rstrip("/")
        path = str(item.get("path") or "")
        if host == "__pending_route__" or not host:
            skipped_pending.append(item)
            continue
        domain = urlsplit(host).netloc if host else ""
        query_values = {}
        body_values = {}
        spec = []
        for pr in item.get("params") or []:
            name = str(pr.get("name") or "")
            if not name:
                continue
            base = str(pr.get("base") or ("1,2" if pr.get("type") == "array" else "1"))
            position = "body" if pr.get("body") else "query"
            spec.append({"name": name, "position": position, "base": base})
            if position == "body":
                body_values[name] = base
            else:
                query_values[name] = base
        # default screening_class from method; per-path override wins
        screening_class = overrides.get(
            "{}:{}".format(method, path),
            DEFAULT_SCREENING_CLASS_BY_METHOD.get(method, "unknown"),
        )
        template_key = "sqli:{}:{}:{}:{}:{}:{}".format(
            project_id, method, path, domain, screening_class, manifest_sha256 or "v1",
        )
        url = host + path
        if query_values:
            url += "?" + urlencode(query_values, doseq=True)
        body = body_values if body_values else {}
        content_type = "application/json" if body else "application/x-www-form-urlencoded"
        # immutability: never overwrite; insert-or-fetch by template_key.
        snapshot = request_snapshot.objects(template_key=template_key).first()
        if snapshot is None:
            snapshot = request_snapshot(
                pathid=int(item.get("idx") if item.get("idx") is not None else fallback_idx),
                source="sqli_screen_plan",
                project_id=project_id,
                env_id=env_id,
                auth_mode=auth_mode,
                method=method,
                url=url,
                path=path,
                domain=domain,
                query=query_values,
                headers={},
                body=body,
                content_type=content_type,
                expected_status_codes=[],
                parameter_sources={},
                template_key=template_key,
                metadata={
                    "sqli_screen": {
                        "schema": SQLI_SCREEN_SCHEMA_VERSION,
                        "spec": spec,
                        "screening_class": screening_class,
                        "manifest_sha256": manifest_sha256 or "",
                    },
                },
            )
            snapshot.save(force_insert=True)
            created += 1
        snapshots.append(snapshot)
    return snapshots, created, skipped_pending
