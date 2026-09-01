"""Generic white-hat SQLi first-pass screening tool (target-agnostic).

Screening methodology: per text parameter, send one benign baseline request plus
a small paired payload set (quote-break, boolean true/false control, paren
boolean, UNION column-count probe, MySQL extractvalue error probe) and classify
each parameter as signal / no_signal / error. This is a first-pass screen, not
a proof of non-injectability - a no_signal verdict only justifies not spending
deep-dive effort on the parameter.

Design rules (mirrors the 2026-08 external-model eval lessons):
  - No hardcoded targets, hosts or credentials: targets and headers come from
    input files so this tool stays publishable under DATA_GOVERNANCE.
  - Hard request budget: projected request count is checked before sending;
    exceeding the budget requires --yes.
  - Every verdict must be recomputable from the emitted evidence file alone
    (the audit layer relies on this).

Usage:
  python tools/whitehat_sqli_screen.py --targets targets.json --out evidence.json \
      --headers-file private-headers.json [--delay-ms 150] [--include-time-based]

targets.json: {"targets": [{"url": "...", "param": "..."}]} or a bare list.
The param must appear in the url query string; all other query parameters are
preserved verbatim on every request.
"""
import argparse
import json
import re
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qsl, quote, urlencode, urlparse

import requests

ROOT = Path(__file__).resolve().parents[1]

DEFAULT_BASELINE_VALUE = "sqli_screen"
DEFAULT_MAX_REQUESTS = 100

PAYLOADS: List[Tuple[str, str]] = [
    ("quote_break", "'"),
    ("bool_true", "' OR '1'='1"),
    ("bool_false", "' OR '1'='2"),
    ("paren_bool_true", "') OR ('1'='1"),
    ("union_probe", "' UNION SELECT NULL-- -"),
    ("mysql_extractvalue", "' AND extractvalue(1,concat(0x7e,version()))-- -"),
]

TIME_BASED_PAYLOADS: List[Tuple[str, str]] = [
    ("time_sleep", "' AND SLEEP(2)-- -"),
    ("time_benchmark", "' AND BENCHMARK(2000000,MD5('x'))-- -"),
]

ERROR_PATTERNS = [
    r"SQLSTATE",
    r"SQL syntax",
    r"\bmysqli?_",
    r"\bmysql\.",
    r"PostgreSQL.*?ERROR",
    r"unclosed quotation mark",
    r"unterminated quoted string",
    r"quoted string not properly terminated",
    r"ORA-\d{5}",
    r"Microsoft\s+OLE\s+DB",
    r"ODBC\s+SQL\s+Server\s+Driver",
    r"Incorrect syntax near",
    r"You have an error in your SQL syntax",
    r"valid MySQL result",
    r"MySqlClient\.",
    r"PG::SyntaxError",
    r"pg_query\(\)",
    r"pg_exec\(\)",
    r"SQLite/JDBCDriver",
    r"SQLite\.Exception",
    r"System\.Data\.SqlClient\.",
    r"each UNION query must have the same number of columns",
    r"different number of columns",
    r"supplied argument is not a valid MySQL",
    r"Warning.*?\bmysql_",
    r"\[SQLServer\]",
    r"\[Microsoft\]\[ODBC",
    r"com\.mysql\.jdbc",
    r"java\.sql\.SQLException",
    r"hibernate\.persister",
    r"Hibernate\s+Exception",
    r"syntax error at or near",
]
ERROR_RE = re.compile("|".join(f"(?:{p})" for p in ERROR_PATTERNS), re.I)

EMPTY_RESULT_RE = re.compile(r'^\[\]$|^\{\s*(?:"[a-z_]*list"\s*:\s*\[\]|"total\w*"\s*:\s*"?0"?)', re.I)

BOOLEAN_DIFF_THRESHOLD_PCT = 5.0
TIME_BASED_THRESHOLD_S = 1.5


def set_param(url: str, key: str, new_val: str) -> str:
    """Replace one query value in the url, preserving every other pair and order."""
    parts = urlparse(url)
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    if key not in [k for k, _ in pairs]:
        raise ValueError(f"param {key!r} not present in url query: {url}")
    out = [(k, new_val if k == key else v) for k, v in pairs]
    new_q = urlencode(out, doseq=False, quote_via=quote, safe="")
    return f"{parts.scheme}://{parts.netloc}{parts.path}?{new_q}"


def send_get(url: str, headers: Dict[str, str], timeout: float) -> Dict[str, Any]:
    t0 = time.perf_counter()
    try:
        r = requests.get(url, headers=headers, timeout=timeout, verify=False, allow_redirects=False)
        elapsed_ms = round((time.perf_counter() - t0) * 1000, 2)
        body = r.content or b""
        return {
            "statusCode": r.status_code,
            "elapsedMs": elapsed_ms,
            "responseLength": len(body),
            "bodySample": body[:4096].decode("utf-8", errors="replace"),
        }
    except Exception as exc:
        return {
            "statusCode": None,
            "elapsedMs": round((time.perf_counter() - t0) * 1000, 2),
            "responseLength": 0,
            "error": type(exc).__name__ + ": " + str(exc)[:300],
        }


def diff_pct(a: float, b: float) -> float:
    base = max(abs(a), abs(b))
    return abs(a - b) / base * 100.0 if base else 0.0


def _payload_resp(results: List[Tuple[str, str, Dict[str, Any]]], name: str) -> Optional[Dict[str, Any]]:
    return next((r for n, _, r in results if n == name), None)


def evaluate_param(baseline: Dict[str, Any],
                   results: List[Tuple[str, str, Dict[str, Any]]]) -> Dict[str, Any]:
    """Classify one parameter from its baseline + payload responses.

    Verdicts: signal (at least one detection fired), no_signal, or the caller
    keeps error for unreachable baselines. Every fired detection is recorded
    with its evidence so the verdict can be recomputed later.
    """
    signals: List[str] = []
    notes: List[str] = []
    error_hits: List[Dict[str, Any]] = []

    # 1) Error-based: SQL error pattern in any payload response.
    for pname, pval, resp in results:
        body = resp.get("bodySample", "") or ""
        m = ERROR_RE.search(body)
        if m:
            error_hits.append({
                "payload": pname,
                "value": pval,
                "matched": m.group(0),
                "statusCode": resp.get("statusCode"),
                "evidence": body[:200],
            })
    if error_hits:
        signals.append("error_based")
        notes.append(f"SQL error pattern matched on {len(error_hits)} payload(s)")

    # 2) Boolean: true vs false control must differ, and true vs baseline too.
    p2 = _payload_resp(results, "bool_true")
    p3 = _payload_resp(results, "bool_false")
    if p2 and p3 and p2.get("statusCode") and p3.get("statusCode"):
        d_tf = diff_pct(p2.get("responseLength", 0), p3.get("responseLength", 0))
        d_tb = diff_pct(p2.get("responseLength", 0), baseline.get("responseLength", 0))
        notes.append(f"bool_true_vs_false: {d_tf:.1f}% length diff; bool_true_vs_baseline: {d_tb:.1f}%")
        if d_tf >= BOOLEAN_DIFF_THRESHOLD_PCT and d_tb >= BOOLEAN_DIFF_THRESHOLD_PCT:
            signals.append("boolean_based")
            notes.append("BOOLEAN signal: true/false differ >=5% AND true differs from baseline >=5%")

    # 3) Paren-closed boolean.
    p4 = _payload_resp(results, "paren_bool_true")
    if p4 and p3 and p4.get("statusCode") and p3.get("statusCode"):
        d_pf = diff_pct(p4.get("responseLength", 0), p3.get("responseLength", 0))
        d_pb = diff_pct(p4.get("responseLength", 0), baseline.get("responseLength", 0))
        notes.append(f"paren_true_vs_false: {d_pf:.1f}%; paren_true_vs_baseline: {d_pb:.1f}%")
        if d_pf >= BOOLEAN_DIFF_THRESHOLD_PCT and d_pb >= BOOLEAN_DIFF_THRESHOLD_PCT:
            signals.append("paren_boolean_based")

    # 4) UNION column-count error.
    p5 = _payload_resp(results, "union_probe")
    if p5:
        body = (p5.get("bodySample") or "").lower()
        if "different number of columns" in body or "each union query must have the same number" in body:
            signals.append("union_column_count")

    # 5) Time-based (only when those payloads were sent).
    base_ms = baseline.get("elapsedMs") or 0
    for pname in ("time_sleep", "time_benchmark"):
        pr = _payload_resp(results, pname)
        if pr and pr.get("statusCode"):
            extra_s = ((pr.get("elapsedMs") or 0) - base_ms) / 1000.0
            notes.append(f"{pname}: +{extra_s:.1f}s vs baseline")
            if extra_s >= TIME_BASED_THRESHOLD_S:
                signals.append("time_based")

    # 6) Observability caveat: an empty baseline result set makes boolean
    #    differentials unobservable -> downgrade no_signal confidence.
    base_body = (baseline.get("bodySample") or "").strip()
    if baseline.get("statusCode") == 200 and EMPTY_RESULT_RE.match(base_body):
        notes.append("observability: baseline is an empty result set - boolean differential is "
                     "unobservable; no_signal here is a weak negative, not evidence of parameterization")

    # 7) Status anomalies worth a human look even when not classified as signal.
    code_anomalies = [
        {"payload": n, "status": r.get("statusCode"), "baseline": baseline.get("statusCode")}
        for n, _, r in results
        if r.get("statusCode") != baseline.get("statusCode") and r.get("statusCode") in (400, 500, 502, 503, 504)
    ]
    if code_anomalies:
        notes.append(f"status anomalies (4xx/5xx) on: {[a['payload'] for a in code_anomalies]}")

    return {
        "verdict": "signal" if signals else "no_signal",
        "signals": signals,
        "notes": notes,
        "error_hits": error_hits,
        "code_anomalies": code_anomalies,
    }


def load_targets(path: Path) -> List[Dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    targets = data.get("targets") if isinstance(data, dict) else data
    if not isinstance(targets, list):
        raise SystemExit("targets file must be a list or {'targets': [...]}")
    for t in targets:
        if not t.get("url") or not t.get("param"):
            raise SystemExit(f"target missing url/param: {t!r}")
        if t["param"] not in dict(parse_qsl(urlparse(t["url"]).query, keep_blank_values=True)):
            raise SystemExit(f"param {t['param']!r} not in url query: {t['url']}")
    return targets


def load_headers(header_args: List[str], headers_file: Optional[str] = None) -> Dict[str, str]:
    """Load request headers without requiring secrets in process arguments."""
    headers: Dict[str, str] = {}
    if headers_file:
        loaded = json.loads(Path(headers_file).read_text(encoding="utf-8-sig"))
        if not isinstance(loaded, dict):
            raise SystemExit("--headers-file must contain a JSON object of headers")
        headers.update({str(name): str(value) for name, value in loaded.items()})
    for header in header_args:
        if ":" not in header:
            raise SystemExit(f"--header expects 'Name: value', got {header!r}")
        name, value = header.split(":", 1)
        headers[name.strip()] = value.strip()
    headers.setdefault("User-Agent", "whitehat-sqli-screen/1.0")
    return headers


def main() -> int:
    parser = argparse.ArgumentParser(description="White-hat SQLi first-pass screening (generic).")
    parser.add_argument("--targets", required=True, help="JSON file with targets")
    parser.add_argument("--out", required=True, help="evidence output JSON path")
    parser.add_argument("--header", action="append", default=[],
                        help="extra request header, 'Name: value' (repeatable)")
    parser.add_argument("--headers-file",
                        help="JSON file holding a {Name: value} header dict; "
                             "keep secrets outside the repo and out of argv")
    parser.add_argument("--baseline-value", default=DEFAULT_BASELINE_VALUE)
    parser.add_argument("--include-time-based", action="store_true",
                        help="add SLEEP/BENCHMARK payloads (slower; adds a time-based signal class)")
    parser.add_argument("--delay-ms", type=int, default=150, help="delay between requests (default 150)")
    parser.add_argument("--timeout", type=float, default=15.0)
    parser.add_argument("--max-requests", type=int, default=DEFAULT_MAX_REQUESTS,
                        help="hard budget; exceeding requires --yes (default 100)")
    parser.add_argument("--yes", action="store_true", help="allow runs above --max-requests")
    args = parser.parse_args()

    headers = load_headers(args.header, args.headers_file)

    targets = load_targets(Path(args.targets))
    payloads = PAYLOADS + (TIME_BASED_PAYLOADS if args.include_time_based else [])
    projected = len(targets) * (1 + len(payloads))
    if projected > args.max_requests and not args.yes:
        raise SystemExit(f"projected {projected} requests exceeds --max-requests {args.max_requests}; "
                         f"rerun with --yes or fewer targets")

    requests.packages.urllib3.disable_warnings()  # type: ignore[attr-defined]
    log: List[Dict[str, Any]] = []
    total_req = 0
    for t in targets:
        base_url = set_param(t["url"], t["param"], args.baseline_value)
        baseline = send_get(base_url, headers, args.timeout)
        total_req += 1
        time.sleep(args.delay_ms / 1000.0)
        if baseline.get("statusCode") != 200:
            log.append({
                "url": t["url"], "param": t["param"], "note": t.get("note"),
                "baseline": {k: baseline.get(k) for k in ("statusCode", "elapsedMs", "responseLength", "error")},
                "verdict": "error",
                "reason": f"baseline non-200 ({baseline.get('statusCode')})",
                "payloads_sent": 0,
            })
            print(f"  [error] {t['url'][:70]} baseline={baseline.get('statusCode')}")
            continue

        results = []
        for pname, pval in payloads:
            url = set_param(t["url"], t["param"], pval)
            resp = send_get(url, headers, args.timeout)
            total_req += 1
            time.sleep(args.delay_ms / 1000.0)
            results.append((pname, pval, resp))
            print(f"  {t['url'][:60]}  {pname:>18s}  status={resp.get('statusCode')}  "
                  f"len={resp.get('responseLength')}  ms={resp.get('elapsedMs')}")

        ev = evaluate_param(baseline, results)
        log.append({
            "url": t["url"], "param": t["param"], "note": t.get("note"),
            "baseline": {k: baseline.get(k) for k in ("statusCode", "elapsedMs", "responseLength")},
            "verdict": ev["verdict"],
            "signals": ev["signals"],
            "notes": ev["notes"],
            "error_hits": ev["error_hits"],
            "code_anomalies": ev["code_anomalies"],
            "payloads": [
                {"name": n, "value": v, "statusCode": r.get("statusCode"),
                 "elapsedMs": r.get("elapsedMs"), "responseLength": r.get("responseLength"),
                 "bodyPreview": (r.get("bodySample") or "")[:2048]}
                for n, v, r in results
            ],
        })
        print(f"  => {ev['verdict']}  signals={ev['signals']}")

    summary = {
        "tool": "whitehat_sqli_screen",
        "ranAt": int(time.time()),
        "baselineValue": args.baseline_value,
        "payloadSet": [n for n, _ in payloads],
        "targetCount": len(targets),
        "totalRequests": total_req,
        "verdicts": {
            "signal": sum(1 for l in log if l.get("verdict") == "signal"),
            "no_signal": sum(1 for l in log if l.get("verdict") == "no_signal"),
            "error": sum(1 for l in log if l.get("verdict") == "error"),
        },
        "results": log,
    }
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"out": str(out), "totalRequests": total_req, "verdicts": summary["verdicts"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
