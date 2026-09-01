"""Recompute stored verdicts from their own evidence and flag mismatches.

A verdict nobody can recompute is a claim, not a result. This tool reloads a
screening evidence file, reruns the classification logic over the recorded
raw metrics, and compares with the stored verdict. Any mismatch means the
evidence file is not self-contained (or the verdict was edited) - both are
audit findings, independent of whether the verdict was correct.

Supported evidence kinds (auto-detected by the "tool" field):
  whitehat_sqli_screen  - output of tools/whitehat_sqli_screen.py

Usage:
  python -m tools.audit.evidence_verify --evidence screening.json [--out report.json]
"""
import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from tools.whitehat_sqli_screen import ERROR_RE, diff_pct, evaluate_param  # noqa: E402

BASELINE_STEP_NAMES = ("benign", "omitted", "baseline")


def _step_metric(step: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "statusCode": step.get("statusCode"),
        "elapsedMs": step.get("elapsedMs") or 0,
        "responseLength": step.get("responseLength")
        or len(str(step.get("text") or "")),
        "bodySample": str(step.get("text") or ""),
    }


def verify_step_metrics(evidence: Dict[str, Any]) -> Dict[str, Any]:
    """Recompute verdicts from per-step raw metrics (heterogeneous schema).

    Rows look like: {label, param, verdict, steps: {name: {statusCode,
    elapsedMs, responseLength, text}}}. The baseline step is detected by name
    (benign/omitted/baseline); boolean control pairs are located by payload
    name (bool_true/bool_false) when present. The recomputation applies the
    standard screening rule to the recorded metrics and compares.
    """
    checks: List[Dict[str, Any]] = []
    mismatch = 0
    for row in evidence.get("results") or []:
        steps = row.get("steps")
        if not isinstance(steps, dict) or not steps:
            checks.append({"label": row.get("label") or row.get("id"),
                           "stored": row.get("verdict"), "ok": False,
                           "reason": "no steps recorded"})
            mismatch += 1
            continue
        baseline_name = next((n for n in BASELINE_STEP_NAMES if n in steps), None)
        if baseline_name is None:
            checks.append({"label": row.get("label") or row.get("id"),
                           "stored": row.get("verdict"), "ok": False,
                           "reason": "no baseline step (benign/omitted/baseline)"})
            mismatch += 1
            continue
        baseline = _step_metric(steps[baseline_name])

        # unreachable route: every step non-2xx -> the round correctly stored
        # an "error" short-circuit verdict; nothing to screen-recompute.
        all_statuses = [s.get("statusCode") for s in steps.values()]
        if all_statuses and all(isinstance(c, int) and not (200 <= c < 300)
                                for c in all_statuses):
            stored = str(row.get("verdict") or "")
            ok = stored.startswith("error") or stored.startswith("not_evaluable")
            if not ok:
                mismatch += 1
            checks.append({
                "label": row.get("label") or row.get("id"),
                "param": row.get("param"),
                "stored": stored,
                "recomputed": "error",
                "reason": "all steps non-2xx (route unreachable)",
                "ok": ok,
            })
            continue

        signals: List[str] = []
        for name, step in steps.items():
            if name == baseline_name:
                continue
            if step.get("statusCode") and ERROR_RE.search(str(step.get("text") or "")):
                signals.append(f"error_based:{name}")
        if "bool_true" in steps and "bool_false" in steps:
            true_len = _step_metric(steps["bool_true"])["responseLength"]
            false_len = _step_metric(steps["bool_false"])["responseLength"]
            d_tf = diff_pct(true_len, false_len)
            d_tb = diff_pct(true_len, baseline["responseLength"])
            if d_tf >= 5.0 and d_tb >= 5.0:
                signals.append("boolean_based")

        stored = str(row.get("verdict") or "")
        recomputed = "signal" if signals else "no_signal"
        ok = (recomputed == stored) or (stored == "signal" and signals) \
            or (stored == "no_signal" and not signals)
        if stored not in ("signal", "no_signal"):
            ok = stored.startswith(recomputed) or recomputed.startswith(stored)
        if not ok:
            mismatch += 1
        checks.append({
            "label": row.get("label") or row.get("id"),
            "param": row.get("param"),
            "stored": stored,
            "recomputed": recomputed,
            "recomputed_signals": signals,
            "baseline_step": baseline_name,
            "ok": ok,
        })
    return {
        "kind": "step_metrics",
        "rowsChecked": len(checks),
        "mismatches": mismatch,
        "checks": checks,
        "verdict": "fail" if mismatch else "pass",
    }


def _payload_result(row: Dict[str, Any], name: str) -> Dict[str, Any]:
    for p in row.get("payloads") or []:
        if p.get("name") == name:
            return {
                "statusCode": p.get("statusCode"),
                "elapsedMs": p.get("elapsedMs"),
                "responseLength": p.get("responseLength"),
                "bodySample": p.get("bodyPreview") or "",
            }
    return {"statusCode": None, "elapsedMs": 0, "responseLength": 0, "bodySample": ""}


def verify_sqli_screen(evidence: Dict[str, Any]) -> Dict[str, Any]:
    results = evidence.get("results") or []
    checks: List[Dict[str, Any]] = []
    mismatch = 0
    for row in results:
        if row.get("verdict") == "error":
            # baseline-error short-circuit: nothing to recompute beyond baseline.
            checks.append({"url": row.get("url"), "param": row.get("param"),
                           "stored": "error", "recomputed": "error", "ok": True})
            continue
        names = [p.get("name") for p in row.get("payloads") or []]
        pairs = []
        from tools.whitehat_sqli_screen import PAYLOADS, TIME_BASED_PAYLOADS
        for name, value in PAYLOADS + TIME_BASED_PAYLOADS:
            if name in names:
                pairs.append((name, value, _payload_result(row, name)))
        baseline = row.get("baseline") or {}
        recomputed = evaluate_param(baseline, pairs)
        stored = row.get("verdict")
        ok = stored == recomputed["verdict"]
        # signals recorded as fired must re-fire; extra recomputed signals are
        # also a mismatch (stored evidence understates what its metrics show).
        stored_signals = set(row.get("signals") or [])
        recomputed_signals = set(recomputed["signals"])
        signals_ok = stored_signals == recomputed_signals
        if not ok or not signals_ok:
            mismatch += 1
        checks.append({
            "url": row.get("url"), "param": row.get("param"),
            "stored": stored, "recomputed": recomputed["verdict"],
            "stored_signals": sorted(stored_signals),
            "recomputed_signals": sorted(recomputed_signals),
            "ok": ok and signals_ok,
        })
    return {
        "kind": "whitehat_sqli_screen",
        "rowsChecked": len(checks),
        "mismatches": mismatch,
        "checks": checks,
        "verdict": "fail" if mismatch else "pass",
    }


def detect_kind(evidence: Dict[str, Any]) -> str:
    """Detect evidence kind by explicit field, falling back to shape."""
    kind = str(evidence.get("tool") or "")
    if kind:
        return kind
    rows = evidence.get("results")
    if isinstance(rows, list) and rows and isinstance(rows[0], dict) \
            and "payloads" in rows[0] and "verdict" in rows[0]:
        return "whitehat_sqli_screen"
    if isinstance(rows, list) and rows and isinstance(rows[0], dict) \
            and isinstance(rows[0].get("steps"), dict) and "verdict" in rows[0]:
        return "step_metrics"
    return kind or "<unknown>"


def verify_evidence(evidence: Dict[str, Any]) -> Dict[str, Any]:
    kind = detect_kind(evidence)
    if kind == "whitehat_sqli_screen":
        return verify_sqli_screen(evidence)
    if kind == "step_metrics":
        return verify_step_metrics(evidence)
    return {
        "kind": kind or "<unknown>",
        "verdict": "unsupported",
        "error": "no verifier registered for this evidence kind; "
                 "supported: whitehat_sqli_screen, step_metrics",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Recompute verdicts from an evidence file.")
    parser.add_argument("--evidence", required=True, help="evidence JSON file")
    parser.add_argument("--out", help="write report JSON here (default: stdout only)")
    args = parser.parse_args()

    evidence = json.loads(Path(args.evidence).read_text(encoding="utf-8-sig"))
    report = verify_evidence(evidence)

    text = json.dumps(report, ensure_ascii=False, indent=2)
    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(text, encoding="utf-8")
    print(text)
    return 1 if report.get("verdict") == "fail" else 0


if __name__ == "__main__":
    raise SystemExit(main())
