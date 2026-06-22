import json
from typing import Any, Dict


SUCCESS_CODES = {200, 201, 202, 204}


def try_json(text: str):
    if not text:
        return None
    try:
        return json.loads(text)
    except Exception:
        return None


def compare_json_overlap(a: Any, b: Any) -> float:
    if not isinstance(a, dict) or not isinstance(b, dict):
        return 0.0
    a_keys = set(a.keys())
    b_keys = set(b.keys())
    if not a_keys or not b_keys:
        return 0.0
    return len(a_keys.intersection(b_keys)) / float(max(len(a_keys), len(b_keys)))


def build_rule_evidence(scenario: str, test: Dict[str, Any], baseline: Dict[str, Any] = None) -> Dict[str, Any]:
    test_evidence = (test or {}).get("evidence") or {}
    base_evidence = (baseline or {}).get("evidence") or {}

    test_status = test_evidence.get("status_code")
    base_status = base_evidence.get("status_code")
    test_text = test_evidence.get("text") or ""
    base_text = base_evidence.get("text") or ""
    test_json = try_json(test_text)
    base_json = try_json(base_text)
    overlap = compare_json_overlap(test_json, base_json)
    ratio = 0.0
    if baseline and len(base_text) > 0:
        ratio = len(test_text) / float(len(base_text))

    return {
        "scenario": scenario,
        "test_status": test_status,
        "baseline_status": base_status,
        "test_success": test_status in SUCCESS_CODES if test_status is not None else False,
        "baseline_success": base_status in SUCCESS_CODES if base_status is not None else False,
        "test_text_len": len(test_text),
        "baseline_text_len": len(base_text),
        "text_len_ratio": ratio,
        "json_overlap": overlap,
        "test_text_sample": test_text[:500],
        "baseline_text_sample": base_text[:500],
    }

