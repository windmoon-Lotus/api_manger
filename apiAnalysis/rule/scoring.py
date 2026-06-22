from typing import Any, Dict, List


def score_rule_from_evidence(evidence: Dict[str, Any]):
    score = 0.0
    reason_codes: List[str] = []
    test_ok = bool(evidence.get("test_success"))
    base_ok = bool(evidence.get("baseline_success"))
    ratio = float(evidence.get("text_len_ratio") or 0.0)
    overlap = float(evidence.get("json_overlap") or 0.0)
    scenario = evidence.get("scenario")

    if not test_ok:
        reason_codes.append("TEST_NOT_SUCCESS")
        return {
            "rule_score": 10.0,
            "rule_result": "no_vuln",
            "rule_reason_codes": reason_codes,
        }

    score += 40
    reason_codes.append("TEST_SUCCESS")

    if scenario == "unauth":
        score += 20
        reason_codes.append("SCENARIO_UNAUTH")

    has_baseline = evidence.get("baseline_status") is not None
    if has_baseline:
        if not base_ok:
            score += 30
            reason_codes.append("BASELINE_FAIL_TEST_PASS")
        else:
            reason_codes.append("BASELINE_SUCCESS")
            if overlap >= 0.7:
                score += 20
                reason_codes.append("JSON_OVERLAP_HIGH")
            if ratio >= 0.7:
                score += 10
                reason_codes.append("TEXT_RATIO_HIGH")
    else:
        if evidence.get("test_text_len", 0) > 0:
            score += 10
            reason_codes.append("NO_BASELINE_BUT_HAS_BODY")

    score = round(min(100.0, max(0.0, score)), 2)

    if score >= 75:
        result = "potential_vuln"
    elif score >= 45:
        result = "need_review"
    else:
        result = "no_vuln"

    # Without a baseline comparison we cannot confirm the response actually
    # exposes protected data (a public 200 is not a finding), so do not let a
    # test-only success auto-escalate to potential_vuln.
    if result == "potential_vuln" and not has_baseline:
        result = "need_review"
        reason_codes.append("UNCONFIRMED_NO_BASELINE")

    return {
        "rule_score": score,
        "rule_result": result,
        "rule_reason_codes": reason_codes,
    }

