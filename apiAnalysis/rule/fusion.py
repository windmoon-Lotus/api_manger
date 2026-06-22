from typing import Dict


def ai_score(ai_verdict: str, risk_level: str, confidence: float) -> float:
    base = {
        "potential_vuln": 85.0,
        "need_review": 50.0,
        "no_vuln": 15.0,
    }.get(ai_verdict, 50.0)
    risk_adjust = {"high": 10.0, "medium": 0.0, "low": -10.0}.get(risk_level, 0.0)
    conf = max(0.0, min(1.0, float(confidence or 0.0)))
    return round(max(0.0, min(100.0, (base + risk_adjust) * (0.5 + conf / 2.0))), 2)


def fuse_rule_ai(rule_score: float, ai_score_value: float, rule_weight: float = 0.7, ai_weight: float = 0.3) -> Dict:
    score = rule_score * rule_weight + ai_score_value * ai_weight
    score = round(max(0.0, min(100.0, score)), 2)
    if score >= 70:
        result = "potential_vuln"
    elif score <= 35:
        result = "no_vuln"
    else:
        result = "need_review"
    return {"final_score": score, "final_result": result}

