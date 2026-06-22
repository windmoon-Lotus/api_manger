from dataclasses import dataclass, field
from typing import Any, Dict, List


_VERDICT_MAP = {
    "potential_vuln": "potential_vuln",
    "vuln": "potential_vuln",
    "high_risk": "potential_vuln",
    "no_vuln": "no_vuln",
    "safe": "no_vuln",
    "need_review": "need_review",
    "review": "need_review",
}


def _normalize_verdict(value: Any) -> str:
    text = str(value or "").strip().lower()
    if text in _VERDICT_MAP:
        return _VERDICT_MAP[text]
    return "need_review"


def _normalize_risk_level(value: Any) -> str:
    text = str(value or "").strip().lower()
    if text in {"high", "medium", "low"}:
        return text
    return "medium"


def _normalize_confidence(value: Any) -> float:
    try:
        num = float(value)
    except Exception:
        return 0.5
    if num > 1:
        num = num / 100.0
    return max(0.0, min(1.0, num))


@dataclass
class AiJudgeResult:
    verdict: str = "need_review"
    risk_level: str = "medium"
    confidence: float = 0.5
    reason: str = ""
    reason_codes: List[str] = field(default_factory=list)
    evidence: Dict[str, Any] = field(default_factory=dict)
    next_action: str = "manual_review"
    model_ver: str = ""
    prompt_ver: str = "v1"
    raw_text: str = ""

    @classmethod
    def from_payload(cls, payload: Dict[str, Any], prompt_ver: str = "v1", raw_text: str = ""):
        payload = payload or {}
        verdict = payload.get("result") or payload.get("verdict") or payload.get("AI研判结论")
        reason = payload.get("reason") or payload.get("AI研判原因") or ""
        risk_level = payload.get("risk_level") or payload.get("risk") or "medium"
        confidence = payload.get("confidence", 0.5)
        reason_codes = payload.get("reason_codes") or payload.get("codes") or []
        if isinstance(reason_codes, str):
            reason_codes = [i.strip() for i in reason_codes.split(",") if i.strip()]
        evidence = payload.get("evidence") if isinstance(payload.get("evidence"), dict) else {}
        next_action = payload.get("next_action") or "manual_review"
        model_ver = payload.get("model_ver") or payload.get("model") or ""
        return cls(
            verdict=_normalize_verdict(verdict),
            risk_level=_normalize_risk_level(risk_level),
            confidence=_normalize_confidence(confidence),
            reason=str(reason)[:1000],
            reason_codes=reason_codes[:10],
            evidence=evidence,
            next_action=str(next_action)[:100],
            model_ver=str(model_ver)[:100],
            prompt_ver=prompt_ver,
            raw_text=str(raw_text or "")[:4000],
        )

    @classmethod
    def fallback(cls, reason: str, prompt_ver: str = "v1"):
        return cls(
            verdict="need_review",
            risk_level="medium",
            confidence=0.3,
            reason=reason[:1000],
            reason_codes=["AI_FALLBACK"],
            prompt_ver=prompt_ver,
        )

