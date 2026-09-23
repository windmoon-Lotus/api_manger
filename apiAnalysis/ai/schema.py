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


RESULT_SCHEMA_V1 = "v1"
RESULT_SCHEMA_V2 = "v2"

# v2 and later require a justification triad before a verdict is accepted.  v1
# payloads keep their historical behaviour so archived snapshots stay readable.
JUSTIFICATION_REQUIRED_FROM = RESULT_SCHEMA_V2

BINDING_ASSOCIATED = "associated"
BINDING_UNASSOCIATED = "unassociated"

REASON_INCOMPLETE_JUSTIFICATION = "AI_JUSTIFICATION_INCOMPLETE"
REASON_UNASSOCIATED = "AI_UNASSOCIATED"


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


def _first_text(payload: Dict[str, Any], *keys: str) -> str:
    for key in keys:
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
        if value not in (None, "", [], {}):
            return str(value).strip()
    return ""


def _normalize_rule_list(value: Any) -> List[str]:
    if isinstance(value, str):
        return [item.strip() for item in value.split(",") if item.strip()]
    if isinstance(value, (list, tuple)):
        return [str(item).strip() for item in value if str(item).strip()]
    return []


def _schema_at_least(prompt_ver: str, floor: str) -> bool:
    return str(prompt_ver or "").strip().lower() >= floor


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

    # What this call actually does, the consequence if it succeeds, and the rule
    # it matched.  All three are required from v2 on: a verdict without them is
    # not a decision, it is an opinion.
    observed_action: str = ""
    consequence: str = ""
    matched_rules: List[str] = field(default_factory=list)
    justification_complete: bool = False

    # Binding to one specific call.  An unverifiable association is reported as
    # unassociated rather than guessed, because a wrong association is worse
    # than a missing one: a missing one is visible, a wrong one looks like fact.
    binding: str = BINDING_ASSOCIATED
    call_id: str = ""
    unassociated_reason: str = ""

    # Fingerprint of what was actually submitted, not of what was intended.
    input_sha256: str = ""
    background_truncated: bool = False

    @classmethod
    def from_payload(cls, payload: Dict[str, Any], prompt_ver: str = "v1",
                     raw_text: str = "", input_sha256: str = "",
                     background_truncated: bool = False):
        payload = payload or {}
        verdict = payload.get("result") or payload.get("verdict") or payload.get("AI研判结论")
        reason = payload.get("reason") or payload.get("AI研判原因") or ""
        risk_level = payload.get("risk_level") or payload.get("risk") or "medium"
        confidence = payload.get("confidence", 0.5)
        reason_codes = payload.get("reason_codes") or payload.get("codes") or []
        if isinstance(reason_codes, str):
            reason_codes = [i.strip() for i in reason_codes.split(",") if i.strip()]
        reason_codes = list(reason_codes)[:10]
        evidence = payload.get("evidence") if isinstance(payload.get("evidence"), dict) else {}
        next_action = payload.get("next_action") or "manual_review"
        model_ver = payload.get("model_ver") or payload.get("model") or ""

        observed_action = _first_text(
            payload, "observed_action", "actual_action", "实际操作",
        )
        consequence = _first_text(
            payload, "consequence", "effect", "成功后的后果", "实际后果",
        )
        matched_rules = _normalize_rule_list(
            payload.get("matched_rules") or payload.get("rules") or payload.get("命中规则")
        )
        complete = bool(observed_action and consequence and matched_rules)

        normalized_verdict = _normalize_verdict(verdict)
        if _schema_at_least(prompt_ver, JUSTIFICATION_REQUIRED_FROM) and not complete:
            # Missing justification is handled by the failure policy -- never by
            # defaulting to a permissive verdict.
            normalized_verdict = "need_review"
            if REASON_INCOMPLETE_JUSTIFICATION not in reason_codes:
                reason_codes = (reason_codes + [REASON_INCOMPLETE_JUSTIFICATION])[:10]

        return cls(
            verdict=normalized_verdict,
            risk_level=_normalize_risk_level(risk_level),
            confidence=_normalize_confidence(confidence),
            reason=str(reason)[:1000],
            reason_codes=reason_codes,
            evidence=evidence,
            next_action=str(next_action)[:100],
            model_ver=str(model_ver)[:100],
            prompt_ver=prompt_ver,
            raw_text=str(raw_text or "")[:4000],
            observed_action=observed_action[:1000],
            consequence=consequence[:1000],
            matched_rules=matched_rules[:10],
            justification_complete=complete,
            input_sha256=str(input_sha256 or ""),
            background_truncated=bool(background_truncated),
        )

    def associate(self, call_id: str):
        """Bind this verdict to the call it decided."""
        self.call_id = str(call_id or "")
        if not self.call_id:
            self.binding = BINDING_UNASSOCIATED
            self.unassociated_reason = "missing_call_id"
        return self

    @classmethod
    def unassociated(cls, reason: str, prompt_ver: str = RESULT_SCHEMA_V2,
                     input_sha256: str = ""):
        """A verdict that cannot be tied to exactly one call.

        Reported instead of guessing: with concurrent calls of the same
        parameters no result can be uniquely matched, and an invented match
        would silently mis-attribute an outcome.
        """
        return cls(
            verdict="need_review",
            risk_level="medium",
            confidence=0.0,
            reason=str(reason)[:1000],
            reason_codes=[REASON_UNASSOCIATED],
            next_action="manual_review",
            prompt_ver=prompt_ver,
            binding=BINDING_UNASSOCIATED,
            unassociated_reason=str(reason)[:200],
            input_sha256=str(input_sha256 or ""),
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
