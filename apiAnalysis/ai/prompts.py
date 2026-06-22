import json
from typing import Any, Dict


PROMPT_VERSION = "v1"


def build_privilege_prompt_payload(
        scenario: str,
        endpoint: str,
        method: str,
        action: str,
        rule_result: str,
        rule_score: float,
        evidence: Dict[str, Any],
        endpoint_description: str = "",
        prompt_ver: str = PROMPT_VERSION,
):
    instruction = (
        "你是API越权检测裁决器。只能基于给定证据判断，不得臆测。"
        "输出JSON对象，必须包含字段：result,risk_level,confidence,reason,reason_codes,next_action,evidence。"
        "result只能是 potential_vuln/no_vuln/need_review。"
        "confidence范围0到1。"
    )
    content = {
        "prompt_ver": prompt_ver,
        "scenario": scenario,
        "endpoint": endpoint,
        "method": method,
        "action": action,
        "rule_result": rule_result,
        "rule_score": rule_score,
        "endpoint_description": endpoint_description or "",
        "evidence": evidence or {},
    }
    prompt_text = instruction + "\n" + json.dumps(content, ensure_ascii=False)
    return {
        "prompt_ver": prompt_ver,
        "instruction": instruction,
        "input": content,
        "prompt": prompt_text,
    }

