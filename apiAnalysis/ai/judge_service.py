import json
from typing import Any, Dict

from apiAnalysis.ai.client import AiHttpClient, sha256_of
from apiAnalysis.ai.prompts import PROMPT_VERSION, build_privilege_prompt_payload
from apiAnalysis.ai.schema import AiJudgeResult


class PrivilegeAiJudgeService:
    """Run one context review and keep a fingerprint of what was submitted.

    Binding rule: a verdict is only usable when it can be tied to exactly one
    call.  When the caller does not supply ``call_id`` the result is reported as
    unassociated instead of being attached to a guess, because with concurrent
    calls of the same parameters no result can be uniquely matched and an
    invented match would silently mis-attribute an outcome.
    """

    def __init__(self, url: str = None, api_key: str = None,
                 prompt_ver: str = PROMPT_VERSION):
        self.client = AiHttpClient(url=url, api_key=api_key)
        self.prompt_ver = prompt_ver

    def judge(self,
              scenario: str,
              endpoint: str,
              method: str,
              action: str,
              rule_result: str,
              rule_score: float,
              evidence: Dict[str, Any],
              endpoint_description: str = "",
              background: str = "",
              call_id: str = ""):
        prompt_payload = build_privilege_prompt_payload(
            scenario=scenario,
            endpoint=endpoint,
            method=method,
            action=action,
            rule_result=rule_result,
            rule_score=rule_score,
            evidence=evidence,
            endpoint_description=endpoint_description,
            prompt_ver=self.prompt_ver,
            background=background,
        )
        raw_payload = json.dumps(prompt_payload, ensure_ascii=False)
        payload_sha256 = sha256_of(raw_payload)

        if not str(call_id or "").strip():
            return (
                AiJudgeResult.unassociated(
                    "call_id not provided, so this verdict cannot be tied to "
                    "exactly one call; reported unassociated rather than guessed",
                    prompt_ver=self.prompt_ver,
                    input_sha256=payload_sha256,
                ),
                raw_payload,
            )

        ai_result = self.client.evaluate(
            raw_payload,
            prompt_ver=self.prompt_ver,
            background_truncated=bool(prompt_payload.get("background_truncated")),
        )
        ai_result.associate(str(call_id))
        if not ai_result.input_sha256:
            ai_result.input_sha256 = payload_sha256
        return ai_result, raw_payload
