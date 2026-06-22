import json
from typing import Any, Dict

from apiAnalysis.ai.client import AiHttpClient
from apiAnalysis.ai.prompts import build_privilege_prompt_payload, PROMPT_VERSION
from apiAnalysis.ai.schema import AiJudgeResult


class PrivilegeAiJudgeService:
    def __init__(self, url: str = None, api_key: str = None, prompt_ver: str = PROMPT_VERSION):
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
              endpoint_description: str = ""):
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
        )
        raw_payload = json.dumps(prompt_payload, ensure_ascii=False)
        ai_result = self.client.evaluate(raw_payload, prompt_ver=self.prompt_ver)
        return ai_result, raw_payload

