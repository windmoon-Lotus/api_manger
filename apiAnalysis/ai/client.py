from typing import Optional

from apiAnalysis.ai.parser import parse_ai_http_response
from apiAnalysis.ai.schema import AiJudgeResult
from apiAnalysis.conf.conf import ai_endpoint, ai_api_key, ai_timeout
from apiAnalysis.model.model import requests_request


class AiHttpClient:
    def __init__(self, url: Optional[str] = None, api_key: Optional[str] = None, timeout: Optional[int] = None):
        self.url = url or ai_endpoint
        self.api_key = api_key or ai_api_key
        self.timeout = timeout or ai_timeout

    def evaluate(self, payload: str, prompt_ver: str = "v1") -> AiJudgeResult:
        if not self.url:
            return AiJudgeResult.fallback("missing_ai_endpoint", prompt_ver=prompt_ver)
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = "Bearer {}".format(self.api_key)
        try:
            resp = requests_request("POST", self.url, data=payload, headers=headers, timeout=self.timeout)
            raw_text = resp.text or ""
            data = parse_ai_http_response(raw_text)
            return AiJudgeResult.from_payload(data, prompt_ver=prompt_ver, raw_text=raw_text)
        except Exception as e:
            return AiJudgeResult.fallback("ai_http_error: {}".format(str(e)), prompt_ver=prompt_ver)

