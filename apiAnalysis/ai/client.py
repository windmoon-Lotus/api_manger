import hashlib
from typing import Optional

from apiAnalysis.ai.parser import parse_ai_http_response
from apiAnalysis.ai.prompts import PROMPT_VERSION
from apiAnalysis.ai.schema import AiJudgeResult
from apiAnalysis.conf.conf import ai_endpoint, ai_api_key, ai_timeout
from apiAnalysis.model.model import requests_request


def sha256_of(text: str) -> str:
    return hashlib.sha256(str(text or "").encode("utf-8", errors="replace")).hexdigest()


class AiHttpClient:
    def __init__(self, url: Optional[str] = None, api_key: Optional[str] = None, timeout: Optional[int] = None):
        self.url = url or ai_endpoint
        self.api_key = api_key or ai_api_key
        self.timeout = timeout or ai_timeout

    def evaluate(self, payload: str, prompt_ver: str = PROMPT_VERSION,
                 background_truncated: bool = False) -> AiJudgeResult:
        # Fingerprint what is actually submitted.  Hashing the intended payload
        # instead would let the stored record diverge from what the model saw.
        submitted_sha256 = sha256_of(payload)

        def _tag(result: AiJudgeResult) -> AiJudgeResult:
            if not result.input_sha256:
                result.input_sha256 = submitted_sha256
            result.background_truncated = bool(
                background_truncated or result.background_truncated
            )
            return result

        if not self.url:
            return _tag(AiJudgeResult.fallback("missing_ai_endpoint", prompt_ver=prompt_ver))
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = "Bearer {}".format(self.api_key)
        try:
            resp = requests_request("POST", self.url, data=payload, headers=headers, timeout=self.timeout)
            raw_text = resp.text or ""
            data = parse_ai_http_response(raw_text)
            return _tag(AiJudgeResult.from_payload(
                data, prompt_ver=prompt_ver, raw_text=raw_text,
                input_sha256=submitted_sha256,
                background_truncated=background_truncated,
            ))
        except Exception as e:
            return _tag(AiJudgeResult.fallback("ai_http_error: {}".format(str(e)), prompt_ver=prompt_ver))
