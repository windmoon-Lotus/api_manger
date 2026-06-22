import json
from typing import Any, Dict


def parse_ai_http_response(text: str) -> Dict[str, Any]:
    text = str(text or "").strip()
    if not text:
        return {}
    try:
        data = json.loads(text)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {"reason": text[:1000], "result": "need_review"}

