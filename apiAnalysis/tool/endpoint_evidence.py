"""Task-oriented, sanitized endpoint evidence for the knowledge-center UI.

The storage layer intentionally keeps flattened parameter occurrences and a
small number of executable request samples.  This module projects those rows
back into an endpoint-shaped view so the UI never needs to expose storage
details or raw credentials.
"""

import datetime as dt
import json
import re
from collections.abc import Mapping
from typing import Any, Iterable, Optional
from urllib.parse import parse_qsl

from apiAnalysis.db.collection import raw_data, req_data, request_sample, res_data
from apiAnalysis.tool.redact import redact_url


SENSITIVE_KEY_PARTS = {
    "authorization", "proxy-authorization", "cookie", "set-cookie",
    "token", "access_token", "refresh_token", "id_token", "jwt",
    "password", "passwd", "pwd", "secret", "client_secret", "api_key",
    "apikey", "x-api-key", "session", "sessionid", "csrf", "xsrf",
}
REDACTED = "*** 已脱敏 ***"
MAX_TEXT = 3000
MAX_ITEMS = 80


def _text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def _sensitive_key(key: Any) -> bool:
    value = _text(key).strip().lower().replace("-", "_")
    if not value:
        return False
    return any(
        value == part.replace("-", "_")
        or value.endswith("_" + part.replace("-", "_"))
        for part in SENSITIVE_KEY_PARTS
    )


def _redact_inline_secrets(value: str) -> str:
    value = re.sub(
        r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+",
        "Bearer ***",
        value,
    )
    return value[:MAX_TEXT] + ("…" if len(value) > MAX_TEXT else "")


def sanitize_sample_value(value: Any, *, key: str = "", depth: int = 0) -> Any:
    """Return a bounded JSON-compatible value with credential fields removed."""
    if _sensitive_key(key):
        return REDACTED
    if depth >= 8:
        return "…"
    if isinstance(value, Mapping):
        result = {}
        for index, (child_key, child) in enumerate(value.items()):
            if index >= MAX_ITEMS:
                result["…"] = "其余字段已省略"
                break
            result[_text(child_key)] = sanitize_sample_value(
                child, key=_text(child_key), depth=depth + 1,
            )
        return result
    if isinstance(value, (list, tuple, set)):
        items = list(value)
        result = [sanitize_sample_value(item, depth=depth + 1) for item in items[:MAX_ITEMS]]
        if len(items) > MAX_ITEMS:
            result.append("其余数据已省略")
        return result
    if isinstance(value, (dt.datetime, dt.date, dt.time)):
        return value.isoformat()
    if value is None or isinstance(value, (bool, int, float)):
        return value
    text = _text(value)
    stripped = text.strip()
    if stripped[:1] in {"{", "["}:
        try:
            parsed = json.loads(stripped)
        except (TypeError, ValueError):
            pass
        else:
            return sanitize_sample_value(parsed, key=key, depth=depth + 1)
    if "=" in stripped and ("&" in stripped or _sensitive_key(stripped.split("=", 1)[0])):
        pairs = parse_qsl(stripped, keep_blank_values=True)
        if pairs and any(_sensitive_key(pair_key) for pair_key, _ in pairs):
            return {
                pair_key: sanitize_sample_value(pair_value, key=pair_key, depth=depth + 1)
                for pair_key, pair_value in pairs[:MAX_ITEMS]
            }
    return _redact_inline_secrets(text)


def _pretty(value: Any) -> str:
    if value in (None, "", {}, []):
        return ""
    sanitized = sanitize_sample_value(value)
    if isinstance(sanitized, str):
        return sanitized
    return json.dumps(sanitized, ensure_ascii=False, indent=2, default=str)


SOURCE_LABELS = {
    "apifox": "Apifox 接口文档",
    "postman": "Postman 集合",
    "openapi": "OpenAPI 文档",
    "swagger": "Swagger 文档",
    "har": "HAR 流量",
    "mitm": "代理流量",
    "traffic": "真实流量",
}


def _source_kind(endpoint: raw_data, samples: Iterable[request_sample]) -> str:
    explicit = _text(endpoint.source).strip().lower()
    if explicit:
        return explicit
    sample_sources = [_text(item.source).strip().lower() for item in samples]
    for kind in ("har", "mitm", "traffic", "postman"):
        if kind in sample_sources:
            return kind
    meta = dict(endpoint.source_meta or {})
    if meta.get("apifox_endpoint_id") or meta.get("apifox_project_id"):
        return "apifox"
    if endpoint.asset_kind == "abstract":
        return "openapi"
    if endpoint.raw_res:
        return "traffic"
    if endpoint.raw_req:
        return "postman"
    return "unknown"


def _parameter_row(item: Any, direction: str, highlighted: set[str]) -> dict:
    parameter = _text(item.parameter)
    display_path = _text(item.display_path or item.schema_path or item.raw_path or parameter)
    leaf = display_path.replace("[]", "").split(".")[-1].lower()
    values = [] if _sensitive_key(parameter) else [
        sanitize_sample_value(value, key=parameter) for value in list(item.value or [])[:3]
    ]
    return {
        "direction": direction,
        "parameter": parameter,
        "display_path": display_path,
        "position": _text(item.position or ("body" if direction == "response" else "unknown")),
        "required": bool(getattr(item, "required", False)),
        "type": _text(item.type or "unknown"),
        "description": _text(item.des),
        "examples": values,
        "highlight": bool(
            parameter.lower() in highlighted
            or display_path.lower() in highlighted
            or leaf in highlighted
        ),
    }


def _sample_row(item: request_sample) -> dict:
    headers = sanitize_sample_value(dict(item.headers or {}))
    query = sanitize_sample_value(dict(item.query or {}))
    body = sanitize_sample_value(item.body)
    response = sanitize_sample_value(item.response_sample)
    return {
        "source": _text(item.source or "traffic").lower(),
        "source_label": SOURCE_LABELS.get(
            _text(item.source or "traffic").lower(), _text(item.source or "样本"),
        ),
        "method": _text(item.method).upper(),
        "url": redact_url(_text(item.url)),
        "domain": _text(item.domain),
        "query": query,
        "query_pretty": _pretty(query),
        "headers": headers,
        "headers_pretty": _pretty(headers),
        "body": body,
        "body_pretty": _pretty(body),
        "response": response,
        "response_pretty": _pretty(response),
        "status_code": item.response_status_code,
        "response_len": int(item.response_len or 0),
        "hit_count": int(item.hit_count or 0),
        "captured_at": item.last_seen or item.ctime,
        "env_id": _text(item.env_id),
        "account_id": _text(item.account_id),
    }


def endpoint_evidence_view(pathid: Any, *, highlight_names: Optional[Iterable[str]] = None,
                           sample_limit: int = 3, parameter_limit: int = 120) -> dict:
    """Build one Apifox/Postman-like endpoint detail with sanitized samples."""
    try:
        pathid = int(pathid)
    except (TypeError, ValueError):
        return {}
    endpoint = raw_data.objects(ptah_id=pathid).first()
    if not endpoint:
        return {}
    samples = list(request_sample.objects(pathid=pathid).order_by("-last_seen")[:max(0, sample_limit)])
    highlighted = {_text(value).lower() for value in (highlight_names or []) if _text(value)}
    request_parameters = [
        _parameter_row(item, "request", highlighted)
        for item in req_data.objects(raw_data=endpoint).order_by("position", "parameter")[:parameter_limit]
    ]
    response_parameters = [
        _parameter_row(item, "response", highlighted)
        for item in res_data.objects(raw_data=endpoint).order_by("position", "parameter")[:parameter_limit]
    ]
    kind = _source_kind(endpoint, samples)
    meta = dict(endpoint.source_meta or {})
    return {
        "pathid": endpoint.ptah_id,
        "method": _text(endpoint.method).upper(),
        "path": _text(endpoint.path),
        "url": redact_url(_text(endpoint.url)),
        "domain": _text(endpoint.domain),
        "name": _text(meta.get("name") or endpoint.des),
        "description": _text(endpoint.des),
        "action": _text(endpoint.action),
        "tags": _text(endpoint.tags),
        "source": kind,
        "source_label": SOURCE_LABELS.get(kind, "接口资产"),
        "source_id": _text(endpoint.source_id),
        "response_status_codes": list(endpoint.response_status_code or []),
        "request_parameters": request_parameters,
        "response_parameters": response_parameters,
        "request_parameter_count": req_data.objects(raw_data=endpoint).count(),
        "response_parameter_count": res_data.objects(raw_data=endpoint).count(),
        "samples": [_sample_row(item) for item in samples],
        "sample_count": request_sample.objects(pathid=pathid).count(),
    }
