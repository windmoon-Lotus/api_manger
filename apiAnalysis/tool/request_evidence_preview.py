"""Transient, bounded request previews for local execution verification.

The preview deliberately keeps useful business values (resource ids, query
values and body fields) while masking authentication material.  Callers must
print or inspect the returned object in-process; it is not scheduler evidence
and must not be persisted to MongoDB or normal application logs.
"""
import json
import re
from typing import Any, Dict, Mapping, Optional
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from apiAnalysis.tool.parameter_sources import WARNING_SOURCES, is_request_sample_only


MASK = "<redacted>"
MAX_STRING = 160
MAX_FIELDS = 40
MAX_ITEMS = 20
MAX_DEPTH = 5

_SENSITIVE_EXACT = {
    "authorization", "proxyauthorization", "cookie", "setcookie",
    "password", "passwd", "pwd", "secret", "clientsecret", "apikey",
    "accesskey", "token", "accesstoken", "refreshtoken", "idtoken", "jwt",
    "session", "sessionid", "csrf", "csrftoken", "xsrf", "xsrftoken",
    "signature", "sign", "nonce", "credential", "privatekey",
}


def _normalized_name(name: Any) -> str:
    return re.sub(r"[^a-z0-9]", "", str(name or "").lower())


def is_sensitive_name(name: Any) -> bool:
    normalized = _normalized_name(name)
    if normalized in _SENSITIVE_EXACT:
        return True
    return any(token in normalized for token in (
        "authorization", "password", "passwd", "clientsecret", "apikey",
        "accesstoken", "refreshtoken", "authtoken", "sessiontoken",
        "csrftoken", "xsrftoken", "privatekey", "signature", "credential",
    ))


def _bounded_scalar(value: Any) -> Any:
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, bytes):
        return "<binary:{} bytes>".format(len(value))
    text = str(value)
    return text if len(text) <= MAX_STRING else text[:MAX_STRING] + "...<truncated>"


def safe_value(value: Any, *, field_name: Any = "", depth: int = 0) -> Any:
    """Return a bounded copy with values of sensitive named fields masked."""
    if field_name and is_sensitive_name(field_name):
        return MASK
    if depth >= MAX_DEPTH:
        return "<max-depth>"
    if isinstance(value, Mapping):
        result: Dict[str, Any] = {}
        rows = list(value.items())
        for key, item in rows[:MAX_FIELDS]:
            result[str(key)[:100]] = safe_value(item, field_name=key, depth=depth + 1)
        if len(rows) > MAX_FIELDS:
            result["<truncated-fields>"] = len(rows) - MAX_FIELDS
        return result
    if isinstance(value, (list, tuple)):
        result = [safe_value(item, depth=depth + 1) for item in list(value)[:MAX_ITEMS]]
        if len(value) > MAX_ITEMS:
            result.append("<truncated-items:{}>".format(len(value) - MAX_ITEMS))
        return result
    return _bounded_scalar(value)


def _safe_url(url: Any) -> str:
    parsed = urlsplit(str(url or ""))
    host = parsed.hostname or ""
    if parsed.port:
        host = "{}:{}".format(host, parsed.port)
    query = []
    for name, value in parse_qsl(parsed.query, keep_blank_values=True):
        query.append((name, MASK if is_sensitive_name(name) else _bounded_scalar(value)))
    path = re.sub(
        r"(?i)(/(?:token|secret|session|signature|nonce|credential)[^/]*/)[^/]+",
        lambda match: match.group(1) + MASK,
        parsed.path,
    )
    return urlunsplit((parsed.scheme, host, path, urlencode(query, doseq=True), ""))


def _headers(headers: Mapping[str, Any]) -> Dict[str, Any]:
    return {
        str(name)[:100]: MASK if is_sensitive_name(name) else _bounded_scalar(value)
        for name, value in list(dict(headers or {}).items())[:MAX_FIELDS]
    }


def _body(request_kwargs: Mapping[str, Any], snapshot: Any) -> Any:
    if "json" in request_kwargs:
        return safe_value(request_kwargs.get("json"))
    value = request_kwargs.get("data", getattr(snapshot, "body", None))
    if isinstance(value, str):
        content_type = str(
            dict(request_kwargs.get("headers") or {}).get("Content-Type")
            or getattr(snapshot, "content_type", "") or ""
        ).lower()
        if "json" in content_type:
            try:
                return safe_value(json.loads(value))
            except (TypeError, ValueError):
                pass
        if "application/x-www-form-urlencoded" in content_type:
            return {
                name: MASK if is_sensitive_name(name) else _bounded_scalar(item)
                for name, item in parse_qsl(value, keep_blank_values=True)[:MAX_FIELDS]
            }
    return safe_value(value)


def _parameter_sources(snapshot: Any) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    for name, meta in list(dict(getattr(snapshot, "parameter_sources", None) or {}).items())[:MAX_FIELDS]:
        row = dict(meta or {}) if isinstance(meta, Mapping) else {"source": str(meta or "")}
        result[str(name)[:100]] = {
            key: safe_value(row.get(key), field_name=key)
            for key in ("position", "source", "value_quality", "required", "type",
                        "canonical_name", "schema_path")
            if row.get(key) not in (None, "")
        }
    return result


def request_quality_warnings(snapshot: Any) -> list:
    warnings = []
    for name, meta in dict(getattr(snapshot, "parameter_sources", None) or {}).items():
        row = dict(meta or {}) if isinstance(meta, Mapping) else {}
        if str(row.get("source") or "") in WARNING_SOURCES and bool(row.get("required")):
            warnings.append("required_parameter_uses_synthetic_default:{}".format(str(name)[:100]))
        elif bool(row.get("required")) and is_request_sample_only(row.get("value_quality")):
            # A value that was only ever seen in a request may be an interface
            # document placeholder. A 4xx on such a request is not evidence that
            # the endpoint is broken, and the request must not be read as proof
            # that the parameter was satisfied with a valid value.
            warnings.append("required_parameter_value_only_seen_in_a_request:{}".format(str(name)[:100]))
    return sorted(set(warnings))


def request_evidence_preview(snapshot: Any, request_kwargs: Optional[Mapping[str, Any]] = None,
                             *, phase: str = "request") -> Dict[str, Any]:
    """Build a local-only preview of the actual request about to be sent."""
    kwargs = dict(request_kwargs or {})
    headers = dict(kwargs.get("headers") or getattr(snapshot, "headers", None) or {})
    cookies = dict(kwargs.get("cookies") or getattr(snapshot, "cookies", None) or {})
    return {
        "preview_version": "1",
        "storage_policy": "transient_stdout_only",
        "phase": str(phase or "request")[:60],
        "snapshot_id": str(getattr(snapshot, "id", "") or ""),
        "pathid": getattr(snapshot, "pathid", None),
        "method": str(getattr(snapshot, "method", "") or "").upper(),
        "url": _safe_url(getattr(snapshot, "url", "")),
        "headers": _headers(headers),
        "cookies": {str(name)[:100]: MASK for name in list(cookies)[:MAX_FIELDS]},
        "body": _body(kwargs, snapshot),
        "parameter_sources": _parameter_sources(snapshot),
        "quality_warnings": request_quality_warnings(snapshot),
        "limits": {
            "string_chars": MAX_STRING, "fields": MAX_FIELDS,
            "list_items": MAX_ITEMS, "depth": MAX_DEPTH,
        },
    }
