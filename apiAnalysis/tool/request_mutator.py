"""
Utilities for mutating a standardized request payload.

The mutator is intentionally independent from MongoEngine so tests and future
tool adapters can use it without a database connection.
"""
import copy
from typing import Any, Dict
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


def _ensure_dict(value):
    return value if isinstance(value, dict) else {}


def _set_nested(target: Dict[str, Any], dotted_name: str, value: Any):
    parts = [part for part in str(dotted_name).split(".") if part != ""]
    if not parts:
        return
    cursor = target
    for part in parts[:-1]:
        existing = cursor.get(part)
        if not isinstance(existing, dict):
            existing = {}
            cursor[part] = existing
        cursor = existing
    cursor[parts[-1]] = value


def _mutate_url_query(url: str, name: str, value: Any) -> str:
    if not url:
        return url
    split = urlsplit(url)
    query = dict(parse_qsl(split.query, keep_blank_values=True))
    query[name] = value
    return urlunsplit((split.scheme, split.netloc, split.path, urlencode(query, doseq=True), split.fragment))


def mutate_request(payload: Dict[str, Any], position: str, name: str, value: Any) -> Dict[str, Any]:
    """
    Return a deep-copied request payload with one parameter changed.

    Supported positions: query, path, header, cookie, body, form, json.
    `body` and `json` support dotted names such as `user.profile.name`.
    """
    result = copy.deepcopy(payload or {})
    position = (position or "body").lower()
    name = str(name or "")
    if not name:
        return result

    if position == "query":
        result["query"] = dict(_ensure_dict(result.get("query")))
        result["query"][name] = value
        result["url"] = _mutate_url_query(result.get("url") or "", name, value)
        return result

    if position == "path":
        result["path_params"] = dict(_ensure_dict(result.get("path_params")))
        result["path_params"][name] = value
        url = result.get("url") or ""
        result["url"] = url.replace("{" + name + "}", str(value)).replace(":" + name, str(value))
        return result

    if position == "header":
        result["headers"] = dict(_ensure_dict(result.get("headers")))
        result["headers"][name] = value
        return result

    if position == "cookie":
        result["cookies"] = dict(_ensure_dict(result.get("cookies")))
        result["cookies"][name] = value
        return result

    if position in {"body", "json"}:
        body = copy.deepcopy(result.get("body") or {})
        if not isinstance(body, dict):
            body = {"_raw": body}
        _set_nested(body, name, value)
        result["body"] = body
        return result

    if position == "form":
        body = copy.deepcopy(result.get("body") or {})
        if not isinstance(body, dict):
            body = {}
        body[name] = value
        result["body"] = body
        result["content_type"] = result.get("content_type") or "application/x-www-form-urlencoded"
        return result

    result.setdefault("metadata", {})
    result["metadata"]["unsupported_mutation"] = {
        "position": position,
        "name": name,
        "value": value,
    }
    return result


def mutate_many(payload: Dict[str, Any], mutations) -> Dict[str, Any]:
    result = copy.deepcopy(payload or {})
    for mutation in mutations or []:
        result = mutate_request(
            result,
            mutation.get("position"),
            mutation.get("name"),
            mutation.get("value"),
        )
    return result
