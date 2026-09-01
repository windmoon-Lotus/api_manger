import hashlib
import json
import re
from urllib.parse import urlparse

from apiAnalysis.tool.tool import body_parse, flatten_json


ROUTE_QUERY_KEYS = {
    "a",
    "act",
    "action",
    "api",
    "c",
    "controller",
    "m",
    "method",
    "module",
    "op",
    "route",
    "s",
    "service",
}

IGNORED_QUERY_KEYS = {
    "_",
    "_t",
    "callback",
    "cb",
    "csrf",
    "limit",
    "nonce",
    "page",
    "page_no",
    "page_size",
    "per_page",
    "r",
    "rand",
    "random",
    "sign",
    "signature",
    "size",
    "sort",
    "timestamp",
    "token",
    "ts",
}

GENERIC_ROUTE_PATHS = {
    "/api.php",
    "/gateway",
    "/index.php",
    "/router",
}


def host_scope(host):
    host = (host or "").split(":")[0].lower().strip(".")
    if not host or host == "localhost" or re.match(r"^\d+\.\d+\.\d+\.\d+$", host):
        return host
    parts = [part for part in host.split(".") if part]
    if len(parts) <= 2:
        return host
    return ".".join(parts[-2:])


def _query_items(query):
    for key, value in sorted((query or {}).items(), key=lambda item: str(item[0])):
        if isinstance(value, list):
            values = value
        else:
            values = [value]
        yield str(key), ["" if item is None else str(item) for item in values]


def _is_route_like_value(value):
    value = str(value or "")
    if "/" in value or "." in value or "::" in value:
        return True
    return bool(re.match(r"^[A-Za-z_][A-Za-z0-9_]*(/[A-Za-z0-9_]+)+$", value))


def route_query_signature(path, query):
    route = {}
    generic_path = (path or "").lower() in GENERIC_ROUTE_PATHS or (path or "").lower().endswith(".php")
    for key, values in _query_items(query):
        lower_key = key.lower()
        if lower_key in ROUTE_QUERY_KEYS:
            route[key] = values
        elif lower_key == "r" and generic_path and any(_is_route_like_value(value) for value in values):
            route[key] = values
    return route


def query_key_signature(query):
    keys = []
    for key, values in _query_items(query):
        lower_key = key.lower()
        if lower_key in IGNORED_QUERY_KEYS:
            continue
        keys.append(key)
    return sorted(set(keys))


def _shape_key(key):
    return ".".join("[]" if part.isdigit() else part for part in str(key).split("."))


def body_shape_signature(body):
    if body in [None, b"", ""]:
        return {"content_type": "", "keys": []}
    if isinstance(body, (dict, list)):
        parsed, content_type = body, "application/json"
    else:
        parsed, content_type = body_parse(body)
    if not content_type:
        return {"content_type": "", "keys": []}
    keys = sorted(set(_shape_key(key) for key in flatten_json(parsed).keys() if key != ""))
    return {"content_type": content_type, "keys": keys}


def normalize_signature_path(path):
    path = path or ""
    path = re.sub(r"\{[^/{}]+\}", "[PARAM]", path)
    path = re.sub(r":[^/]+", "[PARAM]", path)
    path = path.replace("[NUMBER]", "[PARAM]")
    path = re.sub(r"/[0-9a-fA-F-]{8,}(?=/|$)", "/[PARAM]", path)
    path = re.sub(r"/\d+(?=/|$)", "/[PARAM]", path)
    return path


def api_signature(method, url, path, query, body, host=None, asset_kind="concrete"):
    parsed = urlparse(url or "")
    normalized_path = normalize_signature_path(path or parsed.path or "")
    asset_kind = asset_kind or "concrete"
    scope = "abstract" if asset_kind == "abstract" else host_scope(host or parsed.netloc)
    payload = {
        "asset_kind": asset_kind,
        "scope": scope,
        "method": (method or "GET").upper(),
        "path": normalized_path,
        "route_query": route_query_signature(normalized_path, query),
        "query_keys": query_key_signature(query),
        "body_shape": body_shape_signature(body),
    }
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def abstract_signature(method, path, query=None, body=None):
    parsed_path = normalize_signature_path(path or "")
    payload = {
        "method": (method or "GET").upper(),
        "path": parsed_path,
        "route_query": route_query_signature(parsed_path, query or {}),
        "query_keys": query_key_signature(query or {}),
        "body_shape": body_shape_signature(body),
    }
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def api_signature_object_id(method, url, path, query, body, host=None, asset_kind="concrete", identity_scope=""):
    material = api_signature(method, url, path, query, body, host=host, asset_kind=asset_kind)
    if identity_scope:
        material += "|identity_scope=" + str(identity_scope)
    digest = hashlib.md5(material.encode("utf-8")).hexdigest()
    return digest[:24]
