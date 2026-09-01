"""Bounded subprocess runtime for administrator-trusted auth code.

This module is executed with ``python -I`` and communicates only through one
JSON document on stdin/stdout.  It is a defense-in-depth guardrail for a
personal deployment, not an isolation boundary for hostile Python.
"""
from __future__ import annotations

import ast
import base64
import datetime
import hashlib
import hmac
import json
import math
import re
import sys
import time
import uuid
from typing import Any, Dict
from urllib.parse import urlsplit

import requests as _real_requests


_SAFE_MODULES = {
    "base64": base64,
    "datetime": datetime,
    "hashlib": hashlib,
    "hmac": hmac,
    "json": json,
    "math": math,
    "re": re,
    "time": time,
    "uuid": uuid,
}
_BLOCKED_CALLS = {
    "__import__", "breakpoint", "compile", "eval", "exec", "globals",
    "input", "locals", "open", "vars",
}
_BLOCKED_HEADERS = {
    "connection", "content-length", "host", "proxy-authorization",
    "transfer-encoding", "upgrade",
}
_MAX_RESPONSE_BYTES = 1024 * 1024


def _origin(value: str) -> str:
    parsed = urlsplit(str(value or "").strip())
    scheme = str(parsed.scheme or "").lower()
    host = str(parsed.hostname or "").lower().rstrip(".")
    if scheme not in {"http", "https"} or not host or parsed.username or parsed.password:
        return ""
    try:
        port = parsed.port
    except ValueError:
        return ""
    default_port = 443 if scheme == "https" else 80
    suffix = ":{}".format(port) if port and port != default_port else ""
    return "{}://{}{}".format(scheme, host, suffix)


def _validate_source(source: str) -> None:
    tree = ast.parse(source, filename="<trusted_auth_code>", mode="exec")
    has_get_auth = False
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            has_get_auth = has_get_auth or node.name == "get_auth"
        if isinstance(node, ast.Import):
            if any(alias.name not in {*_SAFE_MODULES, "requests"} for alias in node.names):
                raise ValueError("unsupported import")
        if isinstance(node, ast.ImportFrom):
            if str(node.module or "") not in {*_SAFE_MODULES, "requests"}:
                raise ValueError("unsupported import")
        if isinstance(node, ast.Name) and (
                node.id.startswith("__") or node.id in _BLOCKED_CALLS):
            raise ValueError("blocked name")
        if isinstance(node, ast.Attribute) and str(node.attr or "").startswith("__"):
            raise ValueError("blocked attribute")
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            if node.func.id in _BLOCKED_CALLS:
                raise ValueError("blocked call")
    if not has_get_auth:
        raise ValueError("missing get_auth")


class _ResponseView:
    def __init__(self, response: Any):
        content = bytes(response.content or b"")
        if len(content) > _MAX_RESPONSE_BYTES:
            raise ValueError("response too large")
        self.status_code = int(response.status_code)
        self.headers = {
            str(key): str(value) for key, value in response.headers.items()
        }
        self.cookies = {
            str(key): str(value) for key, value in response.cookies.items()
        }
        self.content = content
        self.text = content.decode(response.encoding or "utf-8", errors="replace")
        self.ok = 200 <= self.status_code < 400

    def json(self) -> Any:
        return json.loads(self.text)

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise RuntimeError("HTTP {}".format(self.status_code))


class _RestrictedRequests:
    def __init__(self, payload: Dict[str, Any]):
        self.allowed_origins = set(payload.get("auth_origins") or [])
        self.tls_verify = bool(payload.get("tls_verify", True))
        self.timeout = max(
            1, min(int(payload.get("request_timeout_seconds") or 10), 15),
        )
        self.max_requests = max(
            1, min(int(payload.get("max_requests") or 3), 6),
        )
        self.request_count = 0

    def request(self, method: str, url: str, **kwargs: Any) -> _ResponseView:
        method = str(method or "GET").upper()
        if method not in {"GET", "POST"}:
            raise ValueError("unsupported HTTP method")
        if _origin(url) not in self.allowed_origins:
            raise ValueError("HTTP origin is not allowed")
        self.request_count += 1
        if self.request_count > self.max_requests:
            raise ValueError("authentication request budget exceeded")
        unsupported = set(kwargs) - {
            "params", "data", "json", "headers", "cookies", "timeout",
        }
        if unsupported:
            raise ValueError("unsupported HTTP option")
        headers = dict(kwargs.get("headers") or {})
        for raw_name, raw_value in headers.items():
            name = str(raw_name).strip()
            value = str(raw_value)
            if (
                    not name or name.lower() in _BLOCKED_HEADERS
                    or "\r" in value or "\n" in value):
                raise ValueError("unsafe HTTP header")
        request_kwargs = {
            key: value for key, value in kwargs.items()
            if key in {"params", "data", "json", "headers", "cookies"}
        }
        request_kwargs.update({
            "timeout": self.timeout,
            "verify": self.tls_verify,
            "allow_redirects": False,
        })
        response = _real_requests.request(method, str(url), **request_kwargs)
        return _ResponseView(response)

    def get(self, url: str, **kwargs: Any) -> _ResponseView:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs: Any) -> _ResponseView:
        return self.request("POST", url, **kwargs)


def _execute(payload: Dict[str, Any]) -> Any:
    source = str(payload.get("code") or "")
    _validate_source(source)
    restricted_requests = _RestrictedRequests(payload)

    def safe_import(name: str, globals=None, locals=None, fromlist=(), level=0):
        if level:
            raise ImportError("relative imports are unavailable")
        if name == "requests":
            return restricted_requests
        module = _SAFE_MODULES.get(name)
        if module is None:
            raise ImportError("module is unavailable")
        return module

    safe_builtins = {
        "__import__": safe_import,
        "True": True,
        "False": False,
        "None": None,
        "Exception": Exception,
        "KeyError": KeyError,
        "RuntimeError": RuntimeError,
        "TypeError": TypeError,
        "ValueError": ValueError,
        "abs": abs,
        "all": all,
        "any": any,
        "bool": bool,
        "bytearray": bytearray,
        "bytes": bytes,
        "chr": chr,
        "dict": dict,
        "enumerate": enumerate,
        "filter": filter,
        "float": float,
        "int": int,
        "isinstance": isinstance,
        "len": len,
        "list": list,
        "map": map,
        "max": max,
        "min": min,
        "ord": ord,
        "range": range,
        "reversed": reversed,
        "round": round,
        "set": set,
        "sorted": sorted,
        "str": str,
        "sum": sum,
        "tuple": tuple,
        "zip": zip,
    }
    namespace: Dict[str, Any] = {
        "__builtins__": safe_builtins,
        "requests": restricted_requests,
    }
    exec(compile(source, "<trusted_auth_code>", "exec"), namespace)  # nosec B102
    get_auth = namespace.get("get_auth")
    if not callable(get_auth):
        raise ValueError("missing get_auth")
    return get_auth(
        str(payload.get("username") or ""),
        str(payload.get("password") or ""),
    )


def main() -> int:
    try:
        raw = sys.stdin.read(1024 * 1024)
        payload = json.loads(raw)
        if not isinstance(payload, dict):
            raise ValueError("invalid payload")
        result = _execute(payload)
        if not isinstance(result, dict):
            raise TypeError("result must be a dict")
        output = json.dumps(
            {"ok": True, "result": result},
            ensure_ascii=False,
            separators=(",", ":"),
        )
        if len(output.encode("utf-8")) > _MAX_RESPONSE_BYTES:
            raise ValueError("result too large")
        sys.stdout.write(output)
        return 0
    except Exception as exc:
        sys.stdout.write(json.dumps({
            "ok": False,
            "error_type": type(exc).__name__,
        }, separators=(",", ":")))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
