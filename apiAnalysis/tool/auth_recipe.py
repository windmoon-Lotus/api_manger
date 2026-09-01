"""Restricted declarative authentication recipe runtime.

The runtime accepts data-only recipes and returns short-lived credential
material to the existing AccountContext provider.  It never persists request
or response values and exceptions contain only structural diagnostics.
"""
from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import re
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, MutableMapping, Optional, Sequence
from urllib.parse import urljoin, urlsplit

import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asymmetric_padding
from cryptography.hazmat.primitives.asymmetric import rsa

from apiAnalysis.tool.account_context import AccountContextUnavailable, utcnow
from apiAnalysis.tool.mfa_receiver import (
    MfaPushBroker,
    MfaReceiverError,
    MfaReceiverTimeout,
    default_mfa_push_broker,
    normalize_receiver_id,
    validate_mfa_code,
)


RECIPE_SCHEMA_VERSION = 1
MAX_RECIPE_STEPS = 12
MAX_AUTH_REQUESTS = 6
DEFAULT_TIMEOUT_SECONDS = 10
SET_OPERATIONS = {
    "literal", "unix_time", "uuid4", "concat", "md5", "sha256",
    "base64", "rsa_encrypt",
}
_TEMPLATE = re.compile(r"{{\s*([A-Za-z0-9_.-]+)\s*}}")
_FORBIDDEN_REQUEST_HEADERS = {
    "connection", "content-length", "host", "proxy-authorization",
    "transfer-encoding", "upgrade",
}

AUTH_FAILURE_CODES = {
    "CONFIG_INVALID",
    "AUTH_HOST_UNREACHABLE",
    "CREDENTIAL_REJECTED",
    "MFA_OR_INTERACTION_REQUIRED",
    "LOGIN_PROTOCOL_CHANGED",
    "TOKEN_EXTRACTION_FAILED",
    "SESSION_ESTABLISH_FAILED",
    "IDENTITY_VERIFY_FAILED",
    "BUSINESS_AUDIENCE_MISMATCH",
    "RATE_LIMITED",
    "ADAPTER_RUNTIME_ERROR",
}


class AuthRecipeFailure(AccountContextUnavailable):
    """Safe structured failure whose message contains no response content."""

    def __init__(self, code: str, stage: str, *, request_count: int = 0,
                 diagnostics: Optional[Sequence[Mapping[str, Any]]] = None):
        self.code = code if code in AUTH_FAILURE_CODES else "ADAPTER_RUNTIME_ERROR"
        self.stage = str(stage or "runtime")[:80]
        self.request_count = max(0, int(request_count))
        self.diagnostics = [dict(item) for item in (diagnostics or [])][-12:]
        super().__init__("{} at {}".format(self.code, self.stage))


@dataclass(frozen=True, repr=False)
class RecipeExecutionResult:
    headers: Mapping[str, str] = field(default_factory=dict, repr=False)
    cookies: Mapping[str, str] = field(default_factory=dict, repr=False)
    auth_kind: str = "mixed"
    expires_at: Optional[dt.datetime] = None
    request_count: int = 0
    diagnostics: Sequence[Mapping[str, Any]] = field(default_factory=tuple)
    business_identity: Mapping[str, str] = field(default_factory=dict, repr=False)

    def __repr__(self) -> str:
        return "RecipeExecutionResult(auth_kind={!r}, header_names={!r}, cookie_names={!r}, request_count={!r})".format(
            self.auth_kind, sorted(self.headers), sorted(self.cookies), self.request_count,
        )


def canonical_json_sha256(value: Any) -> str:
    encoded = json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def normalize_origin(value: str, *, default_scheme: str = "https") -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    parsed = urlsplit(text if "://" in text else "{}://{}".format(default_scheme, text))
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


def origin_host(value: str) -> str:
    origin = normalize_origin(value)
    return str(urlsplit(origin).hostname or "") if origin else ""


def validate_recipe(recipe: Mapping[str, Any]) -> None:
    if not isinstance(recipe, Mapping) or int(recipe.get("schema_version") or 0) != RECIPE_SCHEMA_VERSION:
        raise ValueError("unsupported authentication recipe schema")
    steps = recipe.get("steps")
    if not isinstance(steps, list) or not steps or len(steps) > MAX_RECIPE_STEPS:
        raise ValueError("authentication recipe requires a bounded step list")
    names = set()
    for index, step in enumerate(steps):
        if not isinstance(step, Mapping):
            raise ValueError("authentication recipe step is invalid")
        step_type = str(step.get("type") or "")
        if step_type not in {"set", "http", "mfa_receive"}:
            raise ValueError("unsupported authentication recipe step")
        name = str(step.get("id") or "step-{}".format(index + 1))
        if name in names:
            raise ValueError("authentication recipe step id is duplicated")
        names.add(name)
        if step_type == "set" and str(step.get("operation") or "literal") not in SET_OPERATIONS:
            raise ValueError("unsupported authentication recipe set operation")
        if step_type in {"http", "mfa_receive"}:
            method = str(step.get("method") or "POST").upper()
            if method not in {"GET", "POST"}:
                raise ValueError("authentication recipe HTTP method is unsupported")
        if step_type == "mfa_receive":
            mode = str(step.get("mode") or "pull").lower()
            if mode not in {"pull", "push"}:
                raise ValueError("unsupported MFA receiver mode")
            if mode == "pull" and not str(step.get("url") or "").strip():
                raise ValueError("pull MFA receiver requires a URL")
            if mode == "push":
                normalize_receiver_id(str(step.get("receiver_id") or ""))
    output = recipe.get("output")
    if not isinstance(output, Mapping):
        raise ValueError("authentication recipe output is required")


def _lookup(context: Mapping[str, Any], path: str) -> Any:
    value: Any = context
    for part in str(path or "").split("."):
        if not part or not isinstance(value, Mapping) or part not in value:
            raise KeyError(path)
        value = value[part]
    return value


def _render(value: Any, context: Mapping[str, Any]) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _render(item, context) for key, item in value.items()}
    if isinstance(value, list):
        return [_render(item, context) for item in value]
    if not isinstance(value, str):
        return value
    full = _TEMPLATE.fullmatch(value)
    if full:
        return _lookup(context, full.group(1))

    def replace(match: re.Match) -> str:
        return str(_lookup(context, match.group(1)))

    return _TEMPLATE.sub(replace, value)


def _json_path(value: Any, path: str) -> Any:
    current = value
    for part in str(path or "").split("."):
        if not part:
            continue
        if isinstance(current, list) and part.isdigit():
            current = current[int(part)]
        elif isinstance(current, Mapping):
            current = current[part]
        else:
            raise KeyError(path)
    return current


def _json_match_value(value: Any, rule: Mapping[str, Any]) -> Any:
    """Extract one value from a bounded JSON list selected by an exact field."""
    match_path = str(rule.get("match_path") or "").strip()
    if not match_path:
        return _json_path(value, str(rule.get("path") or "code"))
    list_path = str(rule.get("list_path") or "").strip()
    rows = _json_path(value, list_path) if list_path else value
    if not isinstance(rows, list):
        raise KeyError("list_path")
    expected = str(rule.get("match_value") or "")
    value_path = str(rule.get("path") or "code")
    for item in rows[:100]:
        try:
            if str(_json_path(item, match_path)) == expected:
                return _json_path(item, value_path)
        except (KeyError, IndexError, TypeError):
            continue
    raise KeyError("match_value")


def _safe_headers(values: Any) -> Dict[str, str]:
    if not isinstance(values, Mapping):
        raise ValueError("recipe headers must be an object")
    result: Dict[str, str] = {}
    for raw_name, raw_value in values.items():
        name = str(raw_name).strip()
        value = str(raw_value)
        if not name or name.lower() in _FORBIDDEN_REQUEST_HEADERS or "\r" in value or "\n" in value:
            raise ValueError("recipe contains an unsafe request header")
        result[name] = value
    return result


def _status_failure_code(status_code: int, step: Mapping[str, Any]) -> str:
    explicit = (step.get("error_status_map") or {}).get(str(status_code))
    if explicit in AUTH_FAILURE_CODES:
        return explicit
    if status_code in {401, 403}:
        return "CREDENTIAL_REJECTED"
    if status_code in {404, 405, 410, 421}:
        return "LOGIN_PROTOCOL_CHANGED"
    if status_code == 429:
        return "RATE_LIMITED"
    return "SESSION_ESTABLISH_FAILED"


def _json_failure_code(response: Any, step: Mapping[str, Any]) -> str:
    path = str(step.get("json_error_path") or "")
    if not path:
        return ""
    try:
        value = _json_path(response.json(), path)
    except (KeyError, IndexError, TypeError, ValueError, json.JSONDecodeError):
        return ""
    if value in (None, "", False, 0, [], {}):
        return ""
    mapping = step.get("json_error_code_map") or {}
    code = mapping.get(str(value)) or step.get("json_error_default") or ""
    return str(code) if str(code) in AUTH_FAILURE_CODES else ""


def _load_rsa_public_key(value: Any) -> rsa.RSAPublicKey:
    encoded = str(value or "").strip().encode("utf-8")
    if not encoded or len(encoded) > 32768:
        raise ValueError("RSA public key is invalid")
    try:
        if b"BEGIN CERTIFICATE" in encoded:
            key = x509.load_pem_x509_certificate(encoded).public_key()
        else:
            key = serialization.load_pem_public_key(encoded)
    except (TypeError, ValueError):
        raise ValueError("RSA public key is invalid") from None
    if not isinstance(key, rsa.RSAPublicKey) or key.key_size < 2048:
        raise ValueError("RSA public key must be at least 2048 bits")
    return key


def _rsa_encrypt(step: Mapping[str, Any], context: Mapping[str, Any]) -> str:
    value = str(_render(step.get("value", ""), context)).encode("utf-8")
    public_key = _load_rsa_public_key(
        _render(step.get("public_key") or step.get("key") or "", context),
    )
    padding_name = str(step.get("padding") or "pkcs1v15").strip().lower()
    if padding_name == "pkcs1v15":
        selected_padding: Any = asymmetric_padding.PKCS1v15()
    elif padding_name in {"oaep-sha1", "oaep_sha1"}:
        selected_padding = asymmetric_padding.OAEP(
            mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None,
        )
    elif padding_name in {"oaep-sha256", "oaep_sha256", "oaep"}:
        selected_padding = asymmetric_padding.OAEP(
            mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        )
    else:
        raise ValueError("unsupported RSA padding")
    try:
        encrypted = public_key.encrypt(value, selected_padding)
    except ValueError:
        raise ValueError("RSA plaintext is too large for the selected key") from None
    output_encoding = str(step.get("output_encoding") or "base64").lower()
    if output_encoding == "base64":
        return base64.b64encode(encrypted).decode("ascii")
    if output_encoding == "hex":
        return encrypted.hex()
    raise ValueError("unsupported RSA output encoding")


def _set_value(step: Mapping[str, Any], context: Mapping[str, Any]) -> Any:
    operation = str(step.get("operation") or "literal")
    if operation == "literal":
        return _render(step.get("value"), context)
    if operation == "unix_time":
        unit = str(step.get("unit") or "seconds").lower()
        if unit in {"seconds", "second", "s"}:
            return int(time.time())
        if unit in {"milliseconds", "millisecond", "ms"}:
            return int(time.time() * 1000)
        raise ValueError("unsupported unix timestamp unit")
    if operation == "uuid4":
        return str(uuid.uuid4())
    rendered = _render(step.get("value", ""), context)
    if operation == "concat":
        values = _render(step.get("values") or [], context)
        return "".join(str(item) for item in values)
    raw = str(rendered).encode("utf-8")
    if operation == "md5":
        return hashlib.md5(raw).hexdigest()  # nosec - protocol compatibility operation
    if operation == "sha256":
        return hashlib.sha256(raw).hexdigest()
    if operation == "base64":
        return base64.b64encode(raw).decode("ascii")
    if operation == "rsa_encrypt":
        return _rsa_encrypt(step, context)
    raise ValueError("unsupported recipe set operation")


class AuthRecipeExecutor:
    """Execute one validated recipe with exact-origin network confinement."""

    def __init__(self, *, session: Optional[requests.Session] = None,
                 timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
                 max_requests: int = MAX_AUTH_REQUESTS,
                 mfa_push_broker: Optional[MfaPushBroker] = None):
        self.session = session or requests.Session()
        self.timeout_seconds = max(1, min(int(timeout_seconds), 30))
        self.max_requests = max(1, min(int(max_requests), MAX_AUTH_REQUESTS))
        self.mfa_push_broker = mfa_push_broker or default_mfa_push_broker()

    def _receive_mfa(
            self, step: Mapping[str, Any], context: Mapping[str, Any], *,
            allowed_origins: Sequence[str], tls_verify: bool,
            request_count: int, diagnostics: List[Dict[str, Any]],
    ) -> tuple[str, int]:
        stage = str(step.get("id") or "mfa_receive")[:80]
        mode = str(step.get("mode") or "pull").lower()
        if mode == "push":
            receiver_id = normalize_receiver_id(str(step.get("receiver_id") or ""))
            correlation = str(_render(step.get("correlation") or "", context))[:256]
            timeout_seconds = max(
                1, min(int(step.get("timeout_seconds") or 60), 300),
            )
            try:
                code = self.mfa_push_broker.wait(
                    receiver_id,
                    correlation=correlation,
                    timeout_seconds=timeout_seconds,
                )
            except MfaReceiverTimeout:
                raise AuthRecipeFailure(
                    "MFA_OR_INTERACTION_REQUIRED", stage,
                    request_count=request_count,
                    diagnostics=diagnostics + [{
                        "stage": stage, "kind": "mfa_receive", "mode": "push",
                        "receiver_id": receiver_id, "status": "timeout",
                    }],
                ) from None
            except MfaReceiverError:
                raise AuthRecipeFailure(
                    "MFA_OR_INTERACTION_REQUIRED", stage,
                    request_count=request_count,
                    diagnostics=diagnostics + [{
                        "stage": stage, "kind": "mfa_receive", "mode": "push",
                        "receiver_id": receiver_id, "status": "unavailable",
                    }],
                ) from None
            diagnostics.append({
                "stage": stage, "kind": "mfa_receive", "mode": "push",
                "receiver_id": receiver_id, "status": "received",
            })
            return code, request_count

        url = str(_render(step.get("url") or "", context))
        origin = normalize_origin(url)
        if not origin or origin not in set(allowed_origins):
            raise AuthRecipeFailure(
                "CONFIG_INVALID", stage, request_count=request_count,
                diagnostics=diagnostics + [{
                    "stage": stage, "kind": "mfa_receive", "mode": "pull",
                    "status": "origin_blocked",
                }],
            )
        method = str(step.get("method") or "POST").upper()
        headers = _safe_headers(_render(step.get("headers") or {}, context))
        timeout_seconds = max(
            1, min(int(step.get("timeout_seconds") or self.timeout_seconds), 30),
        )
        max_attempts = max(1, min(int(step.get("max_attempts") or 1), 6))
        poll_interval = max(
            0.0, min(float(step.get("poll_interval_seconds") or 0), 10.0),
        )
        accepted = {
            int(item) for item in (step.get("success_statuses") or [200])
        }
        not_ready = {
            int(item) for item in (step.get("not_ready_statuses") or [202])
        }
        rule = step.get("extract") or {"source": "json", "path": "code"}
        if not isinstance(rule, Mapping):
            raise ValueError("MFA receiver extract rule is invalid")

        for attempt in range(1, max_attempts + 1):
            if request_count >= self.max_requests:
                raise AuthRecipeFailure(
                    "CONFIG_INVALID", stage, request_count=request_count,
                    diagnostics=diagnostics,
                )
            kwargs: Dict[str, Any] = {
                "headers": headers,
                "timeout": timeout_seconds,
                "verify": bool(tls_verify),
                "allow_redirects": False,
            }
            if "json" in step:
                kwargs["json"] = _render(step.get("json"), context)
            if "form" in step:
                kwargs["data"] = _render(step.get("form"), context)
            if "query" in step:
                kwargs["params"] = _render(step.get("query"), context)
            request_count += 1
            response = self.session.request(method, url, **kwargs)
            diagnostics.append({
                "stage": stage, "kind": "mfa_receive", "mode": "pull",
                "method": method, "origin": origin,
                "path": str(urlsplit(url).path or "/")[:240],
                "status_code": int(response.status_code),
                "attempt": attempt, "status": "received",
                "tls_verify": bool(tls_verify),
            })
            status_code = int(response.status_code)
            if status_code not in accepted and status_code not in not_ready:
                raise AuthRecipeFailure(
                    _status_failure_code(status_code, step), stage,
                    request_count=request_count, diagnostics=diagnostics,
                )
            if status_code in accepted:
                source = str(rule.get("source") or "json")
                try:
                    if source == "json":
                        value = _json_match_value(response.json(), rule)
                    elif source == "header":
                        value = response.headers[str(rule.get("name") or "X-MFA-Code")]
                    elif source == "cookie":
                        value = self.session.cookies[str(rule.get("name") or "mfa_code")]
                    elif source == "text":
                        value = response.text
                    else:
                        raise KeyError("source")
                    return validate_mfa_code(value), request_count
                except (KeyError, IndexError, TypeError, ValueError, json.JSONDecodeError):
                    pass
            if attempt < max_attempts and poll_interval:
                time.sleep(poll_interval)

        raise AuthRecipeFailure(
            "MFA_OR_INTERACTION_REQUIRED", stage,
            request_count=request_count,
            diagnostics=diagnostics,
        )

    def execute(self, recipe: Mapping[str, Any], credentials: Mapping[str, Any], *,
                 realm_auth_origins: Iterable[str], adapter_auth_origins: Iterable[str],
                 realm_config: Optional[Mapping[str, Any]] = None,
                 realm_secrets: Optional[Mapping[str, Any]] = None,
                 tls_verify: bool = True) -> RecipeExecutionResult:
        try:
            validate_recipe(recipe)
        except (TypeError, ValueError) as exc:
            raise AuthRecipeFailure("CONFIG_INVALID", "recipe_validation") from None
        realm_origins = {normalize_origin(item) for item in realm_auth_origins}
        adapter_origins = {normalize_origin(item) for item in adapter_auth_origins}
        realm_origins.discard("")
        adapter_origins.discard("")
        allowed_origins = realm_origins & adapter_origins
        if not realm_origins or not adapter_origins or not allowed_origins:
            raise AuthRecipeFailure("CONFIG_INVALID", "origin_policy")

        variables: MutableMapping[str, Any] = {}
        context: Dict[str, Any] = {
            "credential": dict(credentials or {}),
            "config": dict(realm_config or {}),
            "secret": dict(realm_secrets or {}),
            "vars": variables,
        }
        diagnostics: List[Dict[str, Any]] = []
        request_count = 0

        for index, step in enumerate(recipe.get("steps") or []):
            stage = str(step.get("id") or "step-{}".format(index + 1))[:80]
            try:
                if step.get("type") == "set":
                    target = str(step.get("target") or stage)
                    variables[target] = _set_value(step, context)
                    diagnostics.append({"stage": stage, "kind": "set", "status": "ok"})
                    continue

                if step.get("type") == "mfa_receive":
                    target = str(step.get("target") or "mfa_code")
                    variables[target], request_count = self._receive_mfa(
                        step,
                        context,
                        allowed_origins=tuple(allowed_origins),
                        tls_verify=bool(tls_verify),
                        request_count=request_count,
                        diagnostics=diagnostics,
                    )
                    continue

                url = str(_render(step.get("url") or "", context))
                origin = normalize_origin(url)
                if not origin or origin not in allowed_origins:
                    raise AuthRecipeFailure(
                        "CONFIG_INVALID", stage, request_count=request_count,
                        diagnostics=diagnostics + [{"stage": stage, "kind": "http", "status": "origin_blocked"}],
                    )
                method = str(step.get("method") or "POST").upper()
                headers = _safe_headers(_render(step.get("headers") or {}, context))
                kwargs: Dict[str, Any] = {
                    "headers": headers,
                    "timeout": max(1, min(int(step.get("timeout_seconds") or self.timeout_seconds), 30)),
                    "verify": bool(tls_verify),
                    "allow_redirects": False,
                }
                if "json" in step:
                    kwargs["json"] = _render(step.get("json"), context)
                if "form" in step:
                    kwargs["data"] = _render(step.get("form"), context)
                if "query" in step:
                    kwargs["params"] = _render(step.get("query"), context)
                request_count += 1
                if request_count > self.max_requests:
                    raise AuthRecipeFailure(
                        "CONFIG_INVALID", stage, request_count=request_count - 1,
                        diagnostics=diagnostics,
                    )
                response = self.session.request(method, url, **kwargs)
                diagnostics.append({
                    "stage": stage,
                    "kind": "http",
                    "method": method,
                    "origin": origin,
                    "path": str(urlsplit(url).path or "/")[:240],
                    "status_code": int(response.status_code),
                    "status": "received",
                    "tls_verify": bool(tls_verify),
                })

                redirects = 0
                while response.is_redirect and step.get("follow_redirects"):
                    redirects += 1
                    if redirects > max(0, min(int(step.get("max_redirects") or 3), 5)):
                        raise AuthRecipeFailure(
                            "LOGIN_PROTOCOL_CHANGED", stage, request_count=request_count,
                            diagnostics=diagnostics,
                        )
                    target_url = urljoin(response.url or url, response.headers.get("Location") or "")
                    target_origin = normalize_origin(target_url)
                    if target_origin not in allowed_origins:
                        raise AuthRecipeFailure(
                            "CONFIG_INVALID", stage, request_count=request_count,
                            diagnostics=diagnostics,
                        )
                    request_count += 1
                    if request_count > self.max_requests:
                        raise AuthRecipeFailure(
                            "CONFIG_INVALID", stage, request_count=request_count - 1,
                            diagnostics=diagnostics,
                        )
                    response = self.session.request(
                        "GET", target_url, headers=headers, timeout=kwargs["timeout"],
                        verify=bool(tls_verify), allow_redirects=False,
                    )
                    diagnostics.append({
                        "stage": stage, "kind": "redirect", "method": "GET",
                        "origin": target_origin,
                        "path": str(urlsplit(target_url).path or "/")[:240],
                        "status_code": int(response.status_code), "status": "received",
                        "tls_verify": bool(tls_verify),
                    })

                body_failure = _json_failure_code(response, step)
                if body_failure:
                    raise AuthRecipeFailure(
                        body_failure, stage, request_count=request_count,
                        diagnostics=diagnostics,
                    )
                accepted = step.get("success_statuses") or list(range(200, 300))
                if int(response.status_code) not in {int(item) for item in accepted}:
                    raise AuthRecipeFailure(
                        _status_failure_code(int(response.status_code), step), stage,
                        request_count=request_count, diagnostics=diagnostics,
                    )

                extract = step.get("extract") or {}
                parsed_json: Any = None
                for target, rule_value in extract.items():
                    rule = rule_value if isinstance(rule_value, Mapping) else {
                        "source": "json", "path": str(rule_value), "required": True,
                    }
                    source = str(rule.get("source") or "json")
                    required = bool(rule.get("required", True))
                    try:
                        if source == "json":
                            if parsed_json is None:
                                parsed_json = response.json()
                            extracted = _json_path(parsed_json, str(rule.get("path") or target))
                        elif source == "header":
                            extracted = response.headers[str(rule.get("name") or target)]
                        elif source == "cookie":
                            extracted = self.session.cookies[str(rule.get("name") or target)]
                        elif source == "status":
                            extracted = int(response.status_code)
                        elif source == "url":
                            extracted = str(response.url or url)
                        else:
                            raise KeyError(target)
                    except (KeyError, IndexError, TypeError, ValueError, json.JSONDecodeError):
                        if required:
                            raise AuthRecipeFailure(
                                str(rule.get("failure_code") or "TOKEN_EXTRACTION_FAILED"), stage,
                                request_count=request_count, diagnostics=diagnostics,
                            ) from None
                        continue
                    variables[str(target)] = extracted
            except AuthRecipeFailure:
                raise
            except requests.exceptions.SSLError:
                raise AuthRecipeFailure(
                    "AUTH_HOST_UNREACHABLE", stage, request_count=request_count,
                    diagnostics=diagnostics,
                ) from None
            except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
                raise AuthRecipeFailure(
                    "AUTH_HOST_UNREACHABLE", stage, request_count=request_count,
                    diagnostics=diagnostics,
                ) from None
            except (KeyError, TypeError, ValueError):
                raise AuthRecipeFailure(
                    "CONFIG_INVALID", stage, request_count=request_count,
                    diagnostics=diagnostics,
                ) from None
            except requests.RequestException:
                raise AuthRecipeFailure(
                    "ADAPTER_RUNTIME_ERROR", stage, request_count=request_count,
                    diagnostics=diagnostics,
                ) from None

        try:
            output = recipe.get("output") or {}
            auth_kind = str(output.get("auth_kind") or "mixed").lower()
            if auth_kind not in {"bearer", "cookie", "mixed"}:
                raise ValueError("invalid auth kind")
            headers = _safe_headers(_render(output.get("headers") or {}, context))
            cookies = {
                str(name): str(value)
                for name, value in _render(output.get("cookies") or {}, context).items()
            }
            if bool(output.get("include_session_cookies", auth_kind in {"cookie", "mixed"})):
                cookies.update({str(cookie.name): str(cookie.value) for cookie in self.session.cookies})
            if auth_kind == "bearer" and not headers:
                raise KeyError("headers")
            if auth_kind == "cookie" and not cookies:
                raise KeyError("cookies")
            if auth_kind == "mixed" and not headers and not cookies:
                raise KeyError("credentials")
            expires_at = None
            if output.get("expires_in_seconds") not in (None, ""):
                seconds = int(_render(output.get("expires_in_seconds"), context))
                expires_at = utcnow() + dt.timedelta(seconds=max(30, min(seconds, 86400)))
        except (KeyError, TypeError, ValueError):
            raise AuthRecipeFailure(
                "TOKEN_EXTRACTION_FAILED", "output", request_count=request_count,
                diagnostics=diagnostics,
            ) from None
        identity_names = {
            "uid", "userid", "user_id", "entid", "ent_id",
            "enterprise_id", "tenant_id",
        }
        business_identity = {
            str(name): str(value)[:256]
            for name, value in variables.items()
            if str(name) in identity_names
            and isinstance(value, (str, int))
            and str(value).strip()
        }
        return RecipeExecutionResult(
            headers=headers,
            cookies=cookies,
            auth_kind=auth_kind,
            expires_at=expires_at,
            request_count=request_count,
            diagnostics=tuple(diagnostics),
            business_identity=business_identity,
        )
