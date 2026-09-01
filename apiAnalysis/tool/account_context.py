"""Secret-free references and short-lived in-memory authentication contexts.

Only references and sanitized health metadata may be persisted by callers.
Credential values live in :class:`AccountContext` instances and must never be
serialized, logged, or included in exception messages.
"""
import ast
import base64
import datetime as dt
import json
import os
import re
import subprocess
import sys
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, Mapping, Optional, Sequence, Tuple
from urllib.parse import urlsplit


_HEADER_NAME = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
_DANGEROUS_PROVIDER_HEADERS = {
    "accept-encoding",
    "connection",
    "content-length",
    "content-type",
    "host",
    "transfer-encoding",
    "upgrade",
}
_READY_STATUSES = {"", "active", "ok", "ready", "success", "valid"}


class AccountContextError(RuntimeError):
    """Base class whose messages must remain safe to persist."""


class AccountContextUnavailable(AccountContextError):
    pass


class AccountContextInvalid(AccountContextError):
    pass


class AccountContextExpired(AccountContextError):
    pass


class AccountContextMismatch(AccountContextError):
    pass


class AccountContextHostNotAllowed(AccountContextError):
    pass


def utcnow() -> dt.datetime:
    return dt.datetime.utcnow()


def _utc_naive(value: Any) -> Optional[dt.datetime]:
    if value in (None, ""):
        return None
    if isinstance(value, dt.datetime):
        parsed = value
    elif isinstance(value, (int, float)):
        parsed = dt.datetime.fromtimestamp(float(value), tz=dt.timezone.utc)
    else:
        text = str(value).strip()
        try:
            if re.fullmatch(r"\d+(?:\.\d+)?", text):
                parsed = dt.datetime.fromtimestamp(float(text), tz=dt.timezone.utc)
            else:
                parsed = dt.datetime.fromisoformat(text.replace("Z", "+00:00"))
        except (ValueError, OverflowError, OSError) as exc:
            raise AccountContextInvalid("account context expiry is invalid") from None
    if parsed.tzinfo is not None:
        parsed = parsed.astimezone(dt.timezone.utc).replace(tzinfo=None)
    return parsed


def _split_values(value: Any) -> Tuple[str, ...]:
    if value in (None, ""):
        return ()
    if isinstance(value, str):
        values = value.split(",")
    elif isinstance(value, (list, tuple, set)):
        values = value
    else:
        raise AccountContextInvalid("account context host scope is invalid")
    return tuple(sorted({str(item).strip().lower().rstrip(".") for item in values if str(item).strip()}))


def _validate_host_patterns(patterns: Sequence[str]) -> Tuple[str, ...]:
    normalized = _split_values(patterns)
    if not normalized:
        raise AccountContextInvalid("account context requires an explicit host scope")
    for pattern in normalized:
        candidate = pattern[2:] if pattern.startswith("*.") else pattern
        if pattern == "*" or not candidate or "/" in candidate or "://" in candidate:
            raise AccountContextInvalid("account context host scope is invalid")
    return normalized


def _host_matches(host: str, patterns: Sequence[str]) -> bool:
    raw_host = str(host or "").strip()
    parsed_host = urlsplit(raw_host if "://" in raw_host else "//" + raw_host).hostname
    host = str(parsed_host or raw_host).strip().lower().rstrip(".")
    if not host:
        return True
    for pattern in patterns:
        if pattern.startswith("*."):
            suffix = pattern[1:]
            if host.endswith(suffix) and host != pattern[2:]:
                return True
        elif host == pattern:
            return True
    return False


def _validate_secret_mapping(values: Mapping[str, Any], *, headers: bool) -> Dict[str, str]:
    if not isinstance(values, Mapping):
        raise AccountContextInvalid("account context credential shape is invalid")
    result: Dict[str, str] = {}
    for raw_name, raw_value in values.items():
        name = str(raw_name).strip()
        value = str(raw_value)
        if not name or not _HEADER_NAME.fullmatch(name) or "\r" in value or "\n" in value:
            raise AccountContextInvalid("account context credential shape is invalid")
        if headers and name.lower() in _DANGEROUS_PROVIDER_HEADERS:
            raise AccountContextInvalid("account context contains a forbidden transport header")
        result[name] = value
    return result


@dataclass(frozen=True)
class AccountContextRef:
    project_id: str
    env_id: str
    account_id: str
    provider_id: str
    context_ref: str = ""

    def validate(self) -> None:
        if not all((self.project_id, self.env_id, self.account_id, self.provider_id)):
            raise AccountContextInvalid(
                "project_id, env_id, account_id and provider_id are required for account auth"
            )

    @property
    def effective_context_ref(self) -> str:
        return self.context_ref or self.account_id

    def cache_key(self) -> Tuple[str, str, str, str, str]:
        self.validate()
        return (
            self.provider_id,
            self.project_id,
            self.env_id,
            self.account_id,
            self.effective_context_ref,
        )


@dataclass(frozen=True, repr=False)
class AccountContext:
    project_id: str
    env_id: str
    account_id: str
    provider_id: str
    context_ref: str = ""
    headers: Mapping[str, str] = field(default_factory=dict, repr=False)
    cookies: Mapping[str, str] = field(default_factory=dict, repr=False)
    auth_kind: str = "opaque"
    expires_at: Optional[dt.datetime] = None
    issued_at: Optional[dt.datetime] = None
    allowed_hosts: Sequence[str] = field(default_factory=tuple)
    metadata: Mapping[str, Any] = field(default_factory=dict, repr=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "headers", _validate_secret_mapping(self.headers, headers=True))
        object.__setattr__(self, "cookies", _validate_secret_mapping(self.cookies, headers=False))
        object.__setattr__(self, "expires_at", _utc_naive(self.expires_at))
        object.__setattr__(self, "issued_at", _utc_naive(self.issued_at))
        object.__setattr__(self, "allowed_hosts", _validate_host_patterns(self.allowed_hosts))
        object.__setattr__(self, "metadata", dict(self.metadata or {}))
        if not self.headers and not self.cookies:
            raise AccountContextInvalid("account context contains no credentials")

    def __repr__(self) -> str:
        return "AccountContext({})".format(
            ", ".join("{}={!r}".format(key, value) for key, value in self.descriptor().items())
        )

    def validate(self, reference: AccountContextRef, host: str = "",
                 min_validity_seconds: int = 0, now: Optional[dt.datetime] = None) -> "AccountContext":
        reference.validate()
        identity = (
            self.provider_id,
            self.project_id,
            self.env_id,
            self.account_id,
            self.context_ref or self.account_id,
        )
        if identity != reference.cache_key():
            raise AccountContextMismatch("account context identity does not match execution context")
        now = now or utcnow()
        if self.expires_at is not None and self.expires_at <= now + dt.timedelta(seconds=min_validity_seconds):
            raise AccountContextExpired("account context is expired or too close to expiry")
        if host and not _host_matches(host, self.allowed_hosts):
            raise AccountContextHostNotAllowed("target host is outside the account context scope")
        return self

    def descriptor(self, status: str = "ready") -> Dict[str, Any]:
        return {
            "status": status,
            "provider_id": self.provider_id,
            "project_id": self.project_id,
            "env_id": self.env_id,
            "account_id": self.account_id,
            "context_ref": self.context_ref or self.account_id,
            "auth_kind": self.auth_kind,
            "header_names": sorted(self.headers),
            "cookie_names": sorted(self.cookies),
            "allowed_hosts": list(self.allowed_hosts),
            "issued_at": self.issued_at.isoformat() + "Z" if self.issued_at else "",
            "expires_at": self.expires_at.isoformat() + "Z" if self.expires_at else "",
        }


class AccountContextProvider:
    provider_id = ""

    def resolve(self, reference: AccountContextRef) -> AccountContext:
        raise NotImplementedError


def _jwt_exp(authorization: str) -> Optional[dt.datetime]:
    try:
        token = str(authorization or "").split()[-1]
        parts = token.split(".")
        if len(parts) != 3:
            return None
        payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4)))
        return _utc_naive(payload.get("exp"))
    except Exception:
        return None


def _record_candidates(record: Mapping[str, Any], index: int) -> Tuple[str, ...]:
    candidates = {
        str(record.get(key) or "").strip()
        for key in ("account_id", "username", "name", "alias", "id", "context_ref")
    }
    candidates.update({str(index), "account[{}]".format(index)})
    return tuple(item for item in candidates if item)


def _records_from_document(document: Any) -> Sequence[Mapping[str, Any]]:
    if not isinstance(document, Mapping):
        raise AccountContextInvalid("account context file is invalid")
    accounts = document.get("accounts")
    if accounts is None:
        accounts = [document]
    if isinstance(accounts, Mapping):
        records = []
        for key, value in accounts.items():
            if not isinstance(value, Mapping):
                raise AccountContextInvalid("account context account record is invalid")
            record = dict(value)
            record.setdefault("account_id", str(key))
            records.append(record)
        return records
    if not isinstance(accounts, list) or not all(isinstance(item, Mapping) for item in accounts):
        raise AccountContextInvalid("account context account record is invalid")
    return accounts


def _record_to_context(record: Mapping[str, Any], reference: AccountContextRef, *,
                       provider_id: str, default_project_id: str = "",
                       default_env_id: str = "", default_allowed_hosts: Sequence[str] = (),
                       document: Optional[Mapping[str, Any]] = None,
                       source_mtime: Optional[dt.datetime] = None,
                       max_age_seconds: int = 1800) -> AccountContext:
    document = document or {}
    project_id = str(record.get("project_id") or document.get("project_id") or default_project_id).strip()
    env_id = str(record.get("env_id") or document.get("env_id") or default_env_id).strip()
    account_id = str(record.get("account_id") or record.get("username") or reference.account_id).strip()
    context_ref = str(record.get("context_ref") or reference.effective_context_ref).strip()
    if project_id != reference.project_id or env_id != reference.env_id:
        raise AccountContextMismatch("account context project or environment does not match")

    status = str(record.get("status") or "").strip().lower()
    if status not in _READY_STATUSES:
        raise AccountContextUnavailable("account context record is not ready")

    headers = dict(record.get("headers") or {})
    cookies = dict(record.get("cookies") or {})
    authorization = record.get("authorization") or record.get("Authorization")
    if not authorization and record.get("access_token"):
        authorization = "{} {}".format(record.get("token_type") or "Bearer", record["access_token"])
    if authorization:
        headers["Authorization"] = authorization
    if record.get("cookie"):
        headers["Cookie"] = record["cookie"]

    explicit_expiry = _utc_naive(
        record.get("expires_at") or record.get("expiresAt") or record.get("expiresHint")
    )
    jwt_expiry = _jwt_exp(str(authorization or ""))
    expiries = [value for value in (explicit_expiry, jwt_expiry) if value is not None]
    expires_at = min(expiries) if expiries else None
    issued_at = _utc_naive(record.get("issued_at") or record.get("issuedAt") or document.get("createdAt"))
    non_expiring = bool(record.get("non_expiring") or record.get("nonExpiring"))
    if expires_at is None and not non_expiring:
        base_time = issued_at or source_mtime
        if base_time is None:
            raise AccountContextInvalid("account context requires an expiry or bounded file age")
        expires_at = base_time + dt.timedelta(seconds=int(max_age_seconds))

    allowed_hosts = (
        record.get("allowed_hosts")
        or record.get("allowedHosts")
        or document.get("allowed_hosts")
        or document.get("allowedHosts")
        or default_allowed_hosts
    )
    metadata = dict(document.get("metadata") or {})
    metadata.update(dict(record.get("metadata") or {}))
    return AccountContext(
        project_id=project_id,
        env_id=env_id,
        account_id=account_id,
        provider_id=provider_id,
        context_ref=context_ref,
        headers=headers,
        cookies=cookies,
        auth_kind=str(record.get("auth_kind") or record.get("authKind") or "opaque"),
        expires_at=expires_at,
        issued_at=issued_at,
        allowed_hosts=allowed_hosts,
        metadata=metadata,
    )


class JsonFileAccountContextProvider(AccountContextProvider):
    """Load private local JSON while caching only parsed values in this process."""

    def __init__(self, path: str, provider_id: str = "local_json", *,
                 default_project_id: str = "", default_env_id: str = "",
                 allowed_hosts: Sequence[str] = (), max_age_seconds: int = 1800,
                 max_file_bytes: int = 5 * 1024 * 1024):
        self.path = Path(path).expanduser().resolve()
        parts = {part.lower() for part in self.path.parts}
        if ".secrets" not in parts and not self.path.name.lower().endswith(".private.json"):
            raise AccountContextInvalid("account context file must be private")
        self.provider_id = str(provider_id or "local_json")
        self.default_project_id = str(default_project_id or "")
        self.default_env_id = str(default_env_id or "")
        self.allowed_hosts = tuple(allowed_hosts or ())
        self.max_age_seconds = int(max_age_seconds)
        self.max_file_bytes = int(max_file_bytes)
        self._lock = threading.Lock()

    def _load(self) -> Tuple[Mapping[str, Any], dt.datetime]:
        try:
            with self._lock:
                stat = self.path.stat()
                if stat.st_size > self.max_file_bytes:
                    raise AccountContextInvalid("account context file is too large")
                document = json.loads(self.path.read_text(encoding="utf-8-sig"))
                if not isinstance(document, Mapping):
                    raise AccountContextInvalid("account context file is invalid")
                mtime = dt.datetime.utcfromtimestamp(stat.st_mtime)
                return document, mtime
        except AccountContextError:
            raise
        except (OSError, UnicodeError, json.JSONDecodeError):
            raise AccountContextUnavailable("account context file is unavailable or invalid") from None

    def resolve(self, reference: AccountContextRef) -> AccountContext:
        reference.validate()
        if reference.provider_id != self.provider_id:
            raise AccountContextMismatch("account context provider does not match")
        document, mtime = self._load()
        matched = None
        matched_index = -1
        for index, record in enumerate(_records_from_document(document)):
            candidates = _record_candidates(record, index)
            if reference.account_id not in candidates:
                continue
            if reference.context_ref and reference.context_ref not in candidates:
                continue
            matched = record
            matched_index = index
            break
        if matched is None:
            raise AccountContextUnavailable("account context account reference was not found")
        context = _record_to_context(
            matched,
            reference,
            provider_id=self.provider_id,
            default_project_id=self.default_project_id,
            default_env_id=self.default_env_id,
            default_allowed_hosts=self.allowed_hosts,
            document=document,
            source_mtime=mtime,
            max_age_seconds=self.max_age_seconds,
        )
        # Legacy username/index aliases resolve to the explicit execution id.
        if context.account_id != reference.account_id or context.context_ref != reference.effective_context_ref:
            context = AccountContext(
                project_id=context.project_id,
                env_id=context.env_id,
                account_id=reference.account_id,
                provider_id=context.provider_id,
                context_ref=reference.effective_context_ref,
                headers=context.headers,
                cookies=context.cookies,
                auth_kind=context.auth_kind,
                expires_at=context.expires_at,
                issued_at=context.issued_at,
                allowed_hosts=context.allowed_hosts,
                metadata={"record_index": matched_index},
            )
        return context.validate(reference)


class CallbackAccountContextProvider(AccountContextProvider):
    """Resolve a fresh context (for example SSO -> product token) in memory."""

    def __init__(self, provider_id: str,
                 callback: Callable[[AccountContextRef], Any], *,
                 default_allowed_hosts: Sequence[str] = ()):
        if not provider_id or not callable(callback):
            raise ValueError("provider_id and callback are required")
        self.provider_id = provider_id
        self.callback = callback
        self.default_allowed_hosts = tuple(default_allowed_hosts or ())

    def resolve(self, reference: AccountContextRef) -> AccountContext:
        reference.validate()
        if reference.provider_id != self.provider_id:
            raise AccountContextMismatch("account context provider does not match")
        try:
            value = self.callback(reference)
        except AccountContextError:
            raise
        except Exception:
            raise AccountContextUnavailable("account context callback failed") from None
        if isinstance(value, AccountContext):
            context = value
        elif isinstance(value, Mapping):
            context = _record_to_context(
                value,
                reference,
                provider_id=self.provider_id,
                default_project_id=reference.project_id,
                default_env_id=reference.env_id,
                default_allowed_hosts=self.default_allowed_hosts,
                max_age_seconds=300,
            )
        else:
            raise AccountContextInvalid("account context callback returned an invalid value")
        return context.validate(reference)


_TRUSTED_CODE_MODULES = {
    "base64", "datetime", "hashlib", "hmac", "json", "math",
    "re", "requests", "time", "uuid",
}
_TRUSTED_CODE_BLOCKED_CALLS = {
    "__import__", "breakpoint", "compile", "eval", "exec", "globals",
    "input", "locals", "open", "vars",
}


def validate_trusted_auth_code(code_text: str) -> str:
    """Apply low-cost guardrails to administrator-trusted auth code.

    This is deliberately not advertised as a hostile-code sandbox.  The code
    still runs in a separate bounded subprocess and only receives a restricted
    outbound HTTP client at runtime.
    """
    code_text = str(code_text or "").strip()
    if not code_text:
        raise ValueError("trusted authentication code is empty")
    if len(code_text.encode("utf-8")) > 65536:
        raise ValueError("trusted authentication code is too large")
    try:
        tree = ast.parse(code_text, filename="<trusted_auth_code>", mode="exec")
    except SyntaxError:
        raise ValueError("trusted authentication code has invalid syntax") from None
    has_get_auth = False
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            has_get_auth = has_get_auth or node.name == "get_auth"
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name not in _TRUSTED_CODE_MODULES:
                    raise ValueError(
                        "trusted authentication code imports an unsupported module"
                    )
        if isinstance(node, ast.ImportFrom):
            if str(node.module or "") not in _TRUSTED_CODE_MODULES:
                raise ValueError(
                    "trusted authentication code imports an unsupported module"
                )
        if isinstance(node, ast.Name) and (
                node.id.startswith("__") or node.id in _TRUSTED_CODE_BLOCKED_CALLS):
            raise ValueError("trusted authentication code uses a blocked name")
        if isinstance(node, ast.Attribute) and str(node.attr or "").startswith("__"):
            raise ValueError("trusted authentication code uses a blocked attribute")
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            if node.func.id in _TRUSTED_CODE_BLOCKED_CALLS:
                raise ValueError("trusted authentication code uses a blocked call")
    if not has_get_auth:
        raise ValueError(
            "trusted authentication code must define get_auth(username, password)"
        )
    return code_text


def trusted_auth_code_enabled() -> bool:
    value = str(
        os.getenv("API_MANAGER_ALLOW_TRUSTED_AUTH_CODE", "1")
    ).strip().lower()
    return value not in {"0", "false", "no", "off"}


def _http_origin(value: str) -> str:
    text = str(value or "").strip()
    parsed = urlsplit(text)
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


class TokenEndpointProvider(AccountContextProvider):
    """Fetch auth tokens from a user-configured HTTP endpoint.

    The simplest integration: the user already has a mechanism to obtain
    tokens (a local script, a browser helper, an OTP tool, a file watcher).
    They expose it as an HTTP endpoint; this provider just calls it.

    Configuration is loaded from the immutable Profile/Realm/Adapter chain:
        token_url       – the endpoint to call
        token_method    – GET or POST (default GET)
        pass_credentials – how to send username/password:
                           "none" | "query" | "headers" | "body" (default "none")
        token_header    – header name for the token (default "Authorization")
        token_prefix    – prefix for the token value (default "Bearer ")
        response_path   – JSON path to extract token (default "access_token")
        extra_headers   – dict of additional headers to send
        cookie_names    – list of cookie names to extract from response
    """

    def __init__(
            self, provider_id: str = "token_endpoint", *,
            default_allowed_hosts: Sequence[str] = (),
            material_loader: Optional[Callable[[AccountContextRef], Mapping[str, Any]]] = None,
            session: Any = None,
    ):
        self.provider_id = provider_id
        self.default_allowed_hosts = tuple(default_allowed_hosts or ())
        self.material_loader = material_loader
        self.session = session

    def resolve(self, reference: AccountContextRef) -> AccountContext:
        reference.validate()
        if reference.provider_id != self.provider_id:
            raise AccountContextMismatch("account context provider does not match")
        if not callable(self.material_loader):
            raise AccountContextUnavailable("token endpoint profile loader is unavailable")
        material = dict(self.material_loader(reference) or {})
        meta = dict(material.get("config") or {})
        token_url = str(meta.get("token_url") or "").strip()
        if not token_url:
            raise AccountContextInvalid("token endpoint profile requires a URL")
        token_origin = _http_origin(token_url)
        allowed_auth_origins = {
            _http_origin(value) for value in (material.get("auth_origins") or ())
        }
        allowed_auth_origins.discard("")
        if not token_origin or token_origin not in allowed_auth_origins:
            raise AccountContextInvalid("token endpoint is outside the authentication Realm")
        method = str(meta.get("token_method") or "GET").upper()
        if method not in {"GET", "POST"}:
            raise AccountContextInvalid("token endpoint method is unsupported")
        pass_cred = str(meta.get("pass_credentials") or "none").lower()
        if pass_cred not in {"none", "query", "headers", "body"}:
            raise AccountContextInvalid("token endpoint credential mode is invalid")
        token_header = str(meta.get("token_header") or "Authorization")
        token_prefix = str(meta.get("token_prefix") or "Bearer ")
        response_path = str(meta.get("response_path") or "access_token")
        extra_headers = _validate_secret_mapping(
            dict(meta.get("extra_headers") or {}), headers=True,
        )
        cookie_names = [
            str(item) for item in (meta.get("cookie_names") or []) if str(item)
        ][:40]
        credentials = dict(material.get("credentials") or {})
        username = str(credentials.get("username") or "")
        password = str(credentials.get("password") or "")
        if pass_cred != "none" and (not username or not password):
            raise AccountContextUnavailable(
                "token endpoint requires a bound account credential"
            )

        import requests as _req
        timeout_seconds = max(
            1, min(int(meta.get("timeout_seconds") or 15), 30),
        )
        kwargs: Dict[str, Any] = {
            "timeout": timeout_seconds,
            "headers": extra_headers,
            "verify": bool(material.get("tls_verify", True)),
            "allow_redirects": False,
        }
        if pass_cred == "query":
            kwargs["params"] = {"username": username, "password": password}
        elif pass_cred == "headers":
            kwargs["headers"].update({"X-Username": username, "X-Password": password})
        elif pass_cred == "body":
            kwargs["json"] = {"username": username, "password": password}

        try:
            client = self.session or _req
            resp = client.request(method, token_url, **kwargs)
            resp.raise_for_status()
            body = getattr(resp, "content", b"")
            if body is not None and len(body) > 1024 * 1024:
                raise ValueError("response too large")
        except Exception as exc:
            raise AccountContextUnavailable(
                "token endpoint call failed: {}".format(type(exc).__name__)
            ) from None

        headers: Dict[str, str] = {}
        cookies: Dict[str, str] = {}
        try:
            data = resp.json()
        except Exception:
            data = {}
        token_value = self._extract(data, response_path) if data else ""
        if not token_value:
            token_value = resp.text.strip()
        if token_value:
            headers[token_header] = token_prefix + token_value if token_prefix else token_value
        for cname in cookie_names:
            if cname in resp.cookies:
                cookies[cname] = resp.cookies[cname]
        if resp.cookies and not cookie_names:
            cookies = dict(resp.cookies)
        if not headers and not cookies:
            raise AccountContextInvalid(
                "token endpoint returned no token or cookie"
            )
        expires_in = max(
            60, min(int(meta.get("expires_in") or 1800), 86400),
        )
        allowed_hosts = (
            material.get("allowed_hosts") or self.default_allowed_hosts
        )
        return AccountContext(
            project_id=reference.project_id,
            env_id=reference.env_id,
            account_id=reference.account_id,
            provider_id=self.provider_id,
            context_ref=reference.effective_context_ref,
            headers=headers,
            cookies=cookies,
            auth_kind="mixed" if headers and cookies else (
                "bearer" if headers else "cookie"
            ),
            issued_at=utcnow(),
            expires_at=utcnow() + dt.timedelta(seconds=expires_in),
            allowed_hosts=allowed_hosts,
            metadata={
                "profile_id": str(
                    getattr(material.get("profile"), "profile_id", "") or ""
                ),
                "auth_request_count": 1,
                "tls_verify": bool(material.get("tls_verify", True)),
            },
        ).validate(reference)

    @staticmethod
    def _extract(data: Any, path: str) -> str:
        """Simple dot-path extraction: 'data.token' -> data['data']['token']."""
        current = data
        for part in path.split("."):
            if isinstance(current, Mapping):
                current = current.get(part)
            elif isinstance(current, (list, tuple)):
                try:
                    current = current[int(part)]
                except (ValueError, IndexError):
                    return ""
            else:
                return ""
            if current is None:
                return ""
        return str(current)


class CodeAccountContextProvider(AccountContextProvider):
    """Execute administrator-trusted Python code in a bounded subprocess.

    The code must define a function ``get_auth(username, password)`` that
    returns a dict with at least ``headers`` or ``authorization`` and
    optionally ``cookies``, ``expires_in``, ``status``.

    This is a personal-deployment plugin boundary, not a hostile-code sandbox.
    Only managers can persist it; runtime adds a subprocess timeout, AST
    guardrails and an origin-restricted GET/POST requests facade.
    """

    def __init__(
            self, provider_id: str = "user_code", *,
            default_allowed_hosts: Sequence[str] = (),
            material_loader: Optional[Callable[[AccountContextRef], Mapping[str, Any]]] = None,
            runner_path: Optional[Path] = None,
    ):
        self.provider_id = provider_id
        self.default_allowed_hosts = tuple(default_allowed_hosts or ())
        self.material_loader = material_loader
        self.runner_path = (
            Path(runner_path).resolve()
            if runner_path is not None
            else Path(__file__).with_name("trusted_auth_code_runner.py").resolve()
        )

    def resolve(self, reference: AccountContextRef) -> AccountContext:
        reference.validate()
        if reference.provider_id != self.provider_id:
            raise AccountContextMismatch("account context provider does not match")
        if not trusted_auth_code_enabled():
            raise AccountContextUnavailable(
                "trusted authentication code is disabled by configuration"
            )
        if not callable(self.material_loader):
            raise AccountContextUnavailable("trusted code profile loader is unavailable")
        material = dict(self.material_loader(reference) or {})
        code_text = str(material.get("source") or "")
        if not code_text.strip():
            raise AccountContextInvalid("trusted code profile has no source")
        try:
            code_text = validate_trusted_auth_code(code_text)
        except ValueError as exc:
            raise AccountContextInvalid(str(exc)) from None
        credentials = dict(material.get("credentials") or {})
        username = str(credentials.get("username") or "")
        password = str(credentials.get("password") or "")
        config = dict(material.get("config") or {})
        try:
            result = self._exec_code(
                code_text,
                username,
                password,
                auth_origins=material.get("auth_origins") or (),
                tls_verify=bool(material.get("tls_verify", True)),
                timeout_seconds=max(
                    1, min(int(config.get("timeout_seconds") or 20), 30),
                ),
                max_requests=max(
                    1, min(int(config.get("max_requests") or 6), 6),
                ),
            )
        except AccountContextError:
            raise
        except Exception as exc:
            raise AccountContextUnavailable(
                "user code execution failed: {}".format(type(exc).__name__)
            ) from None
        if not isinstance(result, Mapping):
            raise AccountContextInvalid("user code must return a dict")
        record = dict(result)
        record.setdefault("status", "ok")
        record["account_id"] = reference.account_id
        record["issued_at"] = utcnow()
        record["metadata"] = {
            "tls_verify": bool(material.get("tls_verify", True)),
        }
        if "expires_in" in record and "expires_at" not in record:
            record["expires_at"] = dt.datetime.utcnow() + dt.timedelta(
                seconds=int(record.pop("expires_in"))
            )
        max_age_seconds = max(
            60, min(int(material.get("max_age_seconds") or 1800), 86400),
        )
        return _record_to_context(
            record, reference,
            provider_id=self.provider_id,
            default_project_id=reference.project_id,
            default_env_id=reference.env_id,
            default_allowed_hosts=(
                material.get("allowed_hosts") or self.default_allowed_hosts
            ),
            max_age_seconds=max_age_seconds,
        ).validate(reference)

    def _exec_code(
            self, code_text: str, username: str, password: str, *,
            auth_origins: Sequence[str], tls_verify: bool,
            timeout_seconds: int, max_requests: int,
    ) -> Any:
        if not self.runner_path.is_file():
            raise AccountContextUnavailable(
                "trusted authentication code runner is unavailable"
            )
        origins = sorted({_http_origin(item) for item in auth_origins})
        origins = [item for item in origins if item]
        if not origins:
            raise AccountContextInvalid(
                "trusted code requires an authentication origin"
            )
        payload = {
            "code": code_text,
            "username": username,
            "password": password,
            "auth_origins": origins,
            "tls_verify": bool(tls_verify),
            "request_timeout_seconds": min(15, timeout_seconds),
            "max_requests": max_requests,
        }
        child_env = {
            key: value for key, value in os.environ.items()
            if key.upper() in {
                "PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMP",
                "PYTHONIOENCODING", "PYTHONUTF8",
            }
        }
        child_env["PYTHONIOENCODING"] = "utf-8"
        child_env["PYTHONUTF8"] = "1"
        try:
            completed = subprocess.run(
                [sys.executable, "-I", str(self.runner_path)],
                input=json.dumps(payload, ensure_ascii=False),
                capture_output=True,
                text=True,
                encoding="utf-8",
                timeout=timeout_seconds,
                check=False,
                env=child_env,
            )
        except subprocess.TimeoutExpired:
            raise AccountContextUnavailable(
                "trusted authentication code timed out"
            ) from None
        output = str(completed.stdout or "")
        if len(output.encode("utf-8")) > 1024 * 1024:
            raise AccountContextInvalid(
                "trusted authentication code returned too much data"
            )
        try:
            message = json.loads(output)
        except (TypeError, ValueError):
            raise AccountContextUnavailable(
                "trusted authentication code runner failed"
            ) from None
        if completed.returncode != 0 or not message.get("ok"):
            error_type = str(message.get("error_type") or "RuntimeError")[:80]
            raise AccountContextUnavailable(
                "trusted authentication code failed: {}".format(error_type)
            )
        result = message.get("result")
        if not isinstance(result, Mapping):
            raise AccountContextInvalid("trusted authentication code must return a dict")
        return result


class AccountContextResolver:
    def __init__(self, providers: Iterable[AccountContextProvider] = (), cache_seconds: int = 15):
        self.cache_seconds = max(0, min(300, int(cache_seconds)))
        self._providers: Dict[str, AccountContextProvider] = {}
        self._cache: Dict[Tuple[str, str, str, str, str], Tuple[dt.datetime, AccountContext]] = {}
        self._lock = threading.RLock()
        for provider in providers:
            self.register(provider)

    def register(self, provider: AccountContextProvider) -> None:
        if not provider.provider_id:
            raise ValueError("account context provider_id is required")
        with self._lock:
            self._providers[provider.provider_id] = provider
            self._cache = {
                key: value for key, value in self._cache.items() if key[0] != provider.provider_id
            }

    def invalidate(self, reference: Optional[AccountContextRef] = None, *,
                   provider_id: str = "", context_ref: str = "") -> int:
        """Remove matching in-memory contexts after an auth repair or revision change."""
        with self._lock:
            before = len(self._cache)
            if reference is not None:
                self._cache.pop(reference.cache_key(), None)
            else:
                self._cache = {
                    key: value for key, value in self._cache.items()
                    if not (
                        (not provider_id or key[0] == provider_id)
                        and (not context_ref or key[4] == context_ref)
                    )
                }
            return before - len(self._cache)

    def resolve(self, reference: AccountContextRef, host: str = "",
                min_validity_seconds: int = 30) -> AccountContext:
        key = reference.cache_key()
        now = utcnow()
        with self._lock:
            cached = self._cache.get(key)
            if cached and cached[0] > now:
                try:
                    return cached[1].validate(reference, host, min_validity_seconds, now)
                except AccountContextExpired:
                    self._cache.pop(key, None)
            provider = self._providers.get(reference.provider_id)
        if provider is None:
            raise AccountContextUnavailable("account context provider is not configured")
        context = provider.resolve(reference).validate(reference, host, min_validity_seconds, now)
        with self._lock:
            cache_until = now + dt.timedelta(seconds=self.cache_seconds)
            if context.expires_at is not None:
                cache_until = min(cache_until, context.expires_at)
            self._cache[key] = (cache_until, context)
        return context

    def health(self, reference: AccountContextRef, host: str = "",
               min_validity_seconds: int = 30) -> Dict[str, Any]:
        try:
            return self.resolve(reference, host, min_validity_seconds).descriptor()
        except AccountContextError as exc:
            return {
                "status": "unavailable",
                "provider_id": reference.provider_id,
                "project_id": reference.project_id,
                "env_id": reference.env_id,
                "account_id": reference.account_id,
                "context_ref": reference.effective_context_ref,
                "error_type": exc.__class__.__name__,
            }


def resolver_from_environment() -> AccountContextResolver:
    """Build the optional local-file provider without reading global auth values."""
    resolver = AccountContextResolver(
        cache_seconds=int(os.getenv("API_MANAGER_ACCOUNT_CONTEXT_CACHE_SECONDS", "15"))
    )
    # The internal project/account catalog is always available as a provider;
    # it performs no database or network work until an explicit profile is
    # resolved for an execution.
    from apiAnalysis.tool.project_auth import register_project_auth_providers
    register_project_auth_providers(resolver)
    path = os.getenv("API_MANAGER_ACCOUNT_CONTEXT_FILE", "").strip()
    if not path:
        return resolver
    provider = JsonFileAccountContextProvider(
        path,
        provider_id=os.getenv("API_MANAGER_ACCOUNT_PROVIDER_ID", "local_json").strip() or "local_json",
        default_project_id=os.getenv("API_MANAGER_ACCOUNT_CONTEXT_PROJECT_ID", "").strip(),
        default_env_id=os.getenv("API_MANAGER_ACCOUNT_CONTEXT_ENV_ID", "").strip(),
        allowed_hosts=_split_values(os.getenv("API_MANAGER_ACCOUNT_ALLOWED_HOSTS", "")),
        max_age_seconds=int(os.getenv("API_MANAGER_ACCOUNT_CONTEXT_MAX_AGE_SECONDS", "1800")),
    )
    resolver.register(provider)
    return resolver
