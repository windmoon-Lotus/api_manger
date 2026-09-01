"""Project authentication providers, immutable revisions, and verification."""
from __future__ import annotations

import copy
import datetime as dt
import json
import re
import secrets
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple
from urllib.parse import urlsplit

from bson import ObjectId
from jwt import decode as decode_jwt

from apiAnalysis.core.identify.sso import legalize_ws
from apiAnalysis.db.collection import (
    AuthAdapter,
    AuthAdapterVersion,
    AuthProfileHealth,
    AuthRealm,
    AuthRealmRevision,
    AuthRealmSecretVersion,
    AuthRepairCandidate,
    AuthVerificationAttempt,
    CredentialVersion,
    ProjectAccountBinding,
    ProjectAuthProfile,
    ProjectAuthProfileRevision,
    ProjectEnvironment,
    TestAccount,
    WorkspaceSso,
    request_snapshot,
    security_execution_checkpoint,
    security_test_result,
    security_test_run,
)
from apiAnalysis.tool.account_context import (
    AccountContext,
    AccountContextInvalid,
    AccountContextMismatch,
    AccountContextProvider,
    AccountContextRef,
    AccountContextUnavailable,
    CodeAccountContextProvider,
    TokenEndpointProvider,
    utcnow,
)
from apiAnalysis.tool.auth_recipe import (
    AuthRecipeExecutor,
    AuthRecipeFailure,
    canonical_json_sha256,
    normalize_origin,
    origin_host,
    validate_recipe,
)


DATABASE_SSO_PROVIDER_ID = "database_sso"
AUTH_RECIPE_PROVIDER_ID = "auth_recipe"
TOKEN_ENDPOINT_PROVIDER_ID = "token_endpoint"
USER_CODE_PROVIDER_ID = "user_code"
AUTH_KINDS = {"bearer", "cookie", "mixed"}
REPAIR_PASSWORD_TRANSFORMS = {
    "plain", "md5", "sha256", "base64", "rsa_pkcs1v15",
}
REPAIR_REQUEST_FORMATS = {"json", "form", "query"}
REPAIR_TOKEN_SOURCES = {"json", "header", "cookie"}
_SENSITIVE_RECIPE_KEY = re.compile(
    r"(?:^|[_-])(authorization|cookie|password|passwd|secret|token|api[_-]?key)(?:$|[_-])",
    re.IGNORECASE,
)
_REALM_SECRET_KEY = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,79}$")
_REALM_SECRET_TEMPLATE = re.compile(
    r"{{\s*secret\.([A-Za-z][A-Za-z0-9_-]{0,79})\s*}}"
)


def normalize_host(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    parsed = urlsplit(text if "://" in text else "//" + text)
    return str(parsed.hostname or parsed.netloc or parsed.path).strip().lower()


def environment_host_names(environment: Optional[ProjectEnvironment]) -> List[str]:
    values: List[str] = []
    if environment:
        values.append(environment.default_host or "")
        for item in environment.hosts or []:
            if isinstance(item, dict):
                values.append(item.get("host") or item.get("base_url") or "")
            else:
                values.append(str(item))
    result = []
    for value in values:
        host = normalize_host(value)
        if host and host not in result:
            result.append(host)
    return result


def profile_context_fields(profile: ProjectAuthProfile) -> Dict[str, str]:
    revision_id = str(getattr(profile, "current_revision_id", "") or "")
    context_ref = revision_id or str(
        profile.context_ref or profile.profile_id or profile.account_key or ""
    )
    realm_revision_id = ""
    adapter_version_id = ""
    if revision_id:
        revision = ProjectAuthProfileRevision.objects(
            profile_revision_id=revision_id,
        ).first()
        if revision:
            realm_revision_id = str(revision.realm_revision_id or "")
            realm = AuthRealmRevision.objects(
                realm_revision_id=realm_revision_id,
            ).first()
            if realm:
                adapter_version_id = str(realm.adapter_version_id or "")
    return {
        "project_id": str(profile.project_id or ""),
        "env_id": str(profile.env_id or ""),
        "account_id": str(profile.account_key or ""),
        "auth_mode": "account",
        "auth_provider_id": str(profile.provider_id or ""),
        "auth_context_ref": context_ref,
        "auth_profile_revision_id": revision_id,
        "auth_realm_revision_id": realm_revision_id,
        "auth_adapter_version_id": adapter_version_id,
    }


def find_auth_profile(profile_id: str, *, project_id: str = "", env_id: str = "",
                      active: bool = True) -> Optional[ProjectAuthProfile]:
    query: Dict[str, Any] = {"profile_id": str(profile_id or "")}
    if project_id:
        query["project_id"] = str(project_id)
    if env_id:
        query["env_id"] = str(env_id)
    if active:
        query["active"] = True
    return ProjectAuthProfile.objects(**query).first()


def _token_expiry(authorization: str) -> Optional[dt.datetime]:
    try:
        token = str(authorization or "").split()[-1]
        claims = decode_jwt(token, options={"verify_signature": False})
        value = claims.get("exp")
        if value is None:
            return None
        return dt.datetime.utcfromtimestamp(float(value))
    except Exception:
        return None


def _cookie_mapping(session: Any) -> Dict[str, str]:
    result: Dict[str, str] = {}
    for cookie in getattr(session, "cookies", ()):
        if getattr(cookie, "name", None) and getattr(cookie, "value", None):
            result[str(cookie.name)] = str(cookie.value)
    return result


class DatabaseSsoAccountContextProvider(AccountContextProvider):
    """Acquire short-lived auth material from the existing SSO test account."""

    provider_id = DATABASE_SSO_PROVIDER_ID

    def _profile(self, reference: AccountContextRef) -> ProjectAuthProfile:
        profiles = ProjectAuthProfile.objects(
            project_id=reference.project_id,
            env_id=reference.env_id,
            account_key=reference.account_id,
            provider_id=self.provider_id,
            active=True,
        )
        for profile in profiles:
            context_ref = str(profile.context_ref or profile.profile_id or profile.account_key)
            if context_ref == reference.effective_context_ref:
                return profile
        raise AccountContextUnavailable("project auth profile is unavailable")

    @staticmethod
    def _workspace_sso(profile: ProjectAuthProfile) -> WorkspaceSso:
        metadata = dict(profile.metadata or {})
        explicit = str(metadata.get("workspace_sso_id") or "")
        if explicit:
            try:
                item = WorkspaceSso.objects(id=ObjectId(explicit)).first()
            except Exception:
                item = None
            if item:
                return item
        workspace_id = str(metadata.get("workspace_id") or "")
        if workspace_id:
            try:
                item = WorkspaceSso.objects(ws_id=ObjectId(workspace_id)).first()
            except Exception:
                item = None
            if item:
                return item
        raise AccountContextUnavailable(
            "database SSO profiles must pin workspace_sso_id or workspace_id; "
            "global Workspace fallback is retired"
        )

    def resolve(self, reference: AccountContextRef) -> AccountContext:
        if reference.provider_id != self.provider_id:
            raise AccountContextMismatch("account context provider does not match")
        profile = self._profile(reference)
        binding = ProjectAccountBinding.objects(
            project_id=reference.project_id,
            env_id=reference.env_id,
            account_key=reference.account_id,
            active=True,
        ).first()
        if not binding or not binding.account:
            raise AccountContextUnavailable("project account binding is unavailable")
        environment = ProjectEnvironment.objects(
            project_id=reference.project_id,
            env_id=reference.env_id,
            active=True,
        ).first()
        allowed_hosts = [normalize_host(item) for item in (profile.allowed_hosts or [])]
        allowed_hosts = [item for item in allowed_hosts if item] or environment_host_names(environment)
        if not allowed_hosts:
            raise AccountContextInvalid("project auth profile requires an allowed Host")
        try:
            authorization, session = legalize_ws(binding.account, self._workspace_sso(profile))
            auth_kind = str(profile.auth_kind or "mixed").lower()
            if auth_kind not in AUTH_KINDS:
                raise AccountContextInvalid("project auth kind is invalid")
            headers = {"Authorization": str(authorization)} if auth_kind in {"bearer", "mixed"} else {}
            cookies = _cookie_mapping(session) if auth_kind in {"cookie", "mixed"} else {}
            expires_at = _token_expiry(authorization)
            if expires_at is None:
                max_age = int((profile.metadata or {}).get("max_age_seconds") or 1800)
                expires_at = utcnow() + dt.timedelta(seconds=max(60, min(max_age, 86400)))
            context = AccountContext(
                project_id=reference.project_id,
                env_id=reference.env_id,
                account_id=reference.account_id,
                provider_id=reference.provider_id,
                context_ref=reference.effective_context_ref,
                headers=headers,
                cookies=cookies,
                auth_kind=auth_kind,
                issued_at=utcnow(),
                expires_at=expires_at,
                allowed_hosts=allowed_hosts,
                metadata={"profile_id": profile.profile_id},
            )
        except (AccountContextInvalid, AccountContextUnavailable, AccountContextMismatch):
            profile.last_error_type = "AccountContextError"
            profile.mtime = utcnow()
            profile.save()
            raise
        except Exception as exc:
            safe_error = str(exc or "").strip()
            if not safe_error.startswith("SSO_"):
                safe_error = exc.__class__.__name__
            profile.last_error_type = safe_error[:120]
            profile.mtime = utcnow()
            profile.save()
            raise AccountContextUnavailable(
                "project account login failed ({})".format(safe_error[:120])
            ) from None
        profile.last_refresh_at = utcnow()
        profile.last_error_type = ""
        profile.mtime = utcnow()
        profile.save()
        return context.validate(reference)


def register_database_sso_provider(resolver: Any) -> Any:
    resolver.register(DatabaseSsoAccountContextProvider())
    return resolver


def environment_business_origins(environment: Optional[ProjectEnvironment]) -> List[str]:
    values: List[str] = []
    if environment:
        if environment.default_host:
            values.append(environment.default_host)
        for item in environment.hosts or []:
            if isinstance(item, dict):
                values.append(item.get("base_url") or item.get("host") or "")
            else:
                values.append(str(item))
    result: List[str] = []
    for value in values:
        origin = normalize_origin(value)
        if origin and origin not in result:
            result.append(origin)
    return result


def _recipe_field_name(value: str, label: str) -> str:
    text = str(value or "").strip()
    if not text or len(text) > 120 or any(ord(char) < 32 for char in text):
        raise ValueError("{} is invalid".format(label))
    return text


def _assert_recipe_contains_no_literal_secrets(value: Any, key: str = "") -> None:
    """Reject credentials accidentally pasted into a persisted Recipe.

    Credentials must be referenced through ``credential`` variables and runtime
    output through ``vars``.  Field names such as ``password`` and
    ``access_token`` remain valid; only literal values under sensitive keys are
    rejected.
    """
    if isinstance(value, Mapping):
        for child_key, child_value in value.items():
            _assert_recipe_contains_no_literal_secrets(child_value, str(child_key))
        return
    if isinstance(value, list):
        for child_value in value:
            _assert_recipe_contains_no_literal_secrets(child_value, key)
        return
    if not isinstance(value, str):
        return
    text = value.strip()
    templated = (
        "{{credential." in text
        or "{{secret." in text
        or "{{vars." in text
    )
    if _SENSITIVE_RECIPE_KEY.search(str(key or "")) and text and not templated:
        raise ValueError("authentication Recipe cannot persist a literal credential or token")
    if text.lower().startswith("bearer ") and not templated:
        raise ValueError("authentication Recipe cannot persist a literal bearer token")


def sanitize_protocol_fields(value: Optional[Mapping[str, Any]]) -> Dict[str, Any]:
    """Return a bounded JSON-compatible mapping for non-secret protocol flags."""
    if value in (None, {}):
        return {}
    if not isinstance(value, Mapping):
        raise ValueError("additional protocol fields must be a JSON object")
    try:
        encoded = json.dumps(value, ensure_ascii=True, sort_keys=True)
        result = json.loads(encoded)
    except (TypeError, ValueError):
        raise ValueError("additional protocol fields must be JSON compatible") from None
    if len(encoded) > 8192:
        raise ValueError("additional protocol fields are too large")
    _assert_recipe_contains_no_literal_secrets(result)
    return result


def normalize_realm_secret_data(
        value: Optional[Mapping[str, Any]]) -> Dict[str, str]:
    """Validate Realm-scoped protocol secrets without exposing their values."""
    if value in (None, {}):
        return {}
    if not isinstance(value, Mapping):
        raise ValueError("Realm shared secrets must be a JSON object")
    if len(value) > 20:
        raise ValueError("Realm shared secrets contain too many fields")
    result: Dict[str, str] = {}
    total_size = 0
    for raw_name, raw_value in value.items():
        name = str(raw_name or "").strip()
        if not _REALM_SECRET_KEY.fullmatch(name):
            raise ValueError("Realm shared secret name is invalid")
        if not isinstance(raw_value, str) or not raw_value:
            raise ValueError("Realm shared secret values must be non-empty strings")
        if len(raw_value) > 8192:
            raise ValueError("Realm shared secret value is too large")
        total_size += len(name) + len(raw_value)
        if total_size > 32768:
            raise ValueError("Realm shared secrets are too large")
        result[name] = raw_value
    return result


def recipe_secret_names(value: Any) -> List[str]:
    """Return the Realm secret names referenced by a Recipe."""
    names = set()
    if isinstance(value, Mapping):
        for child in value.values():
            names.update(recipe_secret_names(child))
    elif isinstance(value, list):
        for child in value:
            names.update(recipe_secret_names(child))
    elif isinstance(value, str):
        names.update(_REALM_SECRET_TEMPLATE.findall(value))
    return sorted(names)


def recipe_output_credential_stage(recipe: Mapping[str, Any]) -> str:
    """Classify the credential exported to business requests.

    New Recipes declare the stage explicitly.  Older imported three-step
    Recipes are recognized only when their output structurally references the
    extracted product token; a template label alone is not sufficient.
    """
    output = recipe.get("output") or {}
    explicit = str(output.get("credential_stage") or "").strip().lower()
    if explicit in {"product", "sso", "session", "direct"}:
        return explicit
    rendered_output = json.dumps(
        {
            "headers": output.get("headers") or {},
            "cookies": output.get("cookies") or {},
        },
        ensure_ascii=True,
        sort_keys=True,
    )
    if "{{vars.product_access_token}}" in rendered_output:
        return "product"
    return "session"


def _auth_http_url(value: str, label: str) -> str:
    text = str(value or "").strip()
    origin = normalize_origin(text)
    parsed = urlsplit(text)
    if (
            not origin
            or str(parsed.scheme or "").lower() not in {"http", "https"}
            or not parsed.path
            or parsed.username
            or parsed.password
            or parsed.fragment):
        raise ValueError("{} must be an absolute HTTP(S) URL".format(label))
    return text




def build_password_login_recipe(
        login_url: str, *,
        method: str = "POST",
        request_format: str = "json",
        username_field: str = "account",
        password_field: str = "password",
        password_transform: str = "plain",
        token_source: str = "json",
        token_path: str = "access_token",
        token_header: str = "Authorization",
        token_prefix: str = "Bearer",
        auth_kind: str = "bearer",
        include_session_cookies: Optional[bool] = None,
        success_statuses: Sequence[int] = (200,),
        error_json_path: str = "",
        extra_fields: Optional[Mapping[str, Any]] = None,
        max_age_seconds: int = 1800,
        rsa_public_key_secret_name: str = "login_rsa_public_key",
        rsa_append_timestamp: bool = False,
        rsa_timestamp_delimiter: str = "###",
        rsa_timestamp_unit: str = "seconds",
) -> Dict[str, Any]:
    """Build the common password-login case as a restricted data Recipe."""
    origin = normalize_origin(login_url)
    parsed = urlsplit(str(login_url or "").strip())
    if not origin or not parsed.path or parsed.username or parsed.password:
        raise ValueError("login URL must be an absolute HTTP(S) URL without credentials")
    method = str(method or "POST").upper()
    if method not in {"GET", "POST"}:
        raise ValueError("login method must be GET or POST")
    request_format = str(request_format or "json").lower()
    if request_format not in REPAIR_REQUEST_FORMATS:
        raise ValueError("login request format is unsupported")
    password_transform = str(password_transform or "plain").lower()
    if password_transform not in REPAIR_PASSWORD_TRANSFORMS:
        raise ValueError("password transform is unsupported")
    auth_kind = str(auth_kind or "bearer").lower()
    if auth_kind not in AUTH_KINDS:
        raise ValueError("authentication output kind is unsupported")
    token_source = str(token_source or "json").lower()
    if token_source not in REPAIR_TOKEN_SOURCES:
        raise ValueError("token extraction source is unsupported")
    username_field = _recipe_field_name(username_field, "username field")
    password_field = _recipe_field_name(password_field, "password field")
    token_header = _recipe_field_name(token_header, "token header")
    if "\r" in str(token_prefix or "") or "\n" in str(token_prefix or ""):
        raise ValueError("token prefix is invalid")
    token_path = str(token_path or "").strip()
    if auth_kind == "bearer" and not token_path:
        raise ValueError("bearer authentication requires a token path or name")

    payload = sanitize_protocol_fields(extra_fields)
    payload[username_field] = "{{credential.username}}"
    steps: List[Dict[str, Any]] = []
    password_value = "{{credential.password}}"
    if password_transform == "rsa_pkcs1v15":
        rsa_public_key_secret_name = _recipe_field_name(
            rsa_public_key_secret_name, "RSA public key secret name",
        )
        if not _REALM_SECRET_KEY.fullmatch(rsa_public_key_secret_name):
            raise ValueError("RSA public key secret name is invalid")
        plaintext_value = "{{credential.password}}"
        if rsa_append_timestamp:
            delimiter = str(rsa_timestamp_delimiter or "")
            if len(delimiter) > 32 or any(ord(char) < 32 for char in delimiter):
                raise ValueError("RSA timestamp delimiter is invalid")
            timestamp_unit = str(rsa_timestamp_unit or "seconds").lower()
            if timestamp_unit not in {"seconds", "milliseconds"}:
                raise ValueError("RSA timestamp unit is invalid")
            steps.extend([
                {
                    "id": "prepare_login_timestamp",
                    "type": "set",
                    "target": "login_timestamp",
                    "operation": "unix_time",
                    "unit": timestamp_unit,
                },
                {
                    "id": "prepare_rsa_plaintext",
                    "type": "set",
                    "target": "rsa_plaintext",
                    "operation": "concat",
                    "values": [
                        "{{credential.password}}",
                        delimiter,
                        "{{vars.login_timestamp}}",
                    ],
                },
            ])
            plaintext_value = "{{vars.rsa_plaintext}}"
        steps.append({
            "id": "prepare_password",
            "type": "set",
            "target": "login_password",
            "operation": "rsa_encrypt",
            "value": plaintext_value,
            "public_key": "{{secret.%s}}" % rsa_public_key_secret_name,
            "padding": "pkcs1v15",
            "output_encoding": "base64",
        })
        password_value = "{{vars.login_password}}"
    elif password_transform != "plain":
        steps.append({
            "id": "prepare_password",
            "type": "set",
            "target": "login_password",
            "operation": password_transform,
            "value": "{{credential.password}}",
        })
        password_value = "{{vars.login_password}}"
    payload[password_field] = password_value

    accepted = []
    for value in success_statuses or (200,):
        try:
            status = int(value)
        except (TypeError, ValueError):
            continue
        if 100 <= status <= 599 and status not in accepted:
            accepted.append(status)
    if not accepted:
        accepted = [200]
    login_step: Dict[str, Any] = {
        "id": "login",
        "type": "http",
        "method": method,
        "url": str(login_url).strip(),
        "headers": {"Accept": "application/json"},
        request_format: payload,
        "success_statuses": accepted[:20],
        "error_status_map": {
            "400": "CREDENTIAL_REJECTED",
            "401": "CREDENTIAL_REJECTED",
            "403": "CREDENTIAL_REJECTED",
            "404": "LOGIN_PROTOCOL_CHANGED",
            "405": "LOGIN_PROTOCOL_CHANGED",
            "410": "LOGIN_PROTOCOL_CHANGED",
            "421": "LOGIN_PROTOCOL_CHANGED",
            "429": "RATE_LIMITED",
        },
    }
    error_json_path = str(error_json_path or "").strip()
    if error_json_path:
        login_step.update({
            "json_error_path": error_json_path,
            "json_error_default": "CREDENTIAL_REJECTED",
        })
    if token_path:
        extract_rule: Dict[str, Any] = {
            "source": token_source,
            "required": auth_kind in {"bearer", "mixed"},
            "failure_code": "TOKEN_EXTRACTION_FAILED",
        }
        if token_source == "json":
            extract_rule["path"] = token_path
        else:
            extract_rule["name"] = token_path
        login_step["extract"] = {"access_token": extract_rule}
    steps.append(login_step)

    output_headers: Dict[str, str] = {}
    if token_path and auth_kind in {"bearer", "mixed"}:
        prefix = str(token_prefix or "").strip()
        output_headers[token_header] = (
            prefix + " {{vars.access_token}}"
            if prefix else "{{vars.access_token}}"
        )
    include_cookies = (
        auth_kind in {"cookie", "mixed"}
        if include_session_cookies is None
        else bool(include_session_cookies)
    )
    recipe = {
        "schema_version": 1,
        "steps": steps,
        "output": {
            "auth_kind": auth_kind,
            "headers": output_headers,
            "cookies": {},
            "include_session_cookies": include_cookies,
            "expires_in_seconds": max(60, min(int(max_age_seconds), 86400)),
        },
    }
    validate_recipe(recipe)
    _assert_recipe_contains_no_literal_secrets(recipe)
    return recipe


def build_sso_product_token_recipe(
        authorization_url: str, token_login_url: str,
        product_verification_url: str, *,
        client_token_secret_name: str = "client_token",
        browser_id: str = "",
        browser_type: str = "chrome",
        sso_token_path: str = "access_token",
        product_token_path: str = "access_token",
        token_header: str = "Authorization",
        token_prefix: str = "Bearer",
        max_age_seconds: int = 1800,
) -> Dict[str, Any]:
    """Build a bounded SSO -> session -> product-token exchange Recipe.

    The Recipe keeps account credentials and the Realm Client Token outside the
    persisted artifact.  Its output deliberately references only the final
    product token, so callers cannot accidentally inject the intermediate SSO
    token into a business request.
    """
    authorization_url = _auth_http_url(
        authorization_url, "SSO authorization URL",
    )
    token_login_url = _auth_http_url(token_login_url, "token-login URL")
    product_verification_url = _auth_http_url(
        product_verification_url, "product-verification URL",
    )
    client_token_secret_name = _recipe_field_name(
        client_token_secret_name, "Realm Client Token secret name",
    )
    token_header = _recipe_field_name(token_header, "token header")
    sso_token_path = str(sso_token_path or "").strip()
    product_token_path = str(product_token_path or "").strip()
    if not sso_token_path or not product_token_path:
        raise ValueError("SSO and product token JSON paths are required")
    if "\r" in str(token_prefix or "") or "\n" in str(token_prefix or ""):
        raise ValueError("token prefix is invalid")
    browser_id = str(browser_id or "").strip()
    browser_type = str(browser_type or "").strip()
    if not browser_id or len(browser_id) > 256:
        raise ValueError("browser identity is required")
    if not browser_type or len(browser_type) > 80:
        raise ValueError("browser type is required")

    bearer_prefix = str(token_prefix or "").strip()
    intermediate_authorization = (
        bearer_prefix + " {{vars.sso_access_token}}"
        if bearer_prefix else "{{vars.sso_access_token}}"
    )
    final_authorization = (
        bearer_prefix + " {{vars.product_access_token}}"
        if bearer_prefix else "{{vars.product_access_token}}"
    )
    recipe: Dict[str, Any] = {
        "schema_version": 1,
        "template": "sso_session_product_token_v1",
        "steps": [
            {
                "id": "prepare_client_token_hash",
                "label": "Hash Realm Client Token",
                "type": "set",
                "target": "client_token_hash",
                "operation": "md5",
                "value": "{{secret.%s}}" % client_token_secret_name,
            },
            {
                "id": "prepare_timestamp",
                "label": "Create login timestamp",
                "type": "set",
                "target": "login_timestamp",
                "operation": "unix_time",
            },
            {
                "id": "prepare_request_token_input",
                "label": "Build authorization signature input",
                "type": "set",
                "target": "request_token_input",
                "operation": "concat",
                "values": [
                    "{{credential.username}}",
                    "{{vars.client_token_hash}}",
                    "{{vars.login_timestamp}}",
                ],
            },
            {
                "id": "prepare_request_token",
                "label": "Hash authorization signature",
                "type": "set",
                "target": "request_token",
                "operation": "md5",
                "value": "{{vars.request_token_input}}",
            },
            {
                "id": "prepare_password",
                "label": "Hash account password",
                "type": "set",
                "target": "login_password",
                "operation": "md5",
                "value": "{{credential.password}}",
            },
            {
                "id": "sso_authorization",
                "label": "Acquire SSO token",
                "type": "http",
                "method": "POST",
                "url": authorization_url,
                "headers": {"Accept": "application/json"},
                "json": {
                    "account": "{{credential.username}}",
                    "ismd5": True,
                    "token": "{{vars.request_token}}",
                    "timestamp": "{{vars.login_timestamp}}",
                    "password": "{{vars.login_password}}",
                },
                "success_statuses": [200],
                "extract": {
                    "sso_access_token": {
                        "source": "json",
                        "path": sso_token_path,
                        "required": True,
                        "failure_code": "TOKEN_EXTRACTION_FAILED",
                    },
                },
            },
            {
                "id": "establish_session",
                "label": "Establish login session",
                "type": "http",
                "method": "GET",
                "url": token_login_url,
                "headers": {"Accept": "application/json, text/plain, */*"},
                "query": {"token": "{{vars.sso_access_token}}"},
                "success_statuses": [200, 204, 302, 303],
            },
            {
                "id": "product_verification",
                "label": "Exchange product token",
                "type": "http",
                "method": "POST",
                "url": product_verification_url,
                "headers": {
                    "Accept": "application/json",
                    "Authorization": intermediate_authorization,
                    "Content-Type": "application/json",
                },
                "json": {
                    "browserid": browser_id,
                    "browsertype": browser_type,
                },
                "success_statuses": [200],
                "extract": {
                    "product_access_token": {
                        "source": "json",
                        "path": product_token_path,
                        "required": True,
                        "failure_code": "TOKEN_EXTRACTION_FAILED",
                    },
                },
            },
        ],
        "output": {
            "credential_stage": "product",
            "auth_kind": "mixed",
            "headers": {token_header: final_authorization},
            "cookies": {},
            "include_session_cookies": True,
            "expires_in_seconds": max(
                60, min(int(max_age_seconds), 86400),
            ),
        },
    }
    validate_recipe(recipe)
    _assert_recipe_contains_no_literal_secrets(recipe)
    return recipe


def recipe_auth_origins(recipe: Mapping[str, Any]) -> List[str]:
    """Return all literal HTTP origins used by a repair Recipe."""
    validate_recipe(recipe)
    origins: List[str] = []
    for step in recipe.get("steps") or []:
        if step.get("type") == "mfa_receive" and str(
                step.get("mode") or "pull").lower() == "push":
            continue
        if step.get("type") not in {"http", "mfa_receive"}:
            continue
        url = str(step.get("url") or "").strip()
        if "{{" in url or "}}" in url:
            raise ValueError("repair Recipe HTTP URLs must be explicit")
        origin = normalize_origin(url)
        if not origin:
            raise ValueError("repair Recipe contains an invalid HTTP URL")
        if origin not in origins:
            origins.append(origin)
    if not origins:
        raise ValueError("repair Recipe requires at least one HTTP origin")
    _assert_recipe_contains_no_literal_secrets(recipe)
    return origins


def validate_repair_recipe(recipe: Mapping[str, Any],
                           auth_origins: Iterable[str] = ()) -> Tuple[Dict[str, Any], List[str]]:
    """Validate and normalize a user-authored declarative repair Recipe."""
    try:
        encoded = json.dumps(recipe, ensure_ascii=True, sort_keys=True)
        normalized_recipe = json.loads(encoded)
    except (TypeError, ValueError):
        raise ValueError("authentication Recipe must be valid JSON") from None
    if len(encoded) > 65536:
        raise ValueError("authentication Recipe is too large")
    used_origins = recipe_auth_origins(normalized_recipe)
    explicit_origins = []
    for value in auth_origins or ():
        origin = normalize_origin(value)
        if origin and origin not in explicit_origins:
            explicit_origins.append(origin)
    selected_origins = explicit_origins or used_origins
    if any(origin not in selected_origins for origin in used_origins):
        raise ValueError("Recipe HTTP origin is outside the selected authentication Realm")
    return normalized_recipe, selected_origins


def create_profile_revision(profile: ProjectAuthProfile, *, project_account_key: str,
                            realm_revision_id: str, auth_kind: str = "mixed",
                            allowed_business_origins: Iterable[str] = (),
                            max_age_seconds: int = 1800) -> ProjectAuthProfileRevision:
    """Create or reuse one content-addressed immutable profile revision."""
    auth_kind = str(auth_kind or "mixed").lower()
    if auth_kind not in AUTH_KINDS:
        raise ValueError("invalid authentication injection kind")
    realm = AuthRealmRevision.objects(realm_revision_id=str(realm_revision_id or "")).first()
    if not realm:
        raise ValueError("authentication realm revision is unavailable")
    origins = sorted({normalize_origin(item) for item in allowed_business_origins})
    origins = [item for item in origins if item]
    payload = {
        "project_account_key": str(project_account_key or ""),
        "realm_revision_id": realm.realm_revision_id,
        "auth_kind": auth_kind,
        "refresh_strategy": "login",
        "allowed_business_origins": origins,
        "max_age_seconds": max(60, min(int(max_age_seconds), 86400)),
    }
    digest = canonical_json_sha256(payload)
    existing = ProjectAuthProfileRevision.objects(
        profile_id=profile.profile_id, config_sha256=digest,
    ).first()
    if existing:
        return existing
    latest = ProjectAuthProfileRevision.objects(
        profile_id=profile.profile_id,
    ).order_by("-revision_no").first()
    revision_no = int(latest.revision_no if latest else 0) + 1
    revision = ProjectAuthProfileRevision(
        profile_revision_id="profile-rev-{}".format(secrets.token_hex(10)),
        profile_id=profile.profile_id,
        revision_no=revision_no,
        config_sha256=digest,
        **payload
    )
    revision.save(force_insert=True)
    return revision


def _next_adapter_semver(adapter_id: str) -> str:
    patch = max(1, AuthAdapterVersion.objects(adapter_id=adapter_id).count())
    while AuthAdapterVersion.objects(
            adapter_id=adapter_id, semver="1.0.{}".format(patch)).first():
        patch += 1
    return "1.0.{}".format(patch)


def recipe_capabilities(recipe: Mapping[str, Any]) -> List[str]:
    capabilities = {"http"}
    for step in recipe.get("steps") or []:
        if step.get("type") == "set":
            capabilities.add(str(step.get("operation") or "set"))
        if step.get("type") == "mfa_receive":
            capabilities.add("mfa_receiver")
            capabilities.add("mfa_{}".format(str(step.get("mode") or "pull")))
        for key in ("json", "form", "query"):
            if key in step:
                capabilities.add(key)
    output = recipe.get("output") or {}
    capabilities.add(str(output.get("auth_kind") or "mixed"))
    return sorted(item for item in capabilities if item)


def _create_adapter_artifact_version(
        adapter: AuthAdapter, *,
        artifact: Mapping[str, Any],
        auth_origins: Sequence[str],
        capabilities: Sequence[str] = (),
) -> AuthAdapterVersion:
    """Create or reuse one immutable adapter artifact.

    ``AuthAdapterVersion.recipe`` is the existing JSON artifact slot.  Recipe
    adapters store a declarative Recipe in it; the Token URL and trusted-code
    adapters store a versioned provider manifest.  Runtime provider selection
    still comes from ``ProjectAuthProfile.provider_id``.
    """
    origins = sorted({normalize_origin(item) for item in auth_origins})
    origins = [item for item in origins if item]
    digest = canonical_json_sha256({
        "artifact": artifact,
        "allowed_auth_origins": origins,
    })
    existing = AuthAdapterVersion.objects(
        adapter_id=adapter.adapter_id,
        artifact_sha256=digest,
    ).first()
    if existing:
        return existing
    version = AuthAdapterVersion(
        adapter_version_id="auth-adapter-rev-{}".format(secrets.token_hex(10)),
        adapter_id=adapter.adapter_id,
        semver=_next_adapter_semver(adapter.adapter_id),
        schema_version=int(artifact.get("schema_version") or 1),
        recipe=dict(artifact),
        capabilities=sorted({str(item) for item in capabilities if str(item)}),
        allowed_auth_origins=origins,
        artifact_sha256=digest,
        lifecycle="draft",
    )
    version.save(force_insert=True)
    return version


def _create_adapter_version(adapter: AuthAdapter, *, recipe: Mapping[str, Any],
                            auth_origins: Sequence[str]) -> AuthAdapterVersion:
    return _create_adapter_artifact_version(
        adapter,
        artifact=recipe,
        auth_origins=auth_origins,
        capabilities=recipe_capabilities(recipe),
    )


def _create_realm_secret_version(
        realm: AuthRealm,
        secret_data: Mapping[str, Any],
) -> AuthRealmSecretVersion:
    normalized = normalize_realm_secret_data(secret_data)
    if not normalized:
        raise ValueError("Realm shared secret data is empty")
    latest = AuthRealmSecretVersion.objects(
        realm_id=realm.realm_id,
    ).order_by("-revision_no").first()
    if latest and dict(latest.secret_data or {}) == normalized:
        return latest
    version = AuthRealmSecretVersion(
        secret_version_id="auth-realm-secret-{}".format(secrets.token_hex(10)),
        realm_id=realm.realm_id,
        revision_no=int(latest.revision_no if latest else 0) + 1,
        secret_data=normalized,
        lifecycle="draft",
    )
    version.save(force_insert=True)
    return version


def realm_secret_key_names(
        realm_revision: Optional[AuthRealmRevision],
) -> List[str]:
    """Return only configured key names for display and preflight."""
    if not realm_revision or not realm_revision.secret_version_id:
        return []
    version = AuthRealmSecretVersion.objects(
        secret_version_id=realm_revision.secret_version_id,
        realm_id=realm_revision.realm_id,
    ).first()
    return sorted(str(key) for key in (version.secret_data or {})) if version else []


def _create_realm_revision(realm: AuthRealm, *, adapter_version_id: str,
                           auth_origins: Sequence[str], tls_verify: bool,
                           secret_version_id: str = "",
                           config: Optional[Mapping[str, Any]] = None) -> AuthRealmRevision:
    origins = sorted({normalize_origin(item) for item in auth_origins})
    origins = [item for item in origins if item]
    normalized_config = sanitize_protocol_fields(config)
    selected_secret_version_id = str(secret_version_id or "")
    if selected_secret_version_id and not AuthRealmSecretVersion.objects(
            secret_version_id=selected_secret_version_id,
            realm_id=realm.realm_id).first():
        raise ValueError("Realm shared secret version is unavailable")
    digest = canonical_json_sha256({
        "adapter_version_id": str(adapter_version_id or ""),
        "secret_version_id": selected_secret_version_id,
        "auth_origins": origins,
        "tls_verify": bool(tls_verify),
        "config": normalized_config,
    })
    existing = AuthRealmRevision.objects(
        realm_id=realm.realm_id,
        config_sha256=digest,
    ).first()
    if existing:
        return existing
    latest = AuthRealmRevision.objects(
        realm_id=realm.realm_id,
    ).order_by("-revision_no").first()
    revision = AuthRealmRevision(
        realm_revision_id="auth-realm-rev-{}".format(secrets.token_hex(10)),
        realm_id=realm.realm_id,
        revision_no=int(latest.revision_no if latest else 0) + 1,
        adapter_version_id=str(adapter_version_id or ""),
        secret_version_id=selected_secret_version_id,
        auth_origins=origins,
        tls_verify=bool(tls_verify),
        config=normalized_config,
        config_sha256=digest,
        lifecycle="draft",
    )
    revision.save(force_insert=True)
    return revision


def _auth_import_purpose(*, login_scene: str, role_key: str, login_mode: str,
                         account_key: str, provider_id: str) -> str:
    """Return the stable Profile slot for one concrete login capability."""
    digest = canonical_json_sha256({
        "login_scene": login_scene,
        "role_key": role_key,
        "login_mode": login_mode,
        "account_key": account_key,
        "provider_id": provider_id,
    })
    return "login:{}".format(digest[:20])


def _current_profile_chain(profile: Optional[ProjectAuthProfile]):
    if not profile or not profile.current_revision_id:
        return None, None, None
    revision = ProjectAuthProfileRevision.objects(
        profile_revision_id=profile.current_revision_id,
        profile_id=profile.profile_id,
    ).first()
    realm = AuthRealmRevision.objects(
        realm_revision_id=revision.realm_revision_id,
    ).first() if revision else None
    adapter = AuthAdapterVersion.objects(
        adapter_version_id=realm.adapter_version_id,
    ).first() if realm else None
    return revision, realm, adapter


def import_versioned_auth_profile(
        *, project_id: str, env_id: str, profile_name: str,
        account_key: str, provider_id: str, adapter_type: str,
        adapter_key: str, artifact: Mapping[str, Any],
        realm_key: str = "",
        auth_origins: Iterable[str],
        allowed_business_origins: Iterable[str] = (),
        login_scene: str = "", role_key: str = "", login_mode: str = "",
        auth_kind: str = "mixed", max_age_seconds: int = 1800,
        tls_verify: bool = True,
        realm_secret_data: Optional[Mapping[str, Any]] = None,
        capabilities: Sequence[str] = (),
) -> Dict[str, str]:
    """One-click import of one project login capability.

    A project may have many active Profiles.  The Profile slot is identified
    by login scene, role, mode and account alias.  Adapter content remains
    immutable and is versioned independently through ``adapter_key``; updating
    one Profile never changes another Profile's pinned revision.
    """
    project_id = _recipe_field_name(project_id, "project id")
    env_id = _recipe_field_name(env_id, "environment id")
    profile_name = _recipe_field_name(profile_name, "profile name")
    account_key = _recipe_field_name(account_key, "account key")
    provider_id = _recipe_field_name(provider_id, "provider id")
    adapter_type = _recipe_field_name(adapter_type, "adapter type")
    login_scene = _recipe_field_name(
        login_scene or profile_name, "login scene",
    )
    role_key = _recipe_field_name(role_key or "default", "role key")
    login_mode = _recipe_field_name(
        login_mode or provider_id, "login mode",
    )
    adapter_key = _recipe_field_name(
        adapter_key or "{}:{}:{}".format(login_scene, role_key, login_mode),
        "adapter key",
    )
    realm_key = (
        _recipe_field_name(realm_key, "Realm key") if str(realm_key or "").strip()
        else ""
    )
    if provider_id not in {
            AUTH_RECIPE_PROVIDER_ID, TOKEN_ENDPOINT_PROVIDER_ID,
            USER_CODE_PROVIDER_ID}:
        raise ValueError("unsupported imported authentication provider")
    environment = ProjectEnvironment.objects(
        project_id=project_id, env_id=env_id, active=True,
    ).first()
    if not environment:
        raise ValueError("project environment is unavailable")
    if not isinstance(artifact, Mapping):
        raise ValueError("authentication adapter artifact must be a JSON object")
    try:
        artifact = json.loads(json.dumps(
            artifact, ensure_ascii=True, sort_keys=True,
        ))
    except (TypeError, ValueError):
        raise ValueError("authentication adapter artifact must be JSON compatible") from None
    if len(json.dumps(artifact, ensure_ascii=True, sort_keys=True)) > 131072:
        raise ValueError("authentication adapter artifact is too large")

    selected_auth_origins = sorted({
        normalize_origin(item) for item in (auth_origins or ())
        if normalize_origin(item)
    })
    if not selected_auth_origins:
        raise ValueError("authentication adapter requires at least one HTTP origin")
    environment_origins = environment_business_origins(environment)
    business_origins = sorted({
        normalize_origin(item) for item in (allowed_business_origins or ())
        if normalize_origin(item)
    }) or environment_origins
    if not business_origins:
        raise ValueError("project environment has no business origin")
    if environment_origins and any(
            item not in environment_origins for item in business_origins):
        raise ValueError("business origins must belong to the selected environment")

    purpose = _auth_import_purpose(
        login_scene=login_scene,
        role_key=role_key,
        login_mode=login_mode,
        account_key=account_key,
        provider_id=provider_id,
    )
    profile = ProjectAuthProfile.objects(
        project_id=project_id, env_id=env_id, purpose=purpose,
    ).first()
    if not profile:
        legacy_profiles = list(ProjectAuthProfile.objects(
            project_id=project_id, env_id=env_id,
            name=profile_name, provider_id=provider_id,
        ))
        if len(legacy_profiles) == 1:
            legacy_metadata = dict(legacy_profiles[0].metadata or {})
            if not legacy_metadata.get("login_scene"):
                profile = legacy_profiles[0]
    if profile and profile.provider_id != provider_id:
        raise ValueError("login Profile slot is already used by another provider")
    if not profile:
        profile = ProjectAuthProfile(
            profile_id="auth-{}".format(secrets.token_hex(10)),
            project_id=project_id,
            env_id=env_id,
            account_key=account_key,
            name=profile_name,
            purpose=purpose,
            provider_id=provider_id,
            lifecycle="active",
            active=True,
        )

    current_revision, current_realm_revision, current_adapter_version = (
        _current_profile_chain(profile)
    )
    profile_metadata = dict(profile.metadata or {})
    stored_adapter_key = str(profile_metadata.get("adapter_key") or "")
    adapter_id = (
        str(profile_metadata.get("adapter_id") or "")
        if not stored_adapter_key or stored_adapter_key == adapter_key
        else ""
    )
    if not adapter_id and current_adapter_version and not stored_adapter_key:
        adapter_id = str(current_adapter_version.adapter_id or "")
    if not adapter_id:
        adapter_id = "auth-adapter-{}".format(canonical_json_sha256({
            "project_id": project_id,
            "env_id": env_id,
            "adapter_key": adapter_key,
        })[:20])
    adapter = AuthAdapter.objects(adapter_id=adapter_id).first()
    accepted_adapter_types = {adapter_type}
    if adapter_type in {"recipe", "auth_recipe"}:
        accepted_adapter_types.update({"recipe", "auth_recipe"})
    if adapter and str(adapter.adapter_type or "") not in accepted_adapter_types:
        raise ValueError("authentication adapter key is already used by another adapter type")
    if not adapter:
        adapter = AuthAdapter(
            adapter_id=adapter_id,
            name=profile_name,
            adapter_type=adapter_type,
            lifecycle="active",
        )
        adapter.save(force_insert=True)
    else:
        adapter.name = profile_name
        adapter.lifecycle = "active"
        adapter.mtime = utcnow()
        adapter.save()
    adapter_version = _create_adapter_artifact_version(
        adapter,
        artifact=artifact,
        auth_origins=selected_auth_origins,
        capabilities=capabilities,
    )

    realm_id = str(profile_metadata.get("realm_id") or "")
    if not realm_id and current_realm_revision:
        realm_id = str(current_realm_revision.realm_id or "")
    if not realm_id and realm_key:
        realm_id = "auth-realm-{}".format(canonical_json_sha256({
            "project_id": project_id,
            "env_id": env_id,
            "provider_id": provider_id,
            "realm_key": realm_key,
        })[:20])
    if not realm_id:
        realm_id = "auth-realm-{}".format(canonical_json_sha256({
            "profile_id": profile.profile_id,
        })[:20])
    realm = AuthRealm.objects(realm_id=realm_id).first()
    if not realm:
        realm = AuthRealm(
            realm_id=realm_id,
            name=(
                "{} / {}".format(login_scene, realm_key)
                if realm_key else "{} / {}".format(profile_name, role_key)
            ),
            lifecycle="active",
            source_ref=(
                "shared-realm:{}:{}:{}".format(project_id, env_id, realm_key)
                if realm_key else profile.profile_id
            ),
        )
        realm.save(force_insert=True)

    current_secret_data: Dict[str, str] = {}
    current_secret_version_id = ""
    if current_realm_revision and current_realm_revision.realm_id == realm.realm_id:
        current_secret_version_id = str(
            current_realm_revision.secret_version_id or "",
        )
        if current_secret_version_id:
            current_secret = AuthRealmSecretVersion.objects(
                secret_version_id=current_secret_version_id,
                realm_id=realm.realm_id,
            ).first()
            if current_secret:
                current_secret_data = normalize_realm_secret_data(
                    current_secret.secret_data,
                )
    entered_secret_data = normalize_realm_secret_data(realm_secret_data)
    effective_secret_data = entered_secret_data or current_secret_data
    missing_secret_names = [
        name for name in recipe_secret_names(artifact)
        if name not in effective_secret_data
    ]
    if missing_secret_names:
        raise ValueError(
            "Recipe requires Realm shared secrets: {}".format(
                ", ".join(missing_secret_names),
            )
        )
    secret_version_id = current_secret_version_id
    if entered_secret_data:
        secret_version_id = _create_realm_secret_version(
            realm, entered_secret_data,
        ).secret_version_id

    realm_config = {
        "provider_id": provider_id,
        "login_mode": login_mode,
        "adapter_key": adapter_key,
    }
    if realm_key:
        # A Realm is the shared protocol boundary. Account-local scene/role
        # metadata belongs to the Profile and must not fork the Realm revision.
        realm_config["realm_key"] = realm_key
    else:
        realm_config.update({
            "login_scene": login_scene,
            "role_key": role_key,
        })
    realm_revision = _create_realm_revision(
        realm,
        adapter_version_id=adapter_version.adapter_version_id,
        auth_origins=selected_auth_origins,
        tls_verify=bool(tls_verify),
        secret_version_id=secret_version_id,
        config=realm_config,
    )

    now = utcnow()
    profile_metadata.update({
        "login_scene": login_scene,
        "role_key": role_key,
        "login_mode": login_mode,
        "adapter_key": adapter_key,
        "adapter_id": adapter.adapter_id,
        "realm_id": realm.realm_id,
        "realm_key": realm_key,
        "max_age_seconds": max(60, min(int(max_age_seconds), 86400)),
        "quick_import": True,
    })
    profile.name = profile_name
    profile.purpose = purpose
    profile.account_key = account_key
    profile.provider_id = provider_id
    profile.auth_kind = str(auth_kind or "mixed").lower()
    profile.refresh_strategy = "login"
    profile.allowed_hosts = sorted({
        origin_host(item) for item in business_origins if origin_host(item)
    })
    profile.metadata = profile_metadata
    profile.lifecycle = "active"
    profile.active = True
    profile.mtime = now
    profile.save()
    profile_revision = create_profile_revision(
        profile,
        project_account_key=account_key,
        realm_revision_id=realm_revision.realm_revision_id,
        auth_kind=profile.auth_kind,
        allowed_business_origins=business_origins,
        max_age_seconds=profile_metadata["max_age_seconds"],
    )

    AuthAdapterVersion.objects(
        adapter_version_id=adapter_version.adapter_version_id,
    ).update_one(set__lifecycle="active")
    if secret_version_id:
        AuthRealmSecretVersion.objects(
            secret_version_id=secret_version_id,
            realm_id=realm.realm_id,
        ).update_one(set__lifecycle="active")
    AuthRealmRevision.objects(
        realm_revision_id=realm_revision.realm_revision_id,
    ).update_one(set__lifecycle="active")
    AuthRealm.objects(realm_id=realm.realm_id).update_one(
        set__lifecycle="active",
        set__current_revision_id=realm_revision.realm_revision_id,
        set__mtime=now,
    )
    ProjectAuthProfile.objects(id=profile.id).update_one(
        set__current_revision_id=profile_revision.profile_revision_id,
        set__context_ref=profile_revision.profile_revision_id,
        set__mtime=now,
    )
    AuthProfileHealth.objects(
        profile_revision_id=profile_revision.profile_revision_id,
    ).modify(
        upsert=True,
        new=True,
        set__profile_id=profile.profile_id,
        set_on_insert__status="unknown",
        set__updated_at=now,
    )
    return {
        "adapter_id": adapter.adapter_id,
        "adapter_version_id": adapter_version.adapter_version_id,
        "realm_id": realm.realm_id,
        "realm_revision_id": realm_revision.realm_revision_id,
        "secret_version_id": secret_version_id,
        "profile_id": profile.profile_id,
        "profile_revision_id": profile_revision.profile_revision_id,
        "profile_purpose": purpose,
    }


def load_versioned_auth_material(
        reference: AccountContextRef, expected_provider_id: str,
) -> Dict[str, Any]:
    """Resolve a Token URL or trusted-code Profile without persisting secrets."""
    profiles = ProjectAuthProfile.objects(
        project_id=reference.project_id,
        env_id=reference.env_id,
        account_key=reference.account_id,
        provider_id=expected_provider_id,
        active=True,
    )
    profile = None
    for candidate in profiles:
        if str(candidate.lifecycle or "active") != "active":
            continue
        accepted_refs = {
            str(candidate.current_revision_id or ""),
            str(candidate.context_ref or ""),
            str(candidate.profile_id or ""),
        }
        accepted_refs.discard("")
        if reference.effective_context_ref in accepted_refs:
            profile = candidate
            break
    if not profile:
        raise AccountContextUnavailable("project auth profile revision is unavailable")

    revision, realm, adapter = _current_profile_chain(profile)
    if revision and realm and adapter:
        if str(realm.lifecycle or "draft") not in {"validated", "active"}:
            raise AccountContextInvalid("authentication realm revision is not active")
        if str(adapter.lifecycle or "draft") not in {"validated", "active"}:
            raise AccountContextInvalid("authentication adapter version is not active")
        artifact = dict(adapter.recipe or {})
        artifact_provider = str(artifact.get("provider_id") or expected_provider_id)
        if artifact_provider != expected_provider_id:
            raise AccountContextInvalid("authentication adapter provider does not match")
        try:
            credentials = RecipeAccountContextProvider._credentials(
                profile, revision,
            )
        except AccountContextUnavailable:
            credentials = {}
        allowed_hosts = RecipeAccountContextProvider._allowed_business_hosts(
            profile, revision,
        )
        return {
            "profile": profile,
            "profile_revision": revision,
            "realm_revision": realm,
            "adapter_version": adapter,
            "artifact": artifact,
            "config": dict(artifact.get("config") or {}),
            "source": str(artifact.get("source") or ""),
            "credentials": credentials,
            "allowed_hosts": allowed_hosts,
            "auth_origins": list(realm.auth_origins or []),
            "tls_verify": bool(realm.tls_verify),
            "max_age_seconds": int(revision.max_age_seconds or 1800),
        }

    # Compatibility for profiles produced by the initial implementation.
    metadata = dict(profile.metadata or {})
    environment = ProjectEnvironment.objects(
        project_id=profile.project_id, env_id=profile.env_id, active=True,
    ).first()
    allowed_hosts = list(profile.allowed_hosts or environment_host_names(environment))
    if not allowed_hosts:
        raise AccountContextInvalid("authentication profile has no permitted business Host")
    auth_origins = list(metadata.get("allowed_auth_origins") or [])
    token_url = str(metadata.get("token_url") or "")
    if token_url and normalize_origin(token_url):
        auth_origins.append(normalize_origin(token_url))
    if not auth_origins:
        auth_origins = environment_business_origins(environment)
    credentials: Dict[str, Any] = {}
    legacy_revision = type("LegacyRevision", (), {
        "project_account_key": profile.account_key,
    })()
    try:
        credentials = RecipeAccountContextProvider._credentials(
            profile, legacy_revision,
        )
    except AccountContextUnavailable:
        pass
    return {
        "profile": profile,
        "profile_revision": None,
        "realm_revision": None,
        "adapter_version": None,
        "artifact": {},
        "config": metadata,
        "source": str(metadata.get("user_code") or ""),
        "credentials": credentials,
        "allowed_hosts": allowed_hosts,
        "auth_origins": sorted(set(auth_origins)),
        "tls_verify": bool(metadata.get("tls_verify", True)),
        "max_age_seconds": int(metadata.get("max_age_seconds") or 1800),
    }


def register_auth_repair_candidate(
        profile: ProjectAuthProfile,
        candidate_revision: ProjectAuthProfileRevision, *,
        previous_profile_revision_id: str = "",
        reason: str = "",
        operator: str = "",
) -> AuthRepairCandidate:
    """Register an immutable Profile Revision without switching the live pointer."""
    previous_id = str(
        previous_profile_revision_id or profile.current_revision_id or ""
    )
    if not previous_id:
        raise ValueError("an active authentication profile revision is required")
    if candidate_revision.profile_id != profile.profile_id:
        raise ValueError("candidate profile revision does not belong to the profile")
    realm = AuthRealmRevision.objects(
        realm_revision_id=candidate_revision.realm_revision_id,
    ).first()
    if not realm:
        raise ValueError("candidate authentication Realm revision is unavailable")
    if candidate_revision.profile_revision_id == previous_id:
        raise ValueError("candidate authentication configuration is unchanged")
    existing = AuthRepairCandidate.objects(
        profile_id=profile.profile_id,
        previous_profile_revision_id=previous_id,
        candidate_profile_revision_id=candidate_revision.profile_revision_id,
        status__in=[
            AuthRepairCandidate.DRAFT,
            AuthRepairCandidate.VALIDATING,
            AuthRepairCandidate.FAILED,
        ],
    ).order_by("-ctime").first()
    if existing:
        return existing
    now = utcnow()
    candidate = AuthRepairCandidate(
        candidate_id="auth-repair-{}".format(secrets.token_hex(10)),
        profile_id=profile.profile_id,
        project_id=profile.project_id,
        env_id=profile.env_id,
        previous_profile_revision_id=previous_id,
        candidate_profile_revision_id=candidate_revision.profile_revision_id,
        candidate_realm_revision_id=realm.realm_revision_id,
        candidate_adapter_version_id=realm.adapter_version_id,
        status=AuthRepairCandidate.DRAFT,
        reason=str(reason or "authentication configuration repair")[:240],
        operator=str(operator or "")[:120],
        ctime=now,
        mtime=now,
    )
    candidate.save(force_insert=True)
    AuthProfileHealth.objects(
        profile_revision_id=candidate_revision.profile_revision_id,
    ).modify(
        upsert=True,
        new=True,
        set__profile_id=profile.profile_id,
        set_on_insert__status="unknown",
        set__updated_at=now,
    )
    return candidate


def create_auth_repair_candidate(
        profile_id: str, *,
        recipe: Mapping[str, Any],
        auth_origins: Iterable[str] = (),
        tls_verify: bool = True,
        auth_kind: str = "",
        project_account_key: str = "",
        allowed_business_origins: Iterable[str] = (),
        max_age_seconds: int = 0,
        realm_secret_data: Optional[Mapping[str, Any]] = None,
        replace_realm_secrets: bool = False,
        reason: str = "",
        operator: str = "",
) -> AuthRepairCandidate:
    """Clone the current Adapter/Realm/Profile chain into a non-live candidate."""
    profile = ProjectAuthProfile.objects(
        profile_id=str(profile_id or ""),
        provider_id=AUTH_RECIPE_PROVIDER_ID,
        active=True,
    ).first()
    if not profile or not profile.current_revision_id:
        raise ValueError("authentication profile has no active version to repair")
    current_revision, current_realm, current_adapter = (
        RecipeAccountContextProvider._load_revision_chain(profile)
    )
    normalized_recipe, selected_origins = validate_repair_recipe(
        recipe, auth_origins,
    )
    realm = AuthRealm.objects(realm_id=current_realm.realm_id).first()
    if not realm:
        raise ValueError("authentication Realm identity is unavailable")
    secret_version_id = str(current_realm.secret_version_id or "")
    current_secret_data: Dict[str, str] = {}
    if secret_version_id:
        current_secret_version = AuthRealmSecretVersion.objects(
            secret_version_id=secret_version_id,
            realm_id=realm.realm_id,
        ).first()
        if current_secret_version:
            current_secret_data = normalize_realm_secret_data(
                current_secret_version.secret_data,
            )
        else:
            secret_version_id = ""
    entered_secret_data = (
        normalize_realm_secret_data(realm_secret_data)
        if realm_secret_data else {}
    )
    normalized_secret_data: Dict[str, str] = {}
    if entered_secret_data:
        normalized_secret_data = (
            dict(entered_secret_data)
            if replace_realm_secrets
            else {**current_secret_data, **entered_secret_data}
        )
    effective_secret_data = normalized_secret_data or current_secret_data
    secret_names = set(effective_secret_data)
    missing_secret_names = [
        name for name in recipe_secret_names(normalized_recipe)
        if name not in secret_names
    ]
    if missing_secret_names:
        raise ValueError(
            "Recipe requires Realm shared secrets: {}".format(
                ", ".join(missing_secret_names)
            )
        )
    if normalized_secret_data:
        secret_version = _create_realm_secret_version(
            realm, normalized_secret_data,
        )
        secret_version_id = secret_version.secret_version_id
    adapter = AuthAdapter.objects(adapter_id=current_adapter.adapter_id).first()
    if not adapter:
        adapter = AuthAdapter(
            adapter_id=current_adapter.adapter_id,
            name="Authentication adapter {}".format(current_adapter.adapter_id),
            adapter_type="recipe",
            lifecycle="active",
        )
        adapter.save(force_insert=True)
    adapter_version = _create_adapter_version(
        adapter,
        recipe=normalized_recipe,
        auth_origins=selected_origins,
    )
    realm_revision = _create_realm_revision(
        realm,
        adapter_version_id=adapter_version.adapter_version_id,
        secret_version_id=secret_version_id,
        auth_origins=selected_origins,
        tls_verify=bool(tls_verify),
        config={
            "login_origins": selected_origins,
            "repair_parent_revision_id": current_realm.realm_revision_id,
        },
    )
    account_key = str(
        project_account_key or current_revision.project_account_key or profile.account_key
    )
    output_kind = str(
        auth_kind or (normalized_recipe.get("output") or {}).get("auth_kind")
        or current_revision.auth_kind or "mixed"
    ).lower()
    business_origins = list(allowed_business_origins or [])
    if not business_origins:
        business_origins = list(current_revision.allowed_business_origins or [])
    maximum_age = int(max_age_seconds or current_revision.max_age_seconds or 1800)
    candidate_revision = create_profile_revision(
        profile,
        project_account_key=account_key,
        realm_revision_id=realm_revision.realm_revision_id,
        auth_kind=output_kind,
        allowed_business_origins=business_origins,
        max_age_seconds=maximum_age,
    )
    return register_auth_repair_candidate(
        profile,
        candidate_revision,
        previous_profile_revision_id=current_revision.profile_revision_id,
        reason=reason or "authentication Realm repair",
        operator=operator,
    )


def _health(profile_id: str, profile_revision_id: str) -> AuthProfileHealth:
    return AuthProfileHealth.objects(
        profile_revision_id=profile_revision_id,
    ).first() or AuthProfileHealth(
        profile_id=profile_id,
        profile_revision_id=profile_revision_id,
    )


def _set_profile_health(profile: ProjectAuthProfile, revision: ProjectAuthProfileRevision,
                        *, status: str, stage: str = "", error_code: str = "",
                        error_summary: str = "", attempt_id: str = "",
                        verified: bool = False,
                        update_profile_projection: bool = True) -> AuthProfileHealth:
    health = _health(profile.profile_id, revision.profile_revision_id)
    health.profile_id = profile.profile_id
    health.status = status
    health.stage = str(stage or "")[:80]
    health.error_code = str(error_code or "")[:80]
    health.error_summary = str(error_summary or "")[:240]
    if attempt_id:
        health.last_attempt_id = attempt_id
    if verified:
        health.last_verified_at = utcnow()
    health.updated_at = utcnow()
    health.save()
    if update_profile_projection:
        profile.last_error_type = health.error_code
        if verified:
            profile.last_refresh_at = utcnow()
        profile.mtime = utcnow()
        profile.save()
    return health


class RecipeAccountContextProvider(AccountContextProvider):
    """Resolve immutable auth revisions into the existing AccountContext."""

    provider_id = AUTH_RECIPE_PROVIDER_ID

    def __init__(self, *, max_requests: int = 6, timeout_seconds: int = 10,
                 session: Any = None):
        self.max_requests = max_requests
        self.timeout_seconds = timeout_seconds
        self.session = session

    def _profile(self, reference: AccountContextRef) -> ProjectAuthProfile:
        profiles = ProjectAuthProfile.objects(
            project_id=reference.project_id,
            env_id=reference.env_id,
            account_key=reference.account_id,
            provider_id=self.provider_id,
            active=True,
        )
        for profile in profiles:
            if str(profile.lifecycle or "active") != "active":
                continue
            revision_id = str(profile.current_revision_id or "")
            if revision_id and reference.effective_context_ref == revision_id:
                return profile
        raise AccountContextUnavailable("project auth profile revision is unavailable")

    @staticmethod
    def _load_revision_chain(profile: ProjectAuthProfile, profile_revision_id: str = "",
                             *, allow_draft: bool = False):
        revision_id = str(profile_revision_id or profile.current_revision_id or "")
        revision = ProjectAuthProfileRevision.objects(
            profile_revision_id=revision_id,
            profile_id=profile.profile_id,
        ).first()
        if not revision:
            raise AccountContextInvalid("project auth profile revision is invalid")
        realm = AuthRealmRevision.objects(
            realm_revision_id=revision.realm_revision_id,
        ).first()
        accepted_lifecycles = {"draft", "validated", "active"} if allow_draft else {
            "validated", "active",
        }
        if not realm or str(realm.lifecycle or "draft") not in accepted_lifecycles:
            raise AccountContextInvalid("authentication realm revision is not active")
        adapter = AuthAdapterVersion.objects(
            adapter_version_id=realm.adapter_version_id,
        ).first()
        if not adapter or str(adapter.lifecycle or "draft") not in accepted_lifecycles:
            raise AccountContextInvalid("authentication adapter version is not active")
        return revision, realm, adapter

    @staticmethod
    def _credentials(profile: ProjectAuthProfile, revision: ProjectAuthProfileRevision) -> Dict[str, Any]:
        binding = ProjectAccountBinding.objects(
            project_id=profile.project_id,
            account_key=revision.project_account_key,
            active=True,
        ).first()
        if not binding or not binding.account_id:
            raise AccountContextUnavailable("project test account binding is unavailable")
        account = TestAccount.objects(
            account_id=binding.account_id, lifecycle=TestAccount.ACTIVE,
        ).first()
        if not account or not account.current_credential_version_id:
            raise AccountContextUnavailable("test account credential is unavailable")
        credential = CredentialVersion.objects(
            credential_version_id=account.current_credential_version_id,
            account_id=account.account_id,
        ).first()
        if not credential:
            raise AccountContextUnavailable("test account credential version is unavailable")
        result = dict(credential.secret_data or {})
        result.setdefault("username", account.username)
        return result

    @staticmethod
    def _realm_secrets(realm: AuthRealmRevision) -> Dict[str, str]:
        if not realm.secret_version_id:
            return {}
        version = AuthRealmSecretVersion.objects(
            secret_version_id=realm.secret_version_id,
            realm_id=realm.realm_id,
        ).first()
        if not version:
            raise AccountContextInvalid(
                "authentication Realm shared secret version is unavailable"
            )
        return normalize_realm_secret_data(version.secret_data)

    @staticmethod
    def _allowed_business_hosts(profile: ProjectAuthProfile,
                                revision: ProjectAuthProfileRevision) -> List[str]:
        environment = ProjectEnvironment.objects(
            project_id=profile.project_id,
            env_id=profile.env_id,
            active=True,
        ).first()
        environment_origins = set(environment_business_origins(environment))
        restricted_origins = {
            normalize_origin(item) for item in (revision.allowed_business_origins or [])
        }
        restricted_origins.discard("")
        selected = environment_origins if not restricted_origins else environment_origins & restricted_origins
        hosts = sorted({origin_host(item) for item in selected if origin_host(item)})
        if not hosts:
            raise AccountContextInvalid("authentication profile has no permitted business Host")
        return hosts

    def _resolve_loaded_chain(
            self, profile: ProjectAuthProfile,
            revision: ProjectAuthProfileRevision,
            realm: AuthRealmRevision,
            adapter: AuthAdapterVersion,
            reference: AccountContextRef, *,
            record_health: bool = True,
    ) -> AccountContext:
        if reference.effective_context_ref != revision.profile_revision_id:
            raise AccountContextMismatch("account context revision does not match")
        try:
            credentials = self._credentials(profile, revision)
            realm_secrets = self._realm_secrets(realm)
            allowed_hosts = self._allowed_business_hosts(profile, revision)
            result = AuthRecipeExecutor(
                session=self.session,
                timeout_seconds=self.timeout_seconds,
                max_requests=self.max_requests,
            ).execute(
                adapter.recipe,
                credentials,
                realm_auth_origins=realm.auth_origins,
                adapter_auth_origins=adapter.allowed_auth_origins,
                realm_config=realm.config,
                realm_secrets=realm_secrets,
                tls_verify=bool(realm.tls_verify),
            )
            auth_kind = str(revision.auth_kind or result.auth_kind or "mixed").lower()
            headers = dict(result.headers) if auth_kind in {"bearer", "mixed"} else {}
            cookies = dict(result.cookies) if auth_kind in {"cookie", "mixed"} else {}
            authorization = next(
                (value for name, value in headers.items() if str(name).lower() == "authorization"),
                "",
            )
            expires_at = result.expires_at or _token_expiry(authorization)
            if expires_at is None:
                expires_at = utcnow() + dt.timedelta(
                    seconds=max(60, min(int(revision.max_age_seconds or 1800), 86400))
                )
            context = AccountContext(
                project_id=reference.project_id,
                env_id=reference.env_id,
                account_id=reference.account_id,
                provider_id=reference.provider_id,
                context_ref=reference.effective_context_ref,
                headers=headers,
                cookies=cookies,
                auth_kind=auth_kind,
                issued_at=utcnow(),
                expires_at=expires_at,
                allowed_hosts=allowed_hosts,
                metadata={
                    "profile_id": profile.profile_id,
                    "profile_revision_id": revision.profile_revision_id,
                    "realm_revision_id": realm.realm_revision_id,
                    "adapter_version_id": adapter.adapter_version_id,
                    "auth_template": str(adapter.recipe.get("template") or ""),
                    "credential_stage": recipe_output_credential_stage(
                        adapter.recipe,
                    ),
                    "auth_request_count": result.request_count,
                    "tls_verify": bool(realm.tls_verify),
                    "business_identity": dict(result.business_identity),
                },
            )
        except AuthRecipeFailure as exc:
            if record_health:
                _set_profile_health(
                    profile, revision, status="failed", stage=exc.stage,
                    error_code=exc.code,
                    error_summary="{} at {}".format(exc.code, exc.stage),
                )
            raise
        except (AccountContextInvalid, AccountContextUnavailable, AccountContextMismatch) as exc:
            if record_health:
                _set_profile_health(
                    profile, revision, status="failed", stage="preflight",
                    error_code="CONFIG_INVALID", error_summary=str(exc)[:240],
                )
            raise
        except Exception:
            if record_health:
                _set_profile_health(
                    profile, revision, status="failed", stage="runtime",
                    error_code="ADAPTER_RUNTIME_ERROR",
                    error_summary="ADAPTER_RUNTIME_ERROR at runtime",
                )
            raise AuthRecipeFailure(
                "ADAPTER_RUNTIME_ERROR", "runtime",
            ) from None
        if record_health:
            _set_profile_health(
                profile, revision, status="healthy", stage="complete",
                error_code="", error_summary="", verified=True,
            )
        return context.validate(reference)

    def resolve_profile_revision(self, profile: ProjectAuthProfile,
                                 profile_revision_id: str, *,
                                 allow_draft: bool = False,
                                 record_health: bool = False) -> AccountContext:
        """Resolve an explicit candidate only for bounded verification."""
        revision, realm, adapter = self._load_revision_chain(
            profile,
            profile_revision_id,
            allow_draft=allow_draft,
        )
        reference = AccountContextRef(
            project_id=profile.project_id,
            env_id=profile.env_id,
            account_id=revision.project_account_key,
            provider_id=self.provider_id,
            context_ref=revision.profile_revision_id,
        )
        reference.validate()
        return self._resolve_loaded_chain(
            profile, revision, realm, adapter, reference,
            record_health=record_health,
        )

    def resolve(self, reference: AccountContextRef) -> AccountContext:
        reference.validate()
        if reference.provider_id != self.provider_id:
            raise AccountContextMismatch("account context provider does not match")
        profile = self._profile(reference)
        revision, realm, adapter = self._load_revision_chain(profile)
        return self._resolve_loaded_chain(
            profile, revision, realm, adapter, reference,
            record_health=True,
        )


def verify_project_auth_profile(profile_id: str, *, max_requests: int = 6,
                                timeout_seconds: int = 10,
                                session: Any = None,
                                retention_days: int = 7,
                                profile_revision_id: str = "",
                                repair_candidate_id: str = "") -> AuthVerificationAttempt:
    """Perform one explicit, bounded verification without a business request."""
    profile = ProjectAuthProfile.objects(
        profile_id=str(profile_id or ""),
        active=True,
    ).first()
    if not profile or not profile.current_revision_id:
        raise ValueError("认证方案尚未迁移到可验证版本")
    selected_revision_id = str(profile_revision_id or profile.current_revision_id or "")
    is_candidate = selected_revision_id != str(profile.current_revision_id or "")
    is_recipe = profile.provider_id == AUTH_RECIPE_PROVIDER_ID
    if is_candidate and not is_recipe:
        raise ValueError("快捷 Provider 不支持候选 Revision 验证")
    candidate = None
    if is_candidate:
        candidate = AuthRepairCandidate.objects(
            candidate_id=str(repair_candidate_id or ""),
            profile_id=profile.profile_id,
            candidate_profile_revision_id=selected_revision_id,
            status__in=[
                AuthRepairCandidate.DRAFT,
                AuthRepairCandidate.VALIDATING,
                AuthRepairCandidate.FAILED,
            ],
        ).first()
        if not candidate:
            raise ValueError("认证候选不存在、已过期或不属于当前方案")
        if candidate.previous_profile_revision_id != str(profile.current_revision_id or ""):
            candidate.status = AuthRepairCandidate.STALE
            candidate.failure_code = "PROFILE_REVISION_CHANGED"
            candidate.mtime = utcnow()
            candidate.save()
            raise ValueError("当前认证方案已变化，请基于新版本重新创建修复候选")
    if is_recipe:
        revision, realm, adapter = RecipeAccountContextProvider._load_revision_chain(
            profile,
            selected_revision_id,
            allow_draft=is_candidate,
        )
    else:
        revision, realm, adapter = _current_profile_chain(profile)
        if (
                not revision or revision.profile_revision_id != selected_revision_id
                or not realm or not adapter):
            raise ValueError("认证方案版本链不完整")
        if str(realm.lifecycle or "draft") not in {"validated", "active"}:
            raise ValueError("认证 Realm 版本尚未激活")
        if str(adapter.lifecycle or "draft") not in {"validated", "active"}:
            raise ValueError("认证 Adapter 版本尚未激活")
    attempt = AuthVerificationAttempt(
        attempt_id="auth-check-{}".format(secrets.token_hex(10)),
        profile_id=profile.profile_id,
        profile_revision_id=revision.profile_revision_id,
        realm_revision_id=realm.realm_revision_id,
        adapter_version_id=adapter.adapter_version_id,
        status="running",
        stage="preflight",
        max_requests=max(1, min(int(max_requests), 6)),
        is_candidate=is_candidate,
        repair_candidate_id=candidate.candidate_id if candidate else "",
        previous_profile_revision_id=(
            candidate.previous_profile_revision_id if candidate else ""
        ),
        expires_at=utcnow() + dt.timedelta(days=max(1, min(int(retention_days), 30))),
    )
    attempt.save(force_insert=True)
    _set_profile_health(
        profile, revision, status="verifying", stage="preflight",
        attempt_id=attempt.attempt_id,
        update_profile_projection=not is_candidate,
    )
    try:
        if is_recipe:
            context = RecipeAccountContextProvider(
                max_requests=attempt.max_requests,
                timeout_seconds=timeout_seconds,
                session=session,
            ).resolve_profile_revision(
                profile,
                revision.profile_revision_id,
                allow_draft=is_candidate,
                record_health=False,
            )
        else:
            reference = AccountContextRef(
                project_id=profile.project_id,
                env_id=profile.env_id,
                account_id=revision.project_account_key,
                provider_id=profile.provider_id,
                context_ref=revision.profile_revision_id,
            )
            if profile.provider_id == TOKEN_ENDPOINT_PROVIDER_ID:
                provider = TokenEndpointProvider(
                    provider_id=TOKEN_ENDPOINT_PROVIDER_ID,
                    session=session,
                    material_loader=lambda value: load_versioned_auth_material(
                        value, TOKEN_ENDPOINT_PROVIDER_ID,
                    ),
                )
            elif profile.provider_id == USER_CODE_PROVIDER_ID:
                provider = CodeAccountContextProvider(
                    provider_id=USER_CODE_PROVIDER_ID,
                    material_loader=lambda value: load_versioned_auth_material(
                        value, USER_CODE_PROVIDER_ID,
                    ),
                )
            else:
                raise AccountContextInvalid(
                    "authentication provider does not support explicit verification"
                )
            context = provider.resolve(reference)
        request_count = int((context.metadata or {}).get("auth_request_count") or 0)
    except AuthRecipeFailure as exc:
        attempt.status = "failed"
        attempt.stage = exc.stage
        attempt.request_count = exc.request_count
        attempt.error_code = exc.code
        attempt.error_summary = "{} at {}".format(exc.code, exc.stage)
        attempt.diagnostics = list(exc.diagnostics)
        attempt.finished_at = utcnow()
        attempt.save()
        _set_profile_health(
            profile, revision, status="failed", stage=exc.stage,
            error_code=exc.code, error_summary=attempt.error_summary,
            attempt_id=attempt.attempt_id,
            update_profile_projection=not is_candidate,
        )
        return attempt
    except (AccountContextInvalid, AccountContextUnavailable, AccountContextMismatch) as exc:
        attempt.status = "failed"
        attempt.stage = "preflight"
        attempt.error_code = "CONFIG_INVALID"
        attempt.error_summary = str(exc)[:240]
        attempt.finished_at = utcnow()
        attempt.save()
        _set_profile_health(
            profile, revision, status="failed", stage=attempt.stage,
            error_code=attempt.error_code, error_summary=attempt.error_summary,
            attempt_id=attempt.attempt_id,
            update_profile_projection=not is_candidate,
        )
        return attempt
    attempt.status = "succeeded"
    attempt.stage = "complete"
    attempt.request_count = request_count
    attempt.error_code = ""
    attempt.error_summary = ""
    attempt.diagnostics = [{
        "stage": "complete",
        "status": "authenticated",
        "header_names": sorted(context.headers),
        "cookie_names": sorted(context.cookies),
    }]
    attempt.finished_at = utcnow()
    attempt.save()
    _set_profile_health(
        profile, revision, status="healthy", stage="complete",
        attempt_id=attempt.attempt_id, verified=True,
        update_profile_projection=not is_candidate,
    )
    return attempt


def activate_auth_repair_candidate(
        candidate_id: str, verification_attempt_id: str) -> ProjectAuthProfile:
    """Atomically switch one profile only after its candidate verified."""
    candidate = AuthRepairCandidate.objects(
        candidate_id=str(candidate_id or ""),
        status__in=[AuthRepairCandidate.VALIDATING, AuthRepairCandidate.FAILED],
    ).first()
    if not candidate:
        candidate = AuthRepairCandidate.objects(
            candidate_id=str(candidate_id or ""),
            status=AuthRepairCandidate.ACTIVATED,
        ).first()
        if candidate:
            profile = ProjectAuthProfile.objects(profile_id=candidate.profile_id).first()
            if profile and profile.current_revision_id == candidate.candidate_profile_revision_id:
                return profile
        raise ValueError("authentication repair candidate is unavailable")
    attempt = AuthVerificationAttempt.objects(
        attempt_id=str(verification_attempt_id or ""),
        repair_candidate_id=candidate.candidate_id,
        profile_revision_id=candidate.candidate_profile_revision_id,
        status="succeeded",
    ).first()
    if not attempt:
        raise ValueError("authentication repair candidate has not passed verification")
    profile = ProjectAuthProfile.objects(
        profile_id=candidate.profile_id,
        project_id=candidate.project_id,
        env_id=candidate.env_id,
        active=True,
    ).first()
    if not profile:
        raise ValueError("authentication profile is unavailable")
    revision, realm, adapter = RecipeAccountContextProvider._load_revision_chain(
        profile,
        candidate.candidate_profile_revision_id,
        allow_draft=True,
    )
    metadata = dict(profile.metadata or {})
    metadata["max_age_seconds"] = int(revision.max_age_seconds or 1800)
    allowed_hosts = sorted({
        origin_host(item) for item in (revision.allowed_business_origins or [])
        if origin_host(item)
    })
    now = utcnow()
    activated = ProjectAuthProfile.objects(
        id=profile.id,
        current_revision_id=candidate.previous_profile_revision_id,
        active=True,
    ).modify(
        new=True,
        set__current_revision_id=revision.profile_revision_id,
        set__context_ref=revision.profile_revision_id,
        set__account_key=revision.project_account_key,
        set__provider_id=AUTH_RECIPE_PROVIDER_ID,
        set__auth_kind=revision.auth_kind,
        set__refresh_strategy=revision.refresh_strategy,
        set__allowed_hosts=allowed_hosts,
        set__metadata=metadata,
        set__last_refresh_at=attempt.finished_at or now,
        set__last_error_type="",
        set__mtime=now,
    )
    if not activated:
        profile.reload()
        if profile.current_revision_id != revision.profile_revision_id:
            candidate.status = AuthRepairCandidate.STALE
            candidate.failure_code = "PROFILE_REVISION_CHANGED"
            candidate.mtime = now
            candidate.save()
            raise ValueError("authentication profile changed while the candidate was verifying")
        activated = profile
    AuthAdapterVersion.objects(
        adapter_version_id=adapter.adapter_version_id,
    ).update_one(set__lifecycle="active")
    AuthAdapter.objects(adapter_id=adapter.adapter_id).update_one(
        set__lifecycle="active", set__mtime=now,
    )
    AuthRealmRevision.objects(
        realm_revision_id=realm.realm_revision_id,
    ).update_one(set__lifecycle="active")
    if realm.secret_version_id:
        AuthRealmSecretVersion.objects(
            secret_version_id=realm.secret_version_id,
            realm_id=realm.realm_id,
        ).update_one(set__lifecycle="active")
    AuthRealm.objects(realm_id=realm.realm_id).update_one(
        set__lifecycle="active",
        set__current_revision_id=realm.realm_revision_id,
        set__mtime=now,
    )
    candidate.status = AuthRepairCandidate.ACTIVATED
    candidate.verification_attempt_id = attempt.attempt_id
    candidate.failure_code = ""
    candidate.activated_at = now
    candidate.mtime = now
    candidate.activation_summary = {
        "profile_revision_id": revision.profile_revision_id,
        "realm_revision_id": realm.realm_revision_id,
        "adapter_version_id": adapter.adapter_version_id,
        "verification_request_count": int(attempt.request_count or 0),
    }
    candidate.save()
    return activated


def verify_and_activate_auth_repair_candidate(
        candidate_id: str, *, max_requests: int = 3,
        timeout_seconds: int = 10, session: Any = None,
) -> Tuple[AuthRepairCandidate, AuthVerificationAttempt, Optional[ProjectAuthProfile]]:
    """Validate a draft candidate and activate it only on success."""
    candidate = AuthRepairCandidate.objects(
        candidate_id=str(candidate_id or ""),
        status__in=[
            AuthRepairCandidate.DRAFT,
            AuthRepairCandidate.FAILED,
            AuthRepairCandidate.VALIDATING,
        ],
    ).first()
    if not candidate:
        raise ValueError("authentication repair candidate is unavailable")
    candidate.status = AuthRepairCandidate.VALIDATING
    candidate.failure_code = ""
    candidate.mtime = utcnow()
    candidate.save()
    attempt = verify_project_auth_profile(
        candidate.profile_id,
        profile_revision_id=candidate.candidate_profile_revision_id,
        repair_candidate_id=candidate.candidate_id,
        max_requests=max_requests,
        timeout_seconds=timeout_seconds,
        session=session,
    )
    candidate.reload()
    candidate.verification_attempt_id = attempt.attempt_id
    candidate.mtime = utcnow()
    if attempt.status != "succeeded":
        candidate.status = AuthRepairCandidate.FAILED
        candidate.failure_code = attempt.error_code or "ADAPTER_RUNTIME_ERROR"
        candidate.save()
        return candidate, attempt, None
    candidate.save()
    profile = activate_auth_repair_candidate(
        candidate.candidate_id,
        attempt.attempt_id,
    )
    candidate.reload()
    return candidate, attempt, profile


def _auth_revision_context(profile: ProjectAuthProfile,
                           revision: ProjectAuthProfileRevision,
                           realm: AuthRealmRevision) -> Dict[str, str]:
    return {
        "project_id": str(profile.project_id or ""),
        "env_id": str(profile.env_id or ""),
        "account_id": str(revision.project_account_key or ""),
        "auth_mode": "account",
        "auth_provider_id": AUTH_RECIPE_PROVIDER_ID,
        "auth_context_ref": revision.profile_revision_id,
        "auth_profile_revision_id": revision.profile_revision_id,
        "auth_realm_revision_id": realm.realm_revision_id,
        "auth_adapter_version_id": realm.adapter_version_id,
    }


def _clone_snapshot_for_auth_revision(
        snapshot: request_snapshot, *,
        profile: ProjectAuthProfile,
        previous_revision_id: str,
        new_context: Mapping[str, str],
        repair_candidate_id: str,
) -> Tuple[request_snapshot, bool]:
    metadata = copy.deepcopy(dict(snapshot.metadata or {}))
    plan = metadata.get("validation_plan")
    changed = str(snapshot.auth_profile_revision_id or "") == previous_revision_id
    if isinstance(plan, Mapping):
        plan = copy.deepcopy(dict(plan))
        for role in ("source", "consumer"):
            role_auth = dict(plan.get(role + "_auth") or {})
            role_profile_id = str(plan.get(role + "_profile_id") or "")
            if (
                    role_profile_id == profile.profile_id
                    or str(role_auth.get("auth_profile_revision_id") or "") == previous_revision_id
                    or str(role_auth.get("auth_context_ref") or "") == previous_revision_id):
                plan[role + "_auth"] = dict(new_context)
                changed = True
        metadata["validation_plan"] = plan
    if not changed:
        return snapshot, False
    values: Dict[str, Any] = {}
    for field_name in request_snapshot._fields:
        if field_name == "id":
            continue
        value = getattr(snapshot, field_name, None)
        values[field_name] = (
            copy.deepcopy(value) if isinstance(value, (dict, list, tuple)) else value
        )
    values.update({
        "account_id": new_context["account_id"],
        "auth_mode": "account",
        "auth_provider_id": new_context["auth_provider_id"],
        "auth_context_ref": new_context["auth_context_ref"],
        "auth_profile_revision_id": new_context["auth_profile_revision_id"],
        "auth_realm_revision_id": new_context["auth_realm_revision_id"],
        "auth_adapter_version_id": new_context["auth_adapter_version_id"],
        "metadata": metadata,
        "template_key": None,
        "ctime": utcnow(),
    })
    values["metadata"]["auth_repair_rebind"] = {
        "candidate_id": repair_candidate_id,
        "previous_profile_revision_id": previous_revision_id,
        "profile_revision_id": new_context["auth_profile_revision_id"],
    }
    clone = request_snapshot(**values)
    clone.save(force_insert=True)
    return clone, True


def rebind_zero_progress_auth_run(
        run_id: Any, candidate_id: str) -> security_test_run:
    """Rebind one paused, request-free run to an activated auth revision.

    Existing snapshots are never edited.  Run-specific clones receive the new
    version references; checkpoints are remapped while the run remains paused,
    and the caller may then use the existing exact CAS resume function.
    """
    try:
        object_id = ObjectId(str(run_id))
    except Exception:
        raise ValueError("paused run id is invalid") from None
    candidate = AuthRepairCandidate.objects(
        candidate_id=str(candidate_id or ""),
        status=AuthRepairCandidate.ACTIVATED,
    ).first()
    if not candidate:
        raise ValueError("authentication repair candidate is not activated")
    profile = ProjectAuthProfile.objects(
        profile_id=candidate.profile_id,
        current_revision_id=candidate.candidate_profile_revision_id,
        active=True,
    ).first()
    if not profile:
        raise ValueError("activated authentication profile is unavailable")
    revision, realm, _adapter = RecipeAccountContextProvider._load_revision_chain(
        profile,
        candidate.candidate_profile_revision_id,
    )
    run = security_test_run.objects(
        id=object_id,
        scheduler_managed=True,
        status=security_test_run.PAUSED,
    ).first()
    if not run:
        existing = security_test_run.objects(id=object_id).first()
        if (
                existing
                and existing.auth_profile_revision_id == revision.profile_revision_id
                and existing.status in {security_test_run.PAUSED, security_test_run.QUEUED}):
            return existing
        raise ValueError("paused run is unavailable")
    if run.project_id != profile.project_id or run.env_id != profile.env_id:
        raise ValueError("paused run belongs to another project or environment")
    if (
            run.dependency_type != "auth_profile"
            or str(run.dependency_id or "") != candidate.previous_profile_revision_id
            or str(run.auth_profile_revision_id or "") != candidate.previous_profile_revision_id):
        raise ValueError("paused run is waiting for another authentication revision")
    counters = (
        run.running_cases, run.completed_cases, run.failed_cases,
        run.skipped_cases, run.cancelled_cases,
    )
    if any(int(value or 0) for value in counters):
        raise ValueError("paused run already has execution progress and cannot be rebound")
    if security_test_result.objects(run_id=run.id).count():
        raise ValueError("paused run already has results and cannot be rebound")
    old_snapshot_ids = list(run.snapshot_ids or [])
    snapshots = list(request_snapshot.objects(id__in=old_snapshot_ids))
    by_id = {item.id: item for item in snapshots}
    if not old_snapshot_ids or len(by_id) != len(old_snapshot_ids):
        raise ValueError("paused run snapshots are incomplete")
    checkpoints = list(security_execution_checkpoint.objects(
        run_id=run.id,
    ).order_by("ordinal"))
    if len(checkpoints) != len(old_snapshot_ids):
        raise ValueError("paused run checkpoints are incomplete")
    for ordinal, checkpoint in enumerate(checkpoints):
        if (
                checkpoint.status != security_execution_checkpoint.PENDING
                or int(checkpoint.attempt_count or 0)
                or checkpoint.result_id
                or checkpoint.snapshot_id != old_snapshot_ids[ordinal]):
            raise ValueError("paused run already entered business execution")

    new_context = _auth_revision_context(profile, revision, realm)
    new_snapshot_ids: List[ObjectId] = []
    created_clones: List[request_snapshot] = []
    changed_pairs: List[Tuple[ObjectId, ObjectId, int]] = []
    for ordinal, old_id in enumerate(old_snapshot_ids):
        clone, changed = _clone_snapshot_for_auth_revision(
            by_id[old_id],
            profile=profile,
            previous_revision_id=candidate.previous_profile_revision_id,
            new_context=new_context,
            repair_candidate_id=candidate.candidate_id,
        )
        new_snapshot_ids.append(clone.id)
        if changed:
            created_clones.append(clone)
            changed_pairs.append((old_id, clone.id, ordinal))
    if not changed_pairs:
        raise ValueError("paused run contains no references to the repaired profile")

    new_scope = copy.deepcopy(dict(run.scope or {}))
    new_scope["auth_repair"] = {
        "candidate_id": candidate.candidate_id,
        "previous_profile_revision_id": candidate.previous_profile_revision_id,
        "profile_revision_id": revision.profile_revision_id,
    }
    changed = security_test_run.objects(
        id=run.id,
        status=security_test_run.PAUSED,
        dependency_type="auth_profile",
        dependency_id=candidate.previous_profile_revision_id,
        auth_profile_revision_id=candidate.previous_profile_revision_id,
        running_cases=0,
        completed_cases=0,
        failed_cases=0,
        skipped_cases=0,
        cancelled_cases=0,
    ).update_one(
        set__snapshot_ids=new_snapshot_ids,
        set__profile_id=profile.profile_id,
        set__account_id=revision.project_account_key,
        set__auth_provider_id=AUTH_RECIPE_PROVIDER_ID,
        set__auth_context_ref=revision.profile_revision_id,
        set__auth_profile_revision_id=revision.profile_revision_id,
        set__auth_realm_revision_id=realm.realm_revision_id,
        set__auth_adapter_version_id=realm.adapter_version_id,
        set__dependency_id=revision.profile_revision_id,
        set__dependency_revision_id=revision.profile_revision_id,
        set__scope=new_scope,
        set__updated_at=utcnow(),
    )
    if not changed:
        request_snapshot.objects(id__in=[item.id for item in created_clones]).delete()
        raise ValueError("paused run changed while authentication was being repaired")

    remapped: List[Tuple[ObjectId, ObjectId, int]] = []
    try:
        for old_id, new_id, ordinal in changed_pairs:
            checkpoint_changed = security_execution_checkpoint.objects(
                run_id=run.id,
                ordinal=ordinal,
                status=security_execution_checkpoint.PENDING,
                attempt_count=0,
                snapshot_id=old_id,
            ).update_one(
                set__snapshot_id=new_id,
                set__updated_at=utcnow(),
            )
            if not checkpoint_changed:
                raise ValueError("paused run checkpoint changed during authentication repair")
            remapped.append((old_id, new_id, ordinal))
    except Exception:
        for old_id, new_id, ordinal in reversed(remapped):
            security_execution_checkpoint.objects(
                run_id=run.id, ordinal=ordinal, snapshot_id=new_id,
            ).update_one(set__snapshot_id=old_id, set__updated_at=utcnow())
        security_test_run.objects(
            id=run.id,
            status=security_test_run.PAUSED,
            auth_profile_revision_id=revision.profile_revision_id,
        ).update_one(
            set__snapshot_ids=old_snapshot_ids,
            set__auth_context_ref=candidate.previous_profile_revision_id,
            set__auth_profile_revision_id=candidate.previous_profile_revision_id,
            set__dependency_id=candidate.previous_profile_revision_id,
            set__dependency_revision_id=candidate.previous_profile_revision_id,
            set__scope=run.scope or {},
            set__updated_at=utcnow(),
        )
        request_snapshot.objects(id__in=[item.id for item in created_clones]).delete()
        raise

    candidate.resume_run_id = str(run.id)
    candidate.rebind_status = "rebound"
    summary = dict(candidate.activation_summary or {})
    summary.update({
        "rebound_run_id": str(run.id),
        "snapshot_clone_count": len(created_clones),
        "business_result_count_before_rebind": 0,
    })
    candidate.activation_summary = summary
    candidate.mtime = utcnow()
    candidate.save()
    return security_test_run.objects(id=run.id).first()


def auth_repair_defaults(profile: ProjectAuthProfile) -> Dict[str, Any]:
    """Project the current Recipe into the progressive repair form."""
    defaults: Dict[str, Any] = {
        "method": "POST",
        "request_format": "json",
        "username_field": "account",
        "password_field": "password",
        "password_transform": "plain",
        "token_source": "json",
        "token_path": "access_token",
        "token_header": "Authorization",
        "token_prefix": "Bearer",
        "auth_kind": str(profile.auth_kind or "mixed"),
        "include_session_cookies": profile.auth_kind in {"cookie", "mixed"},
        "success_statuses": "200",
        "error_json_path": "",
        "extra_fields_json": "{}",
        "max_age_seconds": 1800,
        "max_requests": 3,
        "tls_verify": True,
        "login_url": "",
        "sso_authorization_url": "",
        "token_login_url": "",
        "product_verification_url": "",
        "client_token_secret_name": "client_token",
        "browser_id": "",
        "browser_type": "chrome",
        "sso_token_path": "access_token",
        "product_token_path": "access_token",
        "auth_origins": "",
        "recipe_json": "",
        "template": "",
        "realm_secret_keys": [],
        "rsa_public_key_secret_name": "login_rsa_public_key",
        "rsa_public_key": "",
        "rsa_append_timestamp": False,
        "rsa_timestamp_delimiter": "###",
        "rsa_timestamp_unit": "seconds",
    }
    try:
        revision, realm, adapter = RecipeAccountContextProvider._load_revision_chain(profile)
        recipe = copy.deepcopy(dict(adapter.recipe or {}))
        _assert_recipe_contains_no_literal_secrets(recipe)
        defaults.update({
            "auth_kind": str((recipe.get("output") or {}).get("auth_kind") or revision.auth_kind),
            "max_age_seconds": int(revision.max_age_seconds or 1800),
            "max_requests": max(
                1, min(6, sum(
                    1 if item.get("type") == "http" else (
                        max(1, min(int(item.get("max_attempts") or 1), 6))
                        if item.get("type") == "mfa_receive"
                        and str(item.get("mode") or "pull").lower() == "pull"
                        else 0
                    )
                    for item in (recipe.get("steps") or [])
                )),
            ),
            "tls_verify": bool(realm.tls_verify),
            "auth_origins": "\n".join(realm.auth_origins or []),
            "recipe_json": json.dumps(recipe, ensure_ascii=False, indent=2),
            "template": str(recipe.get("template") or ""),
            "realm_secret_keys": realm_secret_key_names(realm),
        })
        http_step = next(
            (item for item in (recipe.get("steps") or []) if item.get("type") == "http"),
            {},
        )
        defaults["login_url"] = str(http_step.get("url") or "")
        defaults["method"] = str(http_step.get("method") or "POST").upper()
        request_format = next(
            (name for name in ("json", "form", "query") if name in http_step),
            "json",
        )
        defaults["request_format"] = request_format
        payload = copy.deepcopy(dict(http_step.get(request_format) or {}))
        for field_name, field_value in list(payload.items()):
            if field_value == "{{credential.username}}":
                defaults["username_field"] = field_name
                payload.pop(field_name, None)
            elif field_value in {"{{credential.password}}", "{{vars.login_password}}"}:
                defaults["password_field"] = field_name
                payload.pop(field_name, None)
        for step in recipe.get("steps") or []:
            if step.get("type") == "set" and step.get("target") == "login_password":
                operation = str(step.get("operation") or "plain")
                defaults["password_transform"] = (
                    "rsa_pkcs1v15" if operation == "rsa_encrypt" else operation
                )
                if operation == "rsa_encrypt":
                    public_key = str(step.get("public_key") or "")
                    match = _REALM_SECRET_TEMPLATE.fullmatch(public_key)
                    if match:
                        defaults["rsa_public_key_secret_name"] = match.group(1)
        rsa_plaintext_step = next((
            item for item in (recipe.get("steps") or [])
            if item.get("type") == "set"
            and item.get("target") == "rsa_plaintext"
            and item.get("operation") == "concat"
        ), None)
        if rsa_plaintext_step:
            values = list(rsa_plaintext_step.get("values") or [])
            defaults["rsa_append_timestamp"] = True
            if len(values) >= 2:
                defaults["rsa_timestamp_delimiter"] = str(values[1])
            timestamp_step = next((
                item for item in (recipe.get("steps") or [])
                if item.get("type") == "set"
                and item.get("target") == "login_timestamp"
            ), {})
            defaults["rsa_timestamp_unit"] = str(
                timestamp_step.get("unit") or "seconds"
            )
        defaults["extra_fields_json"] = json.dumps(
            sanitize_protocol_fields(payload), ensure_ascii=False, indent=2,
        )
        extract = dict(http_step.get("extract") or {})
        token_target, token_rule = next(iter(extract.items()), ("", {}))
        if token_target:
            rule = token_rule if isinstance(token_rule, Mapping) else {
                "source": "json", "path": str(token_rule),
            }
            defaults["token_source"] = str(rule.get("source") or "json")
            defaults["token_path"] = str(rule.get("path") or rule.get("name") or "")
        output_headers = dict((recipe.get("output") or {}).get("headers") or {})
        for name, value in output_headers.items():
            marker = "{{vars." + (token_target or "access_token") + "}}"
            if marker in str(value):
                defaults["token_header"] = str(name)
                defaults["token_prefix"] = str(value).replace(marker, "").strip()
                break
        defaults["include_session_cookies"] = bool(
            (recipe.get("output") or {}).get("include_session_cookies")
        )
        defaults["success_statuses"] = ",".join(
            str(item) for item in (http_step.get("success_statuses") or [200])
        )
        defaults["error_json_path"] = str(http_step.get("json_error_path") or "")
        if defaults["template"] == "sso_session_product_token_v1":
            steps_by_id = {
                str(item.get("id") or ""): item
                for item in (recipe.get("steps") or [])
                if isinstance(item, Mapping)
            }
            authorization_step = steps_by_id.get("sso_authorization") or {}
            session_step = steps_by_id.get("establish_session") or {}
            product_step = steps_by_id.get("product_verification") or {}
            defaults.update({
                "sso_authorization_url": str(authorization_step.get("url") or ""),
                "token_login_url": str(session_step.get("url") or ""),
                "product_verification_url": str(product_step.get("url") or ""),
            })
            authorization_extract = dict(
                authorization_step.get("extract") or {},
            ).get("sso_access_token") or {}
            if isinstance(authorization_extract, Mapping):
                defaults["sso_token_path"] = str(
                    authorization_extract.get("path") or "access_token"
                )
            product_extract = dict(
                product_step.get("extract") or {},
            ).get("product_access_token") or {}
            if isinstance(product_extract, Mapping):
                defaults["product_token_path"] = str(
                    product_extract.get("path") or "access_token"
                )
            product_body = dict(product_step.get("json") or {})
            defaults["browser_id"] = str(product_body.get("browserid") or "")
            defaults["browser_type"] = str(
                product_body.get("browsertype") or "chrome"
            )
            secret_names = recipe_secret_names(recipe)
            if secret_names:
                defaults["client_token_secret_name"] = secret_names[0]
    except (AccountContextInvalid, ValueError):
        pass
    return defaults


def register_project_auth_providers(resolver: Any) -> Any:
    """Keep existing providers available while P0-B profiles cut over one by one."""
    register_database_sso_provider(resolver)
    resolver.register(RecipeAccountContextProvider())
    resolver.register(TokenEndpointProvider(
        provider_id=TOKEN_ENDPOINT_PROVIDER_ID,
        material_loader=lambda reference: load_versioned_auth_material(
            reference, TOKEN_ENDPOINT_PROVIDER_ID,
        ),
    ))
    resolver.register(CodeAccountContextProvider(
        provider_id=USER_CODE_PROVIDER_ID,
        material_loader=lambda reference: load_versioned_auth_material(
            reference, USER_CODE_PROVIDER_ID,
        ),
    ))
    return resolver
