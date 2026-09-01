"""Universal auth configuration: recipe import + code provider + AI prompt template.

Three paths to configure authentication for any login protocol:
  1. AI-generated Recipe JSON → one-click import
  2. User-provided Python code → CodeAccountContextProvider
  3. Simple password login → existing build_password_login_recipe
"""
import hashlib
import json
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit

from .account_context import validate_trusted_auth_code
from .auth_recipe import normalize_origin
from .project_auth import (
    AUTH_RECIPE_PROVIDER_ID,
    TOKEN_ENDPOINT_PROVIDER_ID,
    USER_CODE_PROVIDER_ID,
    import_versioned_auth_profile,
    recipe_capabilities,
    validate_repair_recipe,
)

def _sha(obj: Any) -> str:
    return hashlib.sha256(
        json.dumps(obj, sort_keys=True, ensure_ascii=False).encode()
    ).hexdigest()


def import_recipe_as_profile(
    *,
    project_id: str,
    env_id: str,
    profile_name: str,
    recipe: Dict[str, Any],
    realm_secrets: Optional[Dict[str, str]] = None,
    auth_origins: Optional[List[str]] = None,
    business_origins: Optional[List[str]] = None,
    account_key: str = "owner",
    auth_kind: str = "mixed",
    max_age_seconds: int = 1800,
    tls_verify: bool = True,
    activate: bool = True,
    recipe_key: str = "",
    realm_key: str = "",
    login_scene: str = "",
    role_key: str = "",
    login_mode: str = "recipe",
) -> Dict[str, str]:
    """One-click import a Recipe into one independently selectable Profile.

    Multiple login scenes/roles/modes may be active in the same project.  The
    Recipe artifact is immutable and content-addressed, while only this
    Profile's current revision pointer is switched.
    """
    if not activate:
        raise ValueError("quick Recipe import always activates the selected Profile")
    normalized_recipe, selected_origins = validate_repair_recipe(
        recipe, auth_origins or (),
    )
    selected_auth_kind = str(
        auth_kind or (normalized_recipe.get("output") or {}).get("auth_kind") or "mixed"
    ).lower()
    return import_versioned_auth_profile(
        project_id=project_id,
        env_id=env_id,
        profile_name=profile_name,
        account_key=account_key,
        provider_id=AUTH_RECIPE_PROVIDER_ID,
        adapter_type="recipe",
        adapter_key=recipe_key,
        realm_key=realm_key,
        artifact=normalized_recipe,
        auth_origins=selected_origins,
        allowed_business_origins=business_origins or (),
        login_scene=login_scene,
        role_key=role_key,
        login_mode=login_mode,
        auth_kind=selected_auth_kind,
        max_age_seconds=max_age_seconds,
        tls_verify=tls_verify,
        realm_secret_data=realm_secrets,
        capabilities=["recipe"] + recipe_capabilities(normalized_recipe),
    )


def import_token_endpoint_as_profile(
        *, project_id: str, env_id: str, profile_name: str,
        token_url: str, token_method: str = "GET",
        pass_credentials: str = "none", response_path: str = "access_token",
        token_prefix: str = "Bearer ", token_header: str = "Authorization",
        expires_in: int = 1800, account_key: str = "owner",
        business_origins: Optional[List[str]] = None,
        login_scene: str = "", role_key: str = "",
        login_mode: str = "token_url", tls_verify: bool = True,
) -> Dict[str, str]:
    token_url = str(token_url or "").strip()
    parsed = urlsplit(token_url)
    token_origin = normalize_origin(token_url)
    if (
            not token_origin
            or str(parsed.scheme or "").lower() not in {"http", "https"}
            or parsed.username or parsed.password or parsed.fragment):
        raise ValueError("Token URL must be an absolute HTTP(S) URL")
    token_method = str(token_method or "GET").upper()
    if token_method not in {"GET", "POST"}:
        raise ValueError("Token URL method must be GET or POST")
    pass_credentials = str(pass_credentials or "none").lower()
    if pass_credentials not in {"none", "query", "headers", "body"}:
        raise ValueError("Token URL credential mode is invalid")
    expires_in = max(60, min(int(expires_in), 86400))
    config = {
        "token_url": token_url,
        "token_method": token_method,
        "pass_credentials": pass_credentials,
        "response_path": str(response_path or "access_token").strip(),
        "token_prefix": str(token_prefix or ""),
        "token_header": str(token_header or "Authorization").strip(),
        "expires_in": expires_in,
        "timeout_seconds": 15,
        "cookie_names": [],
        "extra_headers": {},
    }
    return import_versioned_auth_profile(
        project_id=project_id,
        env_id=env_id,
        profile_name=profile_name,
        account_key=account_key,
        provider_id=TOKEN_ENDPOINT_PROVIDER_ID,
        adapter_type="token_endpoint",
        adapter_key="{}:{}:{}".format(
            login_scene or profile_name, role_key or "default", login_mode,
        ),
        artifact={
            "schema_version": 1,
            "provider_id": TOKEN_ENDPOINT_PROVIDER_ID,
            "config": config,
        },
        auth_origins=[token_origin],
        allowed_business_origins=business_origins or (),
        login_scene=login_scene,
        role_key=role_key,
        login_mode=login_mode,
        auth_kind="mixed",
        max_age_seconds=expires_in,
        tls_verify=tls_verify,
        capabilities=["http", "external_token"],
    )


def import_code_as_profile(
        *, project_id: str, env_id: str, profile_name: str,
        code_text: str, auth_origins: List[str],
        account_key: str = "owner",
        business_origins: Optional[List[str]] = None,
        login_scene: str = "", role_key: str = "",
        login_mode: str = "trusted_code", tls_verify: bool = True,
        max_age_seconds: int = 1800,
) -> Dict[str, str]:
    code_text = validate_trusted_auth_code(code_text)
    selected_origins = sorted({
        normalize_origin(item) for item in (auth_origins or [])
        if normalize_origin(item)
    })
    if not selected_origins:
        raise ValueError("trusted code requires at least one allowed authentication origin")
    max_age_seconds = max(60, min(int(max_age_seconds), 86400))
    return import_versioned_auth_profile(
        project_id=project_id,
        env_id=env_id,
        profile_name=profile_name,
        account_key=account_key,
        provider_id=USER_CODE_PROVIDER_ID,
        adapter_type="trusted_code",
        adapter_key="{}:{}:{}".format(
            login_scene or profile_name, role_key or "default", login_mode,
        ),
        artifact={
            "schema_version": 1,
            "provider_id": USER_CODE_PROVIDER_ID,
            "source": code_text,
            "source_sha256": _sha(code_text),
            "config": {
                "timeout_seconds": 20,
                "max_requests": 6,
            },
        },
        auth_origins=selected_origins,
        allowed_business_origins=business_origins or (),
        login_scene=login_scene,
        role_key=role_key,
        login_mode=login_mode,
        auth_kind="mixed",
        max_age_seconds=max_age_seconds,
        tls_verify=tls_verify,
        capabilities=["trusted_python", "restricted_http"],
    )


RECIPE_SCHEMA_DOC = """\
# Recipe JSON Schema

A recipe is a JSON object describing a multi-step authentication flow.

## Top-level structure

```json
{
  "schema_version": 1,
  "template": "optional-label",
  "steps": [ ... ],
  "output": { ... }
}
```

## Step types

### `set` — compute a variable
```json
{
  "id": "step_name",
  "type": "set",
  "target": "variable_name",
  "operation": "md5|sha256|base64|concat|unix_time|uuid4|literal|rsa_encrypt",
  "value": "{{credential.password}}",
  "values": ["{{credential.username}}", "{{vars.other_var}}"]
}
```

Operations:
- `literal` — render template string as-is
- `md5` / `sha256` — hash the rendered value
- `base64` — base64-encode the rendered value
- `concat` — concatenate the `values` array
- `unix_time` — current unix timestamp (integer)
- `uuid4` — random UUID string
- `rsa_encrypt` — RSA public-key encryption; set `public_key` to a Realm secret
  reference, `padding` to `pkcs1v15`, `oaep-sha1` or `oaep-sha256`, and
  `output_encoding` to `base64` or `hex`

RSA example:
```json
{
  "id": "encrypt_password",
  "type": "set",
  "target": "login_password",
  "operation": "rsa_encrypt",
  "value": "{{vars.rsa_plaintext}}",
  "public_key": "{{secret.login_rsa_public_key}}",
  "padding": "pkcs1v15",
  "output_encoding": "base64"
}
```

### `http` — make an HTTP request
```json
{
  "id": "step_name",
  "type": "http",
  "method": "POST",
  "url": "https://auth.example.com/login",
  "headers": {"Content-Type": "application/json"},
  "json": {"username": "{{credential.username}}", "password": "{{vars.hashed_pw}}"},
  "query": {"token": "{{vars.access_token}}"},
  "success_statuses": [200, 302],
  "error_status_map": {"401": "CREDENTIAL_REJECTED", "403": "CREDENTIAL_REJECTED"},
  "extract": {
    "access_token": {"source": "json", "path": "access_token", "required": true}
  }
}
```

### `mfa_receive` — obtain a one-time second-factor value

Pull mode calls an exact allowlisted authentication Origin:
```json
{
  "id": "receive_mfa",
  "type": "mfa_receive",
  "mode": "pull",
  "target": "mfa_code",
  "method": "POST",
  "url": "https://receiver.example.com/code",
  "json": {"account": "{{credential.username}}"},
  "success_statuses": [200],
  "extract": {
    "source": "json",
    "list_path": "data",
    "match_path": "type",
    "match_value": "login-2fa",
    "path": "code"
  },
  "max_attempts": 3,
  "poll_interval_seconds": 1
}
```

Push mode waits for a trusted tool to use the MFA receiver API:
```json
{
  "id": "receive_mfa",
  "type": "mfa_receive",
  "mode": "push",
  "receiver_id": "company-otp",
  "correlation": "{{credential.username}}",
  "target": "mfa_code",
  "timeout_seconds": 60
}
```

## Variable references

- `{{credential.username}}` / `{{credential.password}}` — from the test account
- `{{secret.client_token}}` — from the realm secret (shared across accounts)
- `{{vars.step_target}}` — from a previous `set` or `extract` step

## Output

```json
{
  "output": {
    "auth_kind": "bearer|cookie|mixed",
    "headers": {"Authorization": "Bearer {{vars.product_token}}"},
    "cookies": {},
    "include_session_cookies": true,
    "expires_in_seconds": 1800
  }
}
```

## Rules

1. No literal secrets in the recipe — use `{{secret.xxx}}` or `{{credential.xxx}}`
2. Every `http` step must declare `success_statuses`
3. Extracted variables from one step are available in subsequent steps
4. The recipe is validated before import; invalid recipes are rejected
"""

AI_PROMPT_TEMPLATE = """\
你是一个认证配方生成器。根据用户提供的登录信息，生成符合以下 schema 的 recipe JSON。

## Schema 规则

1. 顶层结构: `{"schema_version": 1, "steps": [...], "output": {...}}`
2. 步骤类型: `set`（变量计算）、`http`（HTTP 请求）和 `mfa_receive`（二验接收器）
3. `set` 操作: `md5`, `sha256`, `base64`, `concat`, `unix_time`, `uuid4`, `literal`, `rsa_encrypt`
4. `http` 步骤必须声明 `success_statuses` 和 `error_status_map`
5. 变量引用: `{{credential.username}}`, `{{credential.password}}`, `{{secret.xxx}}`, `{{vars.xxx}}`
6. **禁止明文密钥** — 密码用 `{{credential.password}}`，共享密钥用 `{{secret.xxx}}`
7. `output` 必须声明 `auth_kind` 和 `headers`
8. 需要共享密钥（如 client_token）时，在输出中说明需要哪些 secret keys

## 常见模式

### 简单密码登录
POST 到登录 URL，body 包含 username/password，响应中提取 token。

### MD5 签名 SSO
1. set: md5(password) → hashed_pw
2. set: md5(username + md5(secret) + timestamp) → signature
3. http: POST 授权 URL，body 包含 signature + hashed_pw
4. http: GET 登录 URL?token=xxx（建立会话）
5. 可选 http: POST 产品验证 URL

### OAuth / Token Exchange
1. http: POST 到 token endpoint，提取 access_token
2. output: Authorization: Bearer {{vars.access_token}}

### RSA + 二验
1. set: rsa_encrypt，公钥必须引用 {{secret.xxx}}；协议要求时可先用 unix_time + concat
2. http: 首次登录并提取 challenge
3. 可选 http: 使用 challenge 触发发送验证码
4. mfa_receive: pull 或 push 获取验证码
5. http: 提交 challenge 和验证码，提取最终 access_token

## 用户提供的登录信息

{user_login_info}

## 输出要求

只输出 JSON，不要解释。如果需要共享密钥，在 JSON 后面用注释说明：
// REQUIRED_SECRETS: client_token, app_key
"""
