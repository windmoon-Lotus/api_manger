# api_manger Configuration

进程、CLI、Web 页面和 HTTP API 的统一调用索引见
[`docs/CLI_REFERENCE.md`](docs/CLI_REFERENCE.md)。

This project can still run with the default local settings, but the main runtime
configuration can now be overridden with environment variables.

## Runtime Checks

Run:

```powershell
py -3.9 -m apiAnalysis.main --doctor
```

The command checks:

- Python version
- virtual-environment isolation
- exact direct dependency versions and `pip check`
- MongoDB connection
- Redis connection
- Web upload directory writability
- Optional external tool paths

Missing external tools are reported as `WARN` because their adapters are not
required for the current baseline.

Create the environment from the checked-in lock before diagnosing application
errors:

```powershell
py -3.9 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m pip check
```

Do not install the project into a shared global Python tool environment.
Optional legacy flow capture support is isolated in `requirements-capture.txt`.

## Web Startup

```powershell
py -3.9 .\run_web.py
```

`run_web.py` only starts Flask. Production-like local operation starts durable
work in separate processes:

```powershell
py -3.9 .\tools\run_execution_worker.py
py -3.9 .\tools\run_relation_analysis_worker.py
py -3.9 .\tools\run_maintenance_scheduler.py
```

The Web process never performs business replay, relation jobs, lease recovery,
or completed finding-retest evaluation.

Optional web variables:

```powershell
$env:HOST="0.0.0.0"
$env:PORT="5000"
$env:DEBUG="1"
```

## Core Configuration

```powershell
$env:API_MANAGER_SECRET_KEY="change-me"
$env:API_MANAGER_ADMIN_USERNAME="admin"
$env:API_MANAGER_ADMIN_PASSWORD="use-a-strong-local-password"
$env:API_MANAGER_CORS_ORIGINS="http://127.0.0.1:5000,http://localhost:5000"

$env:API_MANAGER_MONGO_DATABASE="apihandl"
$env:API_MANAGER_MONGO_HOST="127.0.0.1"
$env:API_MANAGER_MONGO_PORT="27017"
$env:API_MANAGER_MONGO_USER=""
$env:API_MANAGER_MONGO_PASSWORD=""

$env:API_MANAGER_REDIS_HOST="127.0.0.1"
$env:API_MANAGER_REDIS_PORT="6379"
$env:API_MANAGER_REDIS_DB="0"
$env:API_MANAGER_REDIS_PASSWORD=""
```

The Web server binds to `127.0.0.1` with debug disabled by default. Historical
`admin/admin123` and `normal/normal123` users are disabled unless
`API_MANAGER_ALLOW_INSECURE_DEFAULT_USERS=1` is explicitly set for a short
local migration window.

`HOST=0.0.0.0` is supported for manual LAN access, but it exposes the
administrator UI on every interface. Use a strong administrator password,
keep `DEBUG=0`, restrict the host firewall, and allow only trusted managers to
install authentication code.

When `run_web.py` starts without `API_MANAGER_ADMIN_PASSWORD`, it generates a
local administrator password and Flask secret once, writes them to
`../.secrets/infrastructure/credentials/api-manager-web.local.env`, and prints the password only during
that first generation. Later starts load the file silently. Override the path
with `API_MANAGER_WEB_CREDENTIALS_FILE`; explicit credential environment
variables always win and are not copied into the generated file.

## Versioned Authentication Workbench (Preferred)

New project authentication does not read a global SSO URL. Open:

```text
项目环境与认证
-> 选择认证方案
-> 高级认证 / 修复认证域
```

The workbench has three explicit modes:

- **Common username/password login**: one JSON/Form/Query login request, then
  extract a Bearer token, Cookie, or both.
- **Three-step SSO + product token**: an advanced built-in template. Configure the SSO
  authorization URL, token-login URL, product-verification URL, Realm Client
  Token secret name, and browser identity. It performs exactly three auth
  requests: get the SSO token, establish the Session Cookie, and exchange for
  the product token. The final context contains the product Bearer token plus
  the Session Cookie and is marked `credential_stage=product`. Business
  runners can fail closed instead of accidentally reusing the intermediate SSO
  token.
- **Custom declarative Recipe**: for other multi-step SSO protocols. It can use
  bounded transforms, RSA public-key encryption, HTTP auth steps, pull/push MFA
  receivers, Cookie Jar, and result extraction; it cannot execute Python,
  JavaScript, or Shell.

The Realm Client Token belongs to the authentication Realm rather than one test
account. It is saved in an immutable `AuthRealmSecretVersion`; leaving the
field blank reuses the current version. A Recipe references shared values by
name, for example `{{secret.client_token}}`. Secret values are never copied
into the Recipe, page output, verification evidence, tasks, results, or logs.

Saving creates and verifies a candidate. Verification sends only the auth
requests listed in the preview and sends no business request. Failure keeps
the current Profile/Realm/Recipe active; success atomically switches to the
candidate.

## Quick Authentication Import

Open `/auth-import` for the personal-deployment shortcuts:

- **Token URL** reuses an existing script, browser helper, OTP/MFA tool, or
  local service that already knows how to obtain a Token.
- **Recipe one-click import** performs bounded static validation and activates
  only the selected login Profile. It sends no request during import.
- **Administrator-trusted code** runs `get_auth(username, password)` in a
  bounded subprocess with an origin-restricted GET/POST client.

A project can have many active login Profiles. They are separated by login
scene, role, login mode, and account alias. Recipe content is immutable only so
historical executions keep their original meaning; changing a Recipe creates a
new version and switches only the selected Profile. Different `recipe_key`
values coexist, while the same key and unchanged content are idempotent.

Trusted code is a manager-installed local plugin, not a hostile-code sandbox.
It is enabled by default for this personal project and can be disabled:

```powershell
$env:API_MANAGER_ALLOW_TRUSTED_AUTH_CODE="0"
```

See [`docs/auth_import.md`](docs/auth_import.md) for the complete Profile,
Recipe, Token URL, code-runtime, and listening-address contract.

## MFA Receiver API

`mfa_receive` Recipe steps support two modes. `pull` actively calls an exact
Realm authentication Origin and extracts a code from JSON, a response Header,
a Cookie, or the response text. `push` creates a short-lived pending
transaction for a trusted external tool.

Enable the push API with a random local secret:

```powershell
$env:API_MANAGER_MFA_RECEIVER_TOKEN="<at-least-16-random-characters>"
```

The tool uses `Authorization: Bearer <random-token>` with:

```text
GET  /api/auth/mfa-receiver/pending?receiver_id=<receiver-id>
POST /api/auth/mfa-receiver/push
```

The POST body contains `transaction_id` and `code`. The API never echoes the
code. In the default single-process mode, codes remain only in memory. For a
Web/worker multi-process deployment, configure the same explicit Redis URL and
receiver token in every process:

```powershell
$env:API_MANAGER_MFA_RECEIVER_REDIS_URL="redis://127.0.0.1:6379/2"
```

Redis mode stores only short-lived transaction metadata and an AES-GCM
encrypted code. The receiver token derives the encryption key; it is not saved
in Redis. In both modes, a code is removed immediately after one successful
consumption and expires after at most 300 seconds. Use a dedicated Redis DB or
account and do not place credentials in tracked configuration.

## Legacy Local Private SSO Configuration

The old `apiAnalysis.core.identify.sso` provider still supports local
environment files while remaining legacy code. New versioned
`ProjectAuthProfile` records do not read these global values. Keep any remaining
legacy endpoint values in a local private env file instead of tracked code:

```powershell
Copy-Item .\config_templates\api-manager-sso.local.env.example $env:API_MANAGER_DATA_DIR\api-manager-sso.local.env
notepad $env:API_MANAGER_DATA_DIR\api-manager-sso.local.env
```

Set the real values in that private file:

```text
API_MANAGER_SSO_AUTH_URL=https://<real-auth-host>/authorization
API_MANAGER_SSO_LOGIN_URL=https://<real-login-host>/login/token-login
```

`apiAnalysis.core.identify.sso` loads these files automatically, in order, and
does not override already-set environment variables:

- `$env:API_MANAGER_DATA_DIR\api-manager.local.env`
- `$env:API_MANAGER_DATA_DIR\api-manager-sso.local.env`
- `.env.local`

Legacy engagement-specific refresh helpers remain private. They must preserve
the existing authentication cache when refresh fails so a failed login cannot
replace a working private context with an empty result.

## AI Configuration

These variables currently configure the legacy single-purpose HTTP AI judge.
They do not yet provide a general AI-only CLI or agent session. The planned
editable access presets and approval preferences are documented in
[`docs/ai_cli_access_and_approval_design.md`](docs/ai_cli_access_and_approval_design.md).

```powershell
$env:API_MANAGER_AI_ENDPOINT="http://127.0.0.1:8000/judge"
$env:API_MANAGER_AI_API_KEY="token"
$env:API_MANAGER_AI_TIMEOUT="10"
```

## Optional Tool Paths

These are not required yet, but `--doctor` reports them so future adapters have
a predictable configuration surface.

```powershell
$env:SQLMAP_PATH="sqlmap.py"
$env:NUCLEI_PATH="nuclei"
$env:ZAP_PATH="zap.bat"
$env:SCHEMATHESIS_PATH="schemathesis"
$env:FFUF_PATH="ffuf"
```
