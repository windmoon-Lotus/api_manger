# api_manger

Project-scoped API security workbench for governed evidence import, immutable
request snapshots, durable execution, multi-principal authorization matrices,
human review, evidence replay, and fix-verification closure.

The current product scope and acceptance baseline are documented in
[`REQUIREMENTS_V2.md`](REQUIREMENTS_V2.md). The older Chinese compliance-gap
report is retained only as historical context.

## Documentation

- [`START.md`](START.md): shortest installation and first-run path.
- [`docs/README.md`](docs/README.md): authoritative documentation index and status map.
- [`docs/CLI_REFERENCE.md`](docs/CLI_REFERENCE.md): processes, commands, Web pages,
  HTTP API and network side effects.
- [`PROJECT_OVERVIEW.md`](PROJECT_OVERVIEW.md): current architecture and data flow.
- [`CONFIGURATION.md`](CONFIGURATION.md): environment, credentials and optional tools.
- [`DATA_GOVERNANCE.md`](DATA_GOVERNANCE.md): public repository publication boundary.

## Quick Start

Use the declared Python 3.9 environment and the resolved lock file.

```powershell
py -3.9 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m pip check
.\.venv\Scripts\python.exe -m apiAnalysis.main --doctor
.\.venv\Scripts\python.exe run_web.py
```

Install `requirements-capture.txt` only when the legacy mitmproxy flow reader
is required. It is lazy-loaded and no longer constrains the core Web/runtime
environment. `python -m apiAnalysis.main --version` prints the single
application version used by the UI and system endpoint.

On the first `run_web.py` start, if no administrator password is configured,
the launcher generates a local username/password and persistent Flask key in
`../.secrets/infrastructure/credentials/api-manager-web.local.env`. The password is printed once and then
reused silently. Explicit `API_MANAGER_ADMIN_PASSWORD` and
`API_MANAGER_SECRET_KEY` environment variables always take precedence.

The project expects local MongoDB and Redis by default:

```powershell
$env:API_MANAGER_MONGO_HOST="127.0.0.1"
$env:API_MANAGER_MONGO_PORT="27017"
$env:API_MANAGER_MONGO_DATABASE="apihandl"
$env:API_MANAGER_REDIS_HOST="127.0.0.1"
$env:API_MANAGER_REDIS_PORT="6379"
```

## Import Examples

Import HAR traffic:

```powershell
py -3.9 -m apiAnalysis.main -i traffic.har -f har --source-id browser-capture -p --quiet
```

Import OpenAPI as abstract API definitions:

```powershell
py -3.9 -m apiAnalysis.main -i api.openapi.json -f openapi `
  --project-id <project-id> --env-id <env-id> --base-url https://example.test --quiet
```

Queue snapshots for resumable execution and run one worker job:

```powershell
py -3.9 tools/schedule_snapshot_batch.py --name "baseline" --project-id <project-id> --pathid 3
py -3.9 tools/run_execution_worker.py --once
```

Run the four production responsibilities as separate processes:

```powershell
py -3.9 tools/run_web_server.py
py -3.9 tools/run_execution_worker.py
py -3.9 tools/run_relation_analysis_worker.py
py -3.9 tools/run_maintenance_scheduler.py
```

The persistent scheduler has no fixed endpoint-batch limit. MongoDB owns queue
and checkpoint state; Redis is only a wake-up channel. See
[`docs/execution_scheduler.md`](docs/execution_scheduler.md) for concurrency,
lease recovery, cancellation, retry, mutation safeguards, and CLI usage.
Authenticated jobs use an explicit, Host-scoped in-memory AccountContext rather
than persisted or implicitly inherited credentials; see
[`docs/account_context.md`](docs/account_context.md).
The `/auth-import` shortcut supports multiple simultaneous login scenes and
roles, one-click Recipe import, existing Token URL reuse, and
administrator-trusted code; see [`docs/auth_import.md`](docs/auth_import.md).

The local Web UI now exposes the shared project, routing, and scheduler
lifecycle at `/project-executions`. It shows allowlisted state only; manager
actions append audited routing decisions or invoke the scheduler's existing
cancel/resume transitions. See
[`docs/project_execution_center.md`](docs/project_execution_center.md).

Authorization tests use a versioned N-principal matrix rather than a fixed
two-account model. Rules may combine roles, ranks, scopes, labels and custom
non-sensitive attributes; complete matrix expansion is bounded explicitly and
never silently truncated. See
[`docs/authorization_matrix.md`](docs/authorization_matrix.md).

## Scope of This Repository

This repo ships the **generic base**: the `apiAnalysis` framework, generic
import/eval tooling under `tools/`, and the framework design docs under `docs/`.

Engagement-specific runners and notes (target-internal hosts, test accounts,
and findings) are **not distributed** here. They belong in the external private
data root or a private extension repository. Generic path rules and the
public-data guard enforce this boundary without publishing target names in
repository metadata. See [`DATA_GOVERNANCE.md`](DATA_GOVERNANCE.md).

## Sensitive Files

Do not commit HAR files, traffic dumps, local OpenAPI/Postman exports, database
exports, `.env` files, uploads, or runtime output. These are ignored by default
because they often contain cookies, tokens, request bodies, or internal URLs.
