# AccountContext and authenticated execution

Updated: 2026-07-20

## Purpose

`AccountContext` gives the scheduler a secret-free reference to a short-lived,
in-memory credential. It separates four identities that must not be guessed:
API project, target environment, test account, and credential provider/context
revision. Snapshots, jobs and results store those references, never credential
values.

```text
ExecutionContext (references only)
  -> AccountContextResolver
      -> project database SSO provider OR local private JSON provider OR refresh callback
          -> AccountContext (process memory only)
              -> authenticated_snapshot_batch
```

## Authentication modes

- `anonymous` removes imported authentication headers and cookies. Environment
  authentication variables are ignored.
- `account` removes imported authentication, ignores global authentication
  variables, and requires an `AccountContext` matching the run's project,
  environment, account, provider and Host.
- `inherit` is compatibility mode for older local workflows. It may retain
  snapshot authentication and overlay `API_MANAGER_AUTHORIZATION` /
  `API_MANAGER_AUTH_COOKIE`; new authenticated scheduler jobs should not use it.

The built-in `snapshot_batch` adapter accepts only `anonymous` or legacy
`inherit` reads. `authenticated_snapshot_batch` accepts only `account` reads
and requires a successful AccountContext preflight. Both reject mutations. A
future mutation adapter must declare mutation support and implement owner
readback, cleanup and its judge while reusing the scheduler lifecycle.

## Providers

`DatabaseSsoAccountContextProvider` is the default provider for the local Web
workflow. `/project-auth` binds an existing internal `SsoAccount` to a stable
project/environment alias and creates one or more selectable auth profiles.
Each profile declares Bearer, Cookie, or mixed injection and an explicit Host
allowlist. The worker calls the existing SSO login flow when the context is
missing or stale, keeps the resulting Token/Cookie in process memory, and
stores only the profile/account reference plus sanitized refresh health. The
legacy account password remains in the existing internal account table; it is
not copied into profiles, snapshots, runs, results, or logs.

The Web setup order is:

```text
ProjectEnvironment (Host/Base URL)
  -> ProjectAccountBinding (project alias -> SsoAccount)
      -> ProjectAuthProfile (bearer/cookie/mixed + Host scope)
          -> parameter center source/consumer selection
```

One project may have multiple accounts and multiple profiles per account. A
source request and consumer request may select different profiles while still
remaining inside the same project/environment.

`JsonFileAccountContextProvider` accepts only a path under `.secrets` or a file
named `*.private.json`. A canonical local file can use this shape:

```json
{
  "project_id": "<internal-project-id>",
  "env_id": "formal",
  "allowed_hosts": ["api.example.test"],
  "accounts": [
    {
      "account_id": "owner",
      "context_ref": "owner-current",
      "status": "ready",
      "auth_kind": "product_bearer",
      "authorization": "<short-lived value>",
      "expires_at": "2030-01-01T00:00:00Z"
    }
  ]
}
```

Legacy local files with `username`, numeric `index`, `authorization`, `cookie`
and `expiresHint` are supported when the worker receives explicit default
project, environment and allowed Hosts. Aliases such as `account[0]` avoid
persisting a username in scheduler metadata. Malformed files fail closed and
parser errors never echo file contents.

`CallbackAccountContextProvider` is the extension point for SSO-to-product-token
exchange or refresh. The callback returns an `AccountContext` or equivalent
mapping directly to the worker process. It does not write the token to Mongo.
When the identity token and product API token belong to different trust domains,
the callback must explicitly perform and verify the exchange instead of
relabeling one token as another.

## Queue and worker usage

Queue an existing read-only snapshot set with references only:

```powershell
py -3.9 tools/schedule_snapshot_batch.py `
  --name "owner baseline" `
  --project-id <internal-project-id> `
  --env-id formal `
  --auth-mode account `
  --account-id owner `
  --auth-provider-id local_private `
  --auth-context-ref owner-current `
  --snapshot-file "$env:API_MANAGER_DATA_DIR\inputs\snapshot-ids.json"
```

`authenticated_snapshot_batch` is selected automatically for `account` mode.
Run a worker with an explicitly scoped private file:

```powershell
py -3.9 tools/run_execution_worker.py `
  --account-context-file "$env:API_MANAGER_DATA_DIR\credentials\account.private.json" `
  --account-provider-id local_private `
  --account-project-id <internal-project-id> `
  --account-env-id formal `
  --account-allowed-host api.example.test `
  --account-allowed-host api-v2.example.test
```

The same provider can be configured through the
`API_MANAGER_ACCOUNT_CONTEXT_*` environment variables. Credential values are
not accepted through new account-mode environment variables.

## Pause, refresh and resume

Before any request, the worker validates the adapter version, auth mode,
provider availability, expiry margin and every target Host. A missing, expired
or mismatched context pauses the run with sanitized `auth_context_summary` and
zero requests. The context is resolved again immediately before each request;
if refresh fails mid-run, unstarted checkpoints remain `pending` and the run is
paused instead of producing one transport/auth error per endpoint.

After the provider is repaired or refreshed:

```powershell
py -3.9 tools/manage_execution.py <run-id> --resume
```

For database SSO profiles no manual Token/Cookie paste is required: the next
worker resolution logs in again after cache/expiry invalidation. A failed login
records only `last_error_type`; the run pauses without sending the target
request.

## Persistence boundary

Allowed persisted authentication metadata is limited to provider/account
references, auth kind, credential header/cookie **names**, Host scope, issue and
expiry timestamps, status and error type. Values, raw provider errors and
private response bodies are forbidden in snapshots, runs, checkpoints,
results, logs and tracked files.

Validate indexes and report legacy gaps without reading or moving credentials:

```powershell
py -3.9 tools/migrate_account_context_v1.py
py -3.9 tools/migrate_account_context_v1.py --apply
py -3.9 tools/migrate_parameter_p0.py --apply
```
