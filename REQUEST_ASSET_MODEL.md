# Request Asset and Snapshot Model

This document describes the stage 2 request-modeling layer. It is intended for
future maintainers and AI agents that need to debug request generation, replay,
or external tool adapters.

## Purpose

The project now treats imported API data as assets and converts each asset into
a reproducible request snapshot.

The key handoff is:

```text
raw_data + req_data + parameter_archive + parameter_relation
        |
        v
standard request payload
        |
        v
request_snapshot
        |
        v
replay / sqlmap / nuclei / Schemathesis / ZAP / custom IDOR
```

## Core Files

- `apiAnalysis/db/collection.py`
  - Defines `request_snapshot`.
- `apiAnalysis/tool/compose_request.py`
  - Builds standard request payloads from parsed API assets.
  - Persists snapshots.
- `apiAnalysis/tool/request_mutator.py`
  - Provides database-free mutation helpers for query, path, header, cookie,
    form, and JSON body parameters.

## Standard Request Payload

`build_request_payload(pathid, account_id=None, env_id=None, source="asset")`
returns a dictionary with these important fields:

```text
pathid
raw_id
source
env_id
account_id
method
url
rendered_url
path
domain
content_type
query
headers
cookies
path_params
body
raw_body_sample
response_sample
expected_status_codes
parameter_sources
metadata
```

Notes:

- `url` is the original asset URL.
- `rendered_url` is the URL after path parameters and query parameters are
  applied.
- `headers` merges original asset headers with parsed header parameters.
- `body` is built from parsed body/form parameters when available.
- `raw_body_sample` is retained as fallback evidence from the original import.
- `parameter_sources` records where each parameter value came from.

## Snapshot Model

`request_snapshot` is stored in MongoDB collection `requestSnapshot`.

Important fields:

```text
pathid
raw_data
source
env_id
account_id
method
url
path
domain
query
headers
cookies
path_params
body
content_type
expected_status_codes
parameter_sources
metadata
ctime
```

The model is intentionally explicit. A snapshot should describe one executable
HTTP request without requiring a caller to understand `raw_data` or `req_data`.

## CLI Usage

Create one snapshot:

```powershell
py -3.9 -m apiAnalysis.main --snapshot-pathid 123
```

Create snapshots for recent assets:

```powershell
py -3.9 -m apiAnalysis.main --snapshot-all --snapshot-limit 100
```

Bind generated values to an account archive when available:

```powershell
py -3.9 -m apiAnalysis.main --snapshot-pathid 123 --account-id <account_id>
```

Replay one snapshot:

```powershell
py -3.9 -m apiAnalysis.main --replay-snapshot <snapshot_id>
```

Replay recent snapshots with an authorized domain filter:

```powershell
py -3.9 -m apiAnalysis.main --replay-snapshots --replay-limit 3 --replay-domain-regex "example\\.com"
```

Optional short-lived local auth overlays:

```powershell
$env:API_MANAGER_AUTHORIZATION="Bearer <short-lived-test-token>"
$env:API_MANAGER_AUTH_COOKIE="<short-lived-test-cookie>"
```

Do not paste long-lived production credentials into chat or docs. Keep auth
values local to the machine running the replay command.

## Parameter Mutation

Use `mutate_request(payload, position, name, value)` for a single mutation.

Supported positions:

- `query`
- `path`
- `header`
- `cookie`
- `body`
- `json`
- `form`

Examples:

```python
mutate_request(payload, "query", "page", "2")
mutate_request(payload, "header", "X-Test", "1")
mutate_request(payload, "json", "user.profile.name", "alice")
mutate_request(payload, "path", "user_id", "10001")
```

For multiple changes:

```python
mutate_many(payload, [
    {"position": "query", "name": "page", "value": "2"},
    {"position": "json", "name": "user.role", "value": "admin"},
])
```

## Debug Checklist

When a generated request is wrong, check in this order:

1. Does `raw_data.objects(ptah_id=<id>).first()` exist?
2. Does the asset have the expected `method`, `url`, `headers`, `query`, and
   `raw_req` values?
3. Do `req_data.objects(raw_data=<asset>)` entries have correct `position`
   values?
4. Does `parameter_archive` contain account-bound replacement values?
5. Does `parameter_relation` contain evidence for inferred values?
6. Does `build_request_payload` produce the expected `parameter_sources`?
7. Does `rendered_url` include the intended path and query values?
8. Does `request_snapshot` preserve the final request body and headers?

## Design Rules

- Tool adapters should consume request snapshots or standard request payloads,
  not raw Mongo collections directly.
- Mutators should remain database-free.
- Snapshots are append-only execution records; do not mutate old snapshots to
  represent new test attempts.
- If a future environment model is added, keep `env_id` as the stable link from
  snapshot to environment.
