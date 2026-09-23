# Persistent Execution Scheduler

Updated: 2026-07-20

## Purpose

The scheduler turns an arbitrary-size set of existing `request_snapshot`
records into one resumable execution. It does not add another request composer
or replace mature business runners.

```text
ExecutionContext
  -> request_snapshot[]
  -> security_test_run (queue and lease state)
  -> security_execution_checkpoint[] (per-snapshot progress)
  -> replay_snapshot
  -> security_test_result (sanitized conclusion)
```

MongoDB is the source of truth. Redis contains wake-up signals only. A Redis
restart can delay an idle worker until its next poll, but cannot lose a job.

## Run state machine

```text
preparing -> queued -> running -> done
                       |   |
                       |   +-> cancel_requested -> cancelled
                       +-> lease expired -> queued
                       +-> infrastructure retries exhausted -> failed
```

Each snapshot has an independent checkpoint:

```text
pending -> running -> done | error | skipped | cancelled
```

Queue insertion is content-idempotent across project, environment, account,
auth mode, adapter, plan, check type, snapshot set, and execution policy. An
explicit retry creates a child run containing only selected error, skipped, or
cancelled checkpoints.

## Throughput and stop behavior

There is no ten-interface or other artificial batch-size cap. The default
policy uses eight workers, at most four concurrent requests per Host, and a
25 ms Host start interval. These values are operator-configurable up to bounded
limits.

Transport errors, HTTP 429, and HTTP 5xx maintain independent consecutive
thresholds per Host. Crossing a threshold skips only the remaining checkpoints
for that Host; unrelated Hosts continue. Cancellation stops new submissions and
allows already in-flight requests to finish within their timeout.

The worker uses a renewable lease and heartbeat. Expired work is returned to
`queued`, and checkpoints that were `running` are reset to `pending`. Network
execution is therefore **at least once**, not exactly once. Generic snapshot
mutations require explicit acknowledgement and `max_dispatch_attempts=1`; an
ambiguous interrupted send may still have reached the server, so inspect state
before manually retrying. A normal HTTP response enters `need_review` with its
status and sanitized evidence; a separate readback or residual-state check
establishes the effect. Rate limits, server errors and redirects remain
`not_evaluable`. A specialized lifecycle
adapter remains available when the endpoint supports restoration or cleanup. The bundled worker
registers `snapshot_batch` for anonymous/legacy-inherit reads and
`authenticated_snapshot_batch` for explicit AccountContext reads. A run for an
unknown adapter, unsupported version or incompatible auth mode is paused before
any request and can be resumed after the matching worker/provider is installed.

## Evidence boundary

Scheduler checkpoints contain only status, Host, counters, reason codes, and
sanitized transport metadata. Body-free response fingerprints include SHA-256,
Content-Type, JSON top-level type, and a length bucket; the completed run groups
them by Host/response cluster and emits only targeted Review candidates.
`security_test_result.evidence_summary` never stores response samples or raw
exception messages. Private response bodies and credentials remain outside
Mongo and tracked files.

### Local request verification preview

Sanitized summaries are insufficient for deciding whether a business value or
resource id was constructed correctly. Inspect an existing run without sending
network requests or creating records:

```powershell
py -3.9 tools/inspect_execution_requests.py --run-id <run-id> --limit 5
py -3.9 tools/inspect_execution_requests.py --run-id <run-id> --ordinal 0
```

The output includes the real URL path/query, non-sensitive headers, body,
parameter provenance, execution status, and lifecycle phase. Authorization,
Cookie, token, password, signature, nonce, and similar secrets are rendered as
`<redacted>`; long strings and collections are bounded. An old update run's
actual before-derived restore body cannot be reconstructed because it was
intentionally transient; the inspector labels the stored cleanup template.

For future execution, explicitly enable a transient preview immediately before
each network send:

```powershell
py -3.9 tools/run_execution_worker.py --once --trace-requests
```

JSON preview lines go to stderr and are not added to Mongo or ordinary logs.
Mutation phases are named `before_readback`, `mutation`, `after_readback`,
`cleanup_restore`, and `final_readback`. The lifecycle now fails before any
request when a required mutation parameter still uses `empty_default`, or when
an update readback and its mutation target different resource identities.

The generic judge is deliberately narrow:

- Anonymous 401/403 for `unauth_access` becomes `no_vuln` for that anonymous
  authentication hypothesis.
- Anonymous 2xx becomes `need_review`; it is not automatically a finding.
- Other adapters receive `not_evaluable` until their business-specific judge
  evaluates the evidence.

The `apifox_test_experiment` adapter is an explicit test-environment exception
for all HTTP methods. It keeps the durable result body-free, but may promote a
bounded, valid JSON representative subtree into the private, context-scoped
`request_sample` pool. Runtime authentication headers are stripped from that
sample. Mutation responses always remain `not_evaluable`; 2xx only means a
possible state change until a future readback/cleanup adapter proves the effect.
The lifecycle evidence records that before/after readback and cleanup were not
attempted instead of silently claiming success.

`apifox_mutation_lifecycle` is the corresponding fail-closed effect adapter.
For PUT/PATCH it freezes one same-resource GET and runs at most
`GET before -> mutation -> GET after -> restore -> GET final`. The mutation is
not sent unless the before response is successful JSON and the exact mutation
field shape maps to one unique restore object. A 2xx restore is still
insufficient: final readback must match the before-field digest. Create/delete
cleanup additionally requires a prior proven response-ID shape, a unique detail
GET and a DELETE template; final 404/410 proves removal. Generic DELETE without
reconstruction is not eligible.

The adapter also has a separately hashed `readback_preflight` mode. It sends
only before GET requests and records `restore_payload_ready`; it never sends a
mutation. Each lifecycle checkpoint owns its full bounded sequence so cleanup
cannot be reordered behind another checkpoint. Its execution policy stops a
Host on the first transport, 429 or 5xx outcome and uses one dispatch attempt.

## Lightweight parameter-relation validation

The `parameter_relation_validation` adapter reuses this scheduler instead of
creating a second validation-task table. One Web submission creates one run
containing up to ten relation-plan snapshots. Reusable source/consumer request
templates are content-keyed; each case stores exact typed source/target
locators, project/environment references, selected auth profiles, and selected
Hosts.

The source JSON and source-derived value exist only inside the worker; the value
is injected into Path, Query, Header, Cookie, or nested Body and then discarded.
An optional operator-supplied override must survive the asynchronous handoff, so
it is stored only inside the seven-day expiring plan snapshot. Persistent result
evidence contains only value digest/type/length, status codes, response
fingerprint, profile references, and snapshot references.
Parameter-validation plan snapshots, runs, checkpoints, generic results, and
parameter validation summaries receive a seven-day `expires_at`; Mongo TTL
indexes remove them automatically. Long-lived evidence should be promoted into
the finding/evidence workflow instead of retaining every temporary validation.

## Commands

Import an Apifox details directory and immediately produce a value-free plan
for only that import run (add `--enqueue` to create snapshots and queue it):

```powershell
py -3.9 tools/import_apifox_and_experiment.py `
  --details-dir <directory> --source-id <stable-source-id> `
  --project-id <project-id> --env-id <test-env-id> `
  --profile-revision-id <profile-revision-id> `
  --enqueue --max-workers 8 --per-host-workers 4 --min-interval-ms 25
```

For existing Apifox assets, dry-run first and then enqueue the exact hash:

```powershell
py -3.9 tools/run_apifox_test_experiment.py `
  --project-id <project-id> --env-id <test-env-id> `
  --profile-revision-id <profile-revision-id>

py -3.9 tools/run_apifox_test_experiment.py `
  --project-id <project-id> --env-id <test-env-id> `
  --profile-revision-id <profile-revision-id> `
  --enqueue --expected-plan-sha256 <plan-sha256>
```

Preflight and execute a mutation lifecycle:

```powershell
py -3.9 tools/run_apifox_mutation_lifecycle.py `
  --project-id <project-id> --env-id <test-env-id> `
  --profile-revision-id <profile-revision-id> --preflight-only

py -3.9 tools/run_apifox_mutation_lifecycle.py `
  --project-id <project-id> --env-id <test-env-id> `
  --profile-revision-id <profile-revision-id> --pathid <mutation-pathid>
```

Create snapshots from path IDs and queue a read-only anonymous batch:

```powershell
py -3.9 tools/schedule_snapshot_batch.py `
  --name "anonymous baseline" `
  --check-type unauth_access `
  --project-id <internal-project-id> `
  --env-id formal `
  --auth-mode anonymous `
  --pathid 101 --pathid 102
```

Queue existing snapshot IDs from a JSON list or one-id-per-line file:

```powershell
py -3.9 tools/schedule_snapshot_batch.py `
  --name "owner baseline" `
  --project-id <internal-project-id> `
  --env-id formal `
  --auth-mode account --account-id owner `
  --auth-provider-id local_private --auth-context-ref owner-current `
  --snapshot-file "$env:API_MANAGER_DATA_DIR\inputs\snapshot-ids.json"
```

Account mode automatically selects `authenticated_snapshot_batch`; it does not
inherit snapshot/global credentials. See [`account_context.md`](account_context.md)
for private-file/callback providers, Host scope and pause/resume behavior.

Run one job or keep a worker polling. Worker startup always performs expired
lease recovery first:

```powershell
py -3.9 tools/run_execution_worker.py --once
py -3.9 tools/run_execution_worker.py --poll-seconds 5
```

Inspect, cancel, or retry selected terminal checkpoints:

```powershell
py -3.9 tools/manage_execution.py <run-id>
py -3.9 tools/manage_execution.py <run-id> --cancel
py -3.9 tools/manage_execution.py <run-id> --resume
py -3.9 tools/manage_execution.py <run-id> --retry --retry-status error
```

Validate and create scheduler indexes without rewriting legacy records:

```powershell
py -3.9 tools/migrate_execution_scheduler_v1.py
py -3.9 tools/migrate_execution_scheduler_v1.py --apply
py -3.9 tools/migrate_account_context_v1.py --apply
py -3.9 tools/migrate_parameter_p0.py --apply
```

## Remaining integration work

- Register specialized adapters for ownership comparison, mutation/readback,
  cleanup, and external tools. The Apifox observation adapter deliberately
  records the current readback/cleanup gap; future effect validation should
  reuse this lifecycle instead of adding another queue.
