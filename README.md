# api_manger

Internal API asset and replay base for importing OpenAPI/HAR/mitmproxy traffic,
normalizing request assets, keeping representative request samples, building
replayable snapshots, and preparing future security test adapters.

## Quick Start

Use Python 3.9.

```powershell
py -3.9 -m pip install -r requirements.txt
py -3.9 -m apiAnalysis.main --doctor
py -3.9 run_web.py
```

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
py -3.9 -m apiAnalysis.main -i traffic.har -f har -p --quiet
```

Import OpenAPI as abstract API definitions:

```powershell
py -3.9 -m apiAnalysis.main -i api.openapi.json -f openapi --base-url https://example.test --quiet
```

Create and replay a snapshot:

```powershell
py -3.9 -m apiAnalysis.main --snapshot-pathid 3 --quiet
py -3.9 -m apiAnalysis.main --replay-snapshot <snapshot_id> --quiet
```

## Scope of This Repository

This repo ships the **generic base**: the `apiAnalysis` framework, generic
import/eval tooling under `tools/`, and the framework design docs under `docs/`.

Engagement-specific runners and notes (target-internal hosts, test accounts,
and findings) are **not distributed** here. They are kept local and ignored via
`.gitignore` (`tools/*pgy*`, `tools/gg_*`, `tools/*sunlogin*`, the engagement
docs, `security_reports/`, `security_profiles/`, `.secrets/`, `*.private.json`).
A few generic helpers may reference those local-only runners; treat such imports
as optional extensions, not part of the base.

## Sensitive Files

Do not commit HAR files, traffic dumps, local OpenAPI/Postman exports, database
exports, `.env` files, uploads, or runtime output. These are ignored by default
because they often contain cookies, tokens, request bodies, or internal URLs.
