# api_manger Configuration

This project can still run with the default local settings, but the main runtime
configuration can now be overridden with environment variables.

## Runtime Checks

Run:

```powershell
py -3.9 -m apiAnalysis.main --doctor
```

The command checks:

- Python version
- MongoDB connection
- Redis connection
- Web upload directory writability
- Optional external tool paths

Missing external tools are reported as `WARN` because their adapters are not
required for the current baseline.

## Web Startup

```powershell
py -3.9 .\run_web.py
```

Optional web variables:

```powershell
$env:HOST="0.0.0.0"
$env:PORT="5000"
$env:DEBUG="1"
```

## Core Configuration

```powershell
$env:API_MANAGER_SECRET_KEY="change-me"

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

## AI Configuration

```powershell
$env:API_MANAGER_AI_ENDPOINT="http://127.0.0.1:8000/judge"
$env:API_MANAGER_AI_API_KEY="token"
$env:API_MANAGER_AI_TIMEOUT="10"
```

## Optional Tool Paths

These are not required yet, but `--doctor` reports them so future adapters have
a predictable configuration surface.

```powershell
$env:SQLMAP_PATH="D:\tools\sqlmap\sqlmap.py"
$env:NUCLEI_PATH="nuclei"
$env:ZAP_PATH="zap.bat"
$env:SCHEMATHESIS_PATH="schemathesis"
$env:FFUF_PATH="ffuf"
```
