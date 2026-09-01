import os
import platform
import shutil
import subprocess
import sys
from importlib import metadata

import redis
from pymongo import MongoClient
from local_web_credentials import inspect_local_web_credentials

from apiAnalysis.conf.secret import (
    mongo_database,
    mongo_host,
    mongo_password,
    mongo_port,
    mongo_user,
    redis_db,
    redis_host,
    redis_password,
    redis_port,
    secret_key_is_ephemeral,
)
from apiAnalysis.conf.data_paths import (
    ALLOW_UNSAFE_DATA_DIR_ENV,
    is_repository_local,
    private_upload_dir,
)


CORE_DISTRIBUTIONS = {
    "APScheduler": "3.11.2",
    "Flask": "2.2.5",
    "Flask-Cors": "6.0.2",
    "Flask-Paginate": "2024.4.12",
    "Jinja2": "3.1.4",
    "Werkzeug": "3.0.3",
    "mongoengine": "0.29.1",
    "openpyxl": "3.1.5",
    "pymongo": "4.16.0",
    "PyJWT": "2.11.0",
    "redis": "7.0.1",
    "requests": "2.32.2",
}


def _ok(name, message, detail=None):
    return {"name": name, "ok": True, "message": message, "detail": detail or ""}


def _fail(name, message, detail=None):
    return {"name": name, "ok": False, "message": message, "detail": detail or ""}


def _warn(name, message, detail=None):
    item = _ok(name, message, detail=detail)
    item["warning"] = True
    return item


def _check_python():
    version = "{}.{}.{}".format(sys.version_info.major, sys.version_info.minor, sys.version_info.micro)
    if sys.version_info[:2] == (3, 9):
        return _ok("python", "Python {} ({})".format(version, platform.python_implementation()))
    return _fail("python", "Expected Python 3.9, got {}".format(version))


def _check_virtual_environment():
    if sys.prefix != getattr(sys, "base_prefix", sys.prefix):
        return _ok("python:venv", "Isolated virtual environment: {}".format(sys.prefix))
    return _warn(
        "python:venv",
        "Global Python environment detected; create .venv before installing dependencies",
    )


def _check_core_dependencies():
    missing = []
    mismatched = []
    for distribution, expected in CORE_DISTRIBUTIONS.items():
        try:
            installed = metadata.version(distribution)
        except metadata.PackageNotFoundError:
            missing.append(distribution)
            continue
        if installed != expected:
            mismatched.append("{} {} (expected {})".format(distribution, installed, expected))
    if missing or mismatched:
        detail = "; ".join(
            (["missing: {}".format(", ".join(sorted(missing)))] if missing else [])
            + (["version drift: {}".format(", ".join(sorted(mismatched)))] if mismatched else [])
        )
        return _fail(
            "python:dependencies",
            "Core dependencies do not match requirements.in",
            detail,
        )
    return _ok(
        "python:dependencies",
        "{} locked direct dependencies match".format(len(CORE_DISTRIBUTIONS)),
    )


def _check_dependency_resolver():
    process = subprocess.run(
        [sys.executable, "-m", "pip", "check"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
        text=True,
        timeout=30,
    )
    if process.returncode == 0:
        return _ok("python:pip-check", "Installed dependency graph is consistent")
    lines = [line.strip() for line in process.stdout.splitlines() if line.strip()]
    return _warn(
        "python:pip-check",
        "Installed environment contains dependency conflicts; rebuild .venv",
        "{} conflict line(s)".format(len(lines)),
    )


def _check_mongo():
    try:
        kwargs = {"serverSelectionTimeoutMS": 2000}
        if mongo_user or mongo_password:
            client = MongoClient(
                host=mongo_host,
                port=mongo_port,
                username=mongo_user or None,
                password=mongo_password or None,
                **kwargs
            )
        else:
            client = MongoClient(host=mongo_host, port=mongo_port, **kwargs)
        client.admin.command("ping")
        return _ok("mongodb", "Connected to {}:{}/{}".format(mongo_host, mongo_port, mongo_database))
    except Exception as exc:
        return _fail("mongodb", "Cannot connect to {}:{}/{}".format(mongo_host, mongo_port, mongo_database), str(exc))


def _check_redis():
    try:
        client = redis.Redis(
            host=redis_host,
            port=redis_port,
            db=redis_db,
            password=redis_password,
            socket_connect_timeout=2,
            socket_timeout=2,
        )
        client.ping()
        return _ok("redis", "Connected to {}:{}/{}".format(redis_host, redis_port, redis_db))
    except Exception as exc:
        return _fail("redis", "Cannot connect to {}:{}/{}".format(redis_host, redis_port, redis_db), str(exc))


def _check_upload_dir():
    try:
        upload_dir = private_upload_dir(create=True)
        probe = os.path.join(str(upload_dir), ".doctor_write_probe")
        with open(probe, "w", encoding="utf-8") as fh:
            fh.write("ok")
        os.remove(probe)
        if is_repository_local(upload_dir):
            return _warn(
                "upload_dir",
                "Writable upload dir is inside the repository because {}=1: {}".format(
                    ALLOW_UNSAFE_DATA_DIR_ENV, upload_dir,
                ),
            )
        return _ok("upload_dir", "Writable private upload dir: {}".format(upload_dir))
    except Exception as exc:
        return _fail("upload_dir", "Private upload dir is not writable", str(exc))


def _check_web_security():
    checks = []
    local_credentials = inspect_local_web_credentials()
    if secret_key_is_ephemeral and not local_credentials["complete"]:
        checks.append(_warn(
            "web:secret_key",
            "API_MANAGER_SECRET_KEY is not set; sessions will reset on restart",
        ))
    elif secret_key_is_ephemeral:
        checks.append(_ok(
            "web:secret_key",
            "Persistent Flask secret key is available in the local credential file",
        ))
    else:
        checks.append(_ok("web:secret_key", "Persistent Flask secret key is configured"))

    if os.getenv("API_MANAGER_ALLOW_INSECURE_DEFAULT_USERS", "0") == "1":
        checks.append(_warn(
            "web:local_user",
            "Historical insecure default users are explicitly enabled",
        ))
    elif os.getenv("API_MANAGER_ADMIN_PASSWORD"):
        checks.append(_ok("web:local_user", "Local Web administrator is configured"))
    elif local_credentials["complete"]:
        checks.append(_ok(
            "web:local_user",
            "Generated local Web administrator credentials are available",
        ))
    else:
        checks.append(_warn(
            "web:local_user",
            "No local Web administrator is configured; set API_MANAGER_ADMIN_PASSWORD",
        ))
    return checks


def _tool_path(env_name, candidates):
    configured = os.getenv(env_name)
    if configured:
        if os.path.exists(configured):
            return configured
        found = shutil.which(configured)
        if found:
            return found
        return None
    for candidate in candidates:
        found = shutil.which(candidate)
        if found:
            return found
    return None


def _check_tool(name, env_name, candidates, required=False):
    path = _tool_path(env_name, candidates)
    if path:
        return _ok("tool:{}".format(name), "{} available: {}".format(name, path))
    message = "{} not found; set {} when enabling this adapter".format(name, env_name)
    if required:
        return _fail("tool:{}".format(name), message)
    item = _ok("tool:{}".format(name), message)
    item["warning"] = True
    return item


def run_checks(include_tools=True, include_resolver_check=False):
    checks = [
        _check_python(),
        _check_virtual_environment(),
        _check_core_dependencies(),
        _check_mongo(),
        _check_redis(),
        _check_upload_dir(),
    ]
    checks.extend(_check_web_security())
    if include_resolver_check:
        checks.append(_check_dependency_resolver())
    if include_tools:
        checks.extend([
            _check_tool("sqlmap", "SQLMAP_PATH", ["sqlmap", "sqlmap.py"]),
            _check_tool("nuclei", "NUCLEI_PATH", ["nuclei"]),
            _check_tool("zap", "ZAP_PATH", ["zap.sh", "zap.bat", "zap"]),
            _check_tool("schemathesis", "SCHEMATHESIS_PATH", ["schemathesis", "st"]),
            _check_tool("ffuf", "FFUF_PATH", ["ffuf"]),
        ])
    return checks


def checks_ok(checks):
    return all(item.get("ok") for item in checks)


def format_checks(checks):
    lines = []
    for item in checks:
        marker = "OK" if item.get("ok") else "FAIL"
        if item.get("warning"):
            marker = "WARN"
        line = "[{}] {} - {}".format(marker, item["name"], item["message"])
        if item.get("detail"):
            line = "{} ({})".format(line, item["detail"])
        lines.append(line)
    return "\n".join(lines)
