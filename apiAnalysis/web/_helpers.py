import hmac
import json
import secrets
import datetime as dt
from pathlib import Path
from flask import request, session, url_for
from werkzeug.utils import secure_filename
from ..db.collection import *

WORKSPACE_ROOT = Path(__file__).resolve().parents[3]
SECRETS_ROOT = WORKSPACE_ROOT / ".secrets"


def _bounded_int(value, default=0, minimum=0, maximum=1000000):
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return max(minimum, min(maximum, parsed))


def _lifecycle_csrf_token():
    token = session.get("lifecycle_csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["lifecycle_csrf_token"] = token
    return token


def _lifecycle_csrf_valid(value):
    expected = str(session.get("lifecycle_csrf_token") or "")
    supplied = str(value or "")
    return bool(expected and supplied and hmac.compare_digest(expected, supplied))


def _set_lifecycle_notice(text, level="success"):
    session["lifecycle_notice"] = {
        "text": str(text or "")[:300],
        "level": level if level in {"success", "warning", "error"} else "warning",
    }


def _lifecycle_return_url():
    values = {}
    for key in ("project_id", "run_status", "run_id", "page", "case_page"):
        value = request.form.get("return_" + key)
        if value not in (None, ""):
            values[key] = value
    return url_for("web.project_execution_center", **values)


def _project_id_from_endpoint(endpoint):
    meta = endpoint.source_meta or {}
    value = meta.get("apifox_project_id") or meta.get("project_id") or meta.get("projectId") or ""
    return str(value or "")


def _canonical_project_id(project_id):
    """Resolve a stable ApiProject id while accepting legacy source ids."""
    value = str(project_id or "").strip()
    if not value:
        return ""
    if ApiProject.objects(project_id=value, status=ApiProject.ACTIVE).first():
        return value
    binding = ProjectSourceBinding.objects(
        source_type="apifox", source_id=value, active=True,
    ).first()
    return str(binding.project_id or value) if binding else value


def _project_source_ids(project_id):
    stable_id = _canonical_project_id(project_id)
    values = []
    if stable_id:
        for binding in ProjectSourceBinding.objects(
                project_id=stable_id, source_type="apifox", active=True):
            source_id = str(binding.source_id or "")
            if source_id and source_id not in values:
                values.append(source_id)
    raw_value = str(project_id or "").strip()
    if raw_value and raw_value != stable_id and raw_value not in values:
        values.append(raw_value)
    return values


def _available_projects():
    rows = []
    for project in ApiProject.objects(status=ApiProject.ACTIVE).order_by("name", "project_id"):
        source_ids = _project_source_ids(project.project_id)
        count = raw_data.objects(project_id=project.project_id).count()
        if not count and source_ids:
            typed_ids = []
            for source_id in source_ids:
                typed_ids.extend([source_id, int(source_id) if source_id.isdigit() else source_id])
            count = raw_data.objects(
                source="apifox", source_meta__apifox_project_id__in=typed_ids,
            ).count()
        rows.append({
            "id": project.project_id,
            "name": project.name or project.project_id,
            "source_ids": source_ids,
            "count": count,
        })
    if rows:
        return rows

    # Compatibility fallback for databases that have not run project-context
    # migration yet. New writes still resolve to a stable project when one is
    # available.
    projects = {}
    for row in raw_data.objects(source="apifox").only("source_meta").limit(5000):
        project_id = _project_id_from_endpoint(row)
        if not project_id:
            continue
        projects.setdefault(project_id, 0)
        projects[project_id] += 1
    return [
        {"id": key, "name": "Apifox {}".format(key), "source_ids": [key], "count": value}
        for key, value in sorted(projects.items(), key=lambda item: item[0])
    ]


def _project_endpoints(project_id=""):
    stable_id = _canonical_project_id(project_id)
    if not stable_id:
        return []
    endpoints = list(raw_data.objects(project_id=stable_id).only(
        "ptah_id", "source_meta", "method", "path", "domain", "des", "project_id",
    ))
    if endpoints:
        return endpoints
    source_ids = _project_source_ids(project_id)
    typed_ids = []
    for source_id in source_ids:
        typed_ids.append(source_id)
        if source_id.isdigit():
            typed_ids.append(int(source_id))
    if not typed_ids and str(project_id or "").isdigit():
        typed_ids = [str(project_id), int(project_id)]
    if not typed_ids:
        return []
    return list(raw_data.objects(
        source="apifox", source_meta__apifox_project_id__in=typed_ids,
    ).only("ptah_id", "source_meta", "method", "path", "domain", "des", "project_id"))


def _elapsed_text(started_at, finished_at=None):
    if not started_at:
        return "-"
    seconds = max(0, int(((finished_at or dt.datetime.utcnow()) - started_at).total_seconds()))
    if seconds < 60:
        return "{} 秒".format(seconds)
    minutes, remainder = divmod(seconds, 60)
    if minutes < 60:
        return "{} 分 {} 秒".format(minutes, remainder)
    hours, minutes = divmod(minutes, 60)
    return "{} 小时 {} 分".format(hours, minutes)


def _safe_secret_json_name(value, default_name):
    name = secure_filename(value or default_name)
    if not name.endswith(".json"):
        name = default_name
    return name


def _load_secret_json(filename):
    safe_name = _safe_secret_json_name(filename, filename)
    path = SECRETS_ROOT / safe_name
    if not path.exists():
        return {}, path
    try:
        return json.loads(path.read_text(encoding="utf-8-sig")), path
    except Exception:
        return {}, path
