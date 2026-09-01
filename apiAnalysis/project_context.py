"""First-class project/source/import context helpers.

This module keeps external source ids (Apifox, Workspace, HAR) separate from
the stable internal ApiProject id. Importers can adopt it incrementally without
changing the existing request composition chain.
"""
import datetime as dt
import hashlib
import uuid
from typing import Any, Dict, Optional

from apiAnalysis.db.collection import (
    ApiProject,
    DataSource,
    ImportRun,
    ProjectEnvironment,
    ProjectSourceBinding,
)


def data_source_identity(source_type: str, external_id: str) -> str:
    source_type = str(source_type or "").strip().lower()
    external_id = str(external_id or "").strip()
    if not source_type or not external_id:
        raise ValueError("source_type and external_id are required")
    digest = hashlib.sha256(
        "{}\0{}".format(source_type, external_id).encode("utf-8")
    ).hexdigest()[:24]
    return "source-{}".format(digest)


def ensure_data_source(
    source_type: str,
    external_id: str,
    name: str = "",
    workspace_id: str = "",
    config: Optional[Dict[str, Any]] = None,
) -> DataSource:
    """Resolve one stable, credential-free data source."""
    source_type = str(source_type or "").strip().lower()
    external_id = str(external_id or "").strip()
    if not source_type or not external_id:
        raise ValueError("source_type and external_id are required")
    source = DataSource.objects(
        source_type=source_type,
        external_id=external_id,
    ).first()
    now = dt.datetime.utcnow()
    if not source:
        source = DataSource(
            data_source_id=data_source_identity(source_type, external_id),
            source_type=source_type,
            external_id=external_id,
            name=str(name or "{}:{}".format(source_type, external_id))[:240],
            workspace_id=str(workspace_id or ""),
            lifecycle=DataSource.ACTIVE,
            config=dict(config or {}),
            ctime=now,
            mtime=now,
        )
        source.save()
        return source

    changed = False
    if name and source.name != str(name)[:240]:
        source.name = str(name)[:240]
        changed = True
    if workspace_id and source.workspace_id != str(workspace_id):
        source.workspace_id = str(workspace_id)
        changed = True
    if config:
        merged = dict(source.config or {})
        merged.update(dict(config))
        if merged != dict(source.config or {}):
            source.config = merged
            changed = True
    if changed:
        source.mtime = now
        source.save()
    return source


def ensure_source_binding(
    data_source_id: str,
    project_id: str,
    env_id: str = "",
    routing_rules: Optional[Dict[str, Any]] = None,
) -> ProjectSourceBinding:
    """Bind a source to one project/environment without owning either."""
    source = DataSource.objects(data_source_id=str(data_source_id or "")).first()
    project = ApiProject.objects(
        project_id=str(project_id or ""),
        status=ApiProject.ACTIVE,
    ).first()
    if not source or not project:
        raise ValueError("data source and active project are required")
    env_id = str(env_id or "").strip()
    if env_id and not ProjectEnvironment.objects(
            project_id=project.project_id, env_id=env_id, active=True).first():
        raise ValueError("selected project environment is unavailable")

    binding = ProjectSourceBinding.objects(
        project_id=project.project_id,
        data_source_id=source.data_source_id,
        env_id=env_id,
    ).first()
    if not binding:
        binding = ProjectSourceBinding(
            project_id=project.project_id,
            data_source_id=source.data_source_id,
            source_type=source.source_type,
            source_id=source.external_id,
            env_id=env_id,
            workspace_id=source.workspace_id,
            routing_rules=dict(routing_rules or {}),
            active=True,
        )
        binding.save()
        return binding

    changed = False
    if not binding.active:
        binding.active = True
        binding.disabled_by = ""
        binding.disabled_at = None
        changed = True
    if routing_rules:
        merged = dict(binding.routing_rules or {})
        merged.update(dict(routing_rules))
        if merged != dict(binding.routing_rules or {}):
            binding.routing_rules = merged
            changed = True
    if changed:
        binding.mtime = dt.datetime.utcnow()
        binding.save()
    return binding


def ensure_project_for_source(
    source_type: str,
    source_id: str,
    name: str = "",
    env_id: str = "",
    project_id: str = "",
    workspace_id: str = "",
    routing_rules: Optional[Dict[str, Any]] = None,
) -> Dict[str, str]:
    """Resolve or create one stable project and source binding."""
    source_type = str(source_type or "").strip().lower()
    source_id = str(source_id or "").strip()
    env_id = str(env_id or "").strip()
    if not source_type or not source_id:
        raise ValueError("source_type and source_id are required")

    source = ensure_data_source(
        source_type,
        source_id,
        name=name or "{}:{}".format(source_type, source_id),
        workspace_id=workspace_id,
    )
    binding_query = ProjectSourceBinding.objects(
        data_source_id=source.data_source_id,
        env_id=env_id,
        active=True,
    )
    if project_id:
        binding_query = binding_query.filter(project_id=str(project_id))
    binding = binding_query.first()
    if not binding:
        legacy_query = ProjectSourceBinding.objects(
            source_type=source_type,
            source_id=source_id,
            env_id=env_id,
            active=True,
        )
        if project_id:
            legacy_query = legacy_query.filter(project_id=str(project_id))
        binding = legacy_query.first()
        if binding and not binding.data_source_id:
            binding.data_source_id = source.data_source_id
            binding.save()
    if binding:
        project = ApiProject.objects(project_id=binding.project_id).first()
        return {
            "project_id": binding.project_id,
            "project_name": project.name if project else "",
            "binding_id": str(binding.id),
            "created": False,
        }

    internal_id = str(project_id or uuid.uuid4())
    project = ApiProject.objects(project_id=internal_id).first()
    if not project:
        project = ApiProject(
            project_id=internal_id,
            name=name or f"{source_type}:{source_id}",
            metadata={"created_from_source": {"type": source_type, "id": source_id}},
        )
        project.save()
    binding = ensure_source_binding(
        source.data_source_id,
        internal_id,
        env_id=env_id,
        routing_rules=routing_rules,
    )
    return {
        "project_id": internal_id,
        "project_name": project.name,
        "binding_id": str(binding.id),
        "created": True,
    }


def start_import_run(
    source_type: str,
    project_id: str = "",
    source_id: str = "",
    env_id: str = "",
    account_id: str = "",
    content_hash: str = "",
    data_source_id: str = "",
    source_name: str = "",
    workspace_id: str = "",
) -> ImportRun:
    source = DataSource.objects(
        data_source_id=str(data_source_id or "")
    ).first() if data_source_id else None
    if not source:
        external_id = str(source_id or content_hash or uuid.uuid4())
        source = ensure_data_source(
            source_type,
            external_id,
            name=source_name or "{}:{}".format(source_type, external_id),
            workspace_id=workspace_id,
        )
    if project_id:
        ensure_source_binding(
            source.data_source_id,
            str(project_id),
            env_id=str(env_id or ""),
        )
    run = ImportRun(
        import_run_id=str(uuid.uuid4()),
        data_source_id=source.data_source_id,
        project_id=str(project_id or ""),
        project_ids=[str(project_id)] if project_id else [],
        source_type=str(source_type),
        source_id=str(source_id or ""),
        env_id=str(env_id or ""),
        account_id=str(account_id or ""),
        content_hash=str(content_hash or ""),
        status=ImportRun.RUNNING,
    )
    run.save()
    return run


def finish_import_run(run: ImportRun, summary: Optional[Dict[str, Any]] = None, error: str = "") -> ImportRun:
    run.summary = summary or {}
    discovered = [str(item) for item in (run.summary.get("project_ids") or []) if item]
    run.project_ids = sorted(set(list(run.project_ids or []) + discovered))
    run.error_summary = str(error or "")[:1000]
    run.status = ImportRun.FAILED if error else ImportRun.DONE
    run.finished_at = dt.datetime.utcnow()
    run.save()
    if run.data_source_id:
        DataSource.objects(data_source_id=run.data_source_id).update_one(
            set__current_import_run_id=run.import_run_id,
            set__mtime=run.finished_at,
        )
    return run


def asset_context(asset) -> Dict[str, str]:
    """Read new explicit fields first, then legacy source_meta for compatibility."""
    meta = getattr(asset, "source_meta", None) or {}
    return {
        "project_id": str(getattr(asset, "project_id", "") or meta.get("internal_project_id") or ""),
        "env_id": str(getattr(asset, "env_id", "") or meta.get("env_id") or ""),
        "import_run_id": str(getattr(asset, "import_run_id", "") or meta.get("import_run_id") or ""),
    }
