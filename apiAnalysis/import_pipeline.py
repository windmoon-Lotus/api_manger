"""One import contract shared by Web, CLI, and source adapters.

An empty import must never fall back to an unbounded full-database analysis.
Every source invocation owns exactly one ImportRun lifecycle and returns one
normalized outcome before optional batch-scoped post processing.
"""

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

from bson import ObjectId

from apiAnalysis.db.collection import ProjectAssetLink, RequestObservation, raw_data
from apiAnalysis.db.save import (
    data_generate_mongodb,
    data_generate_openapi,
    data_generate_postman,
    parameter_date_mongodb,
    parameter_disassemble_mongodb,
)
from apiAnalysis.project_context import (
    ensure_data_source,
    ensure_source_binding,
    finish_import_run,
    start_import_run,
)
from apiAnalysis.rule.analysis import analysis
from apiAnalysis.tool.apifox_importer import import_apifox_details
from apiAnalysis.tool.interface_knowledge import discover_project_relations
from apiAnalysis.tool.parameter_relation_workbench import preprocess_relations


IMPORT_SOURCE_TYPES = {"flow", "har", "openapi", "postman", "apifox"}


@dataclass(frozen=True)
class ImportRequest:
    source_type: str
    source_path: str
    project_id: str = ""
    env_id: str = ""
    account_id: str = ""
    source_id: str = ""
    source_name: str = ""
    data_source_id: str = ""
    base_url: str = ""
    content_hash: str = ""
    run_parameters: bool = False
    server_map: Optional[Dict[str, str]] = None

    def validate(self) -> None:
        source_type = str(self.source_type or "").strip().lower()
        if source_type not in IMPORT_SOURCE_TYPES:
            raise ValueError("unsupported import source_type: {}".format(source_type))
        path = Path(str(self.source_path or ""))
        if not self.source_path or not path.exists():
            raise ValueError("import source path does not exist")
        if source_type == "apifox" and not path.is_dir():
            raise ValueError("Apifox import source must be a directory")
        if source_type != "apifox" and not path.is_file():
            raise ValueError("import source must be a file")
        if source_type in {"openapi", "postman", "apifox"} and not self.project_id:
            raise ValueError("document imports require project_id")


@dataclass(frozen=True)
class ImportOutcome:
    run: Any
    summary: Dict[str, Any]
    raw_ids: List[str]


def _source_content_hash(path: Path) -> str:
    digest = hashlib.sha256()
    files = [path] if path.is_file() else sorted(
        item for item in path.rglob("*") if item.is_file()
    )
    for item in files:
        if path.is_dir():
            digest.update(str(item.relative_to(path)).replace("\\", "/").encode("utf-8"))
            digest.update(b"\0")
        with item.open("rb") as handle:
            while True:
                chunk = handle.read(1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
    return digest.hexdigest()


def _dispatch_import(request: ImportRequest, run, source) -> List[Any]:
    source_type = request.source_type.strip().lower()
    common = {
        "project_id": request.project_id or None,
        "env_id": request.env_id or None,
        "import_run_id": run.import_run_id,
        "source_id": source.external_id,
    }
    if source_type in {"flow", "har"}:
        return data_generate_mongodb(
            request.source_path,
            "mitm" if source_type == "flow" else "har",
            account_id=request.account_id or None,
            data_source_id=source.data_source_id,
            **common
        ) or []
    if source_type == "openapi":
        return data_generate_openapi(
            request.source_path,
            base_url=request.base_url or None,
            **common
        ) or []
    if source_type == "postman":
        return data_generate_postman(
            request.source_path,
            base_url=request.base_url or None,
            **common
        ) or []

    apifox_summary = import_apifox_details(
        Path(request.source_path),
        base_url=request.base_url,
        server_map=request.server_map,
        source_context={
            "project_id": request.project_id,
            "env_id": request.env_id,
            "account_id": request.account_id,
            "import_run_id": run.import_run_id,
            "data_source_id": source.data_source_id,
        },
    )
    pathids = [int(item) for item in apifox_summary.get("pathids") or []]
    # ``raw_data`` declares ``_id`` as its primary-key field, so MongoEngine
    # exposes it through the portable ``pk`` alias rather than ``id``.
    return list(raw_data.objects(ptah_id__in=pathids).scalar("pk")) if pathids else []


def execute_import(request: ImportRequest) -> ImportOutcome:
    """Execute one source import with exactly one durable lifecycle record."""
    request.validate()
    source_type = request.source_type.strip().lower()
    path = Path(request.source_path)
    content_hash = request.content_hash or _source_content_hash(path)
    source_name = request.source_name or path.stem or path.name
    external_id = request.source_id or content_hash
    source = ensure_data_source(
        source_type,
        external_id,
        name=source_name,
        config={"last_filename": path.name},
    )
    if request.data_source_id and request.data_source_id != source.data_source_id:
        raise ValueError("data_source_id does not match source identity")
    if request.project_id:
        ensure_source_binding(
            source.data_source_id,
            request.project_id,
            env_id=request.env_id,
        )
    run = start_import_run(
        source_type,
        project_id=request.project_id,
        source_id=source.external_id,
        env_id=request.env_id,
        account_id=request.account_id,
        content_hash=content_hash,
        data_source_id=source.data_source_id,
        source_name=source.name,
    )
    try:
        imported = _dispatch_import(request, run, source)
        normalized = normalize_raw_ids(imported)
        batch = process_import_batch(
            normalized,
            account_id=request.account_id or None,
            run_parameters=request.run_parameters,
            project_id=request.project_id or None,
            env_id=request.env_id or None,
            import_run_id=run.import_run_id,
        )
        discovered_projects = {
            str(item)
            for item in raw_data.objects(
                import_run_id=run.import_run_id,
                project_id__nin=["", None],
            ).distinct("project_id")
            if item
        }
        if request.project_id:
            discovered_projects.add(request.project_id)
        summary = dict(batch or {})
        summary.update({
            "contract_version": "import.v1",
            "asset_count": len(normalized),
            "observation_count": RequestObservation.objects(
                import_run_id=run.import_run_id,
            ).count(),
            "project_ids": sorted(discovered_projects),
            "source_name": source.name,
            "filename": path.name,
        })
        finish_import_run(run, summary=summary)
        return ImportOutcome(run=run, summary=summary, raw_ids=normalized)
    except Exception as exc:
        finish_import_run(
            run,
            summary={
                "contract_version": "import.v1",
                "source_name": source.name,
                "filename": path.name,
            },
            error=str(exc),
        )
        raise


def normalize_raw_ids(raw_ids):
    normalized = []
    seen = set()
    for item in raw_ids or []:
        if item is None:
            continue
        value = str(item)
        if not value or value in seen:
            continue
        seen.add(value)
        normalized.append(value)
    return normalized


def pathids_for_raw_ids(raw_ids):
    normalized = normalize_raw_ids(raw_ids)
    if not normalized:
        return []
    object_ids = [ObjectId(value) for value in normalized]
    return list(raw_data.objects(pk__in=object_ids).scalar("ptah_id"))


def process_import_batch(raw_ids, account_id=None, run_parameters=False,
                         project_id=None, env_id=None, import_run_id=None):
    """Process only assets returned by one importer invocation."""
    normalized = normalize_raw_ids(raw_ids)
    summary = {
        "raw_ids": normalized,
        "pathids": [],
        "asset_count": len(normalized),
        "parameter_analysis": False,
        "skipped": not bool(normalized),
        "scope_warning": "",
    }
    if not normalized:
        return summary

    pathids = pathids_for_raw_ids(normalized)
    summary["pathids"] = pathids
    if project_id:
        raw_data.objects(pk__in=[ObjectId(value) for value in normalized]).update(
            set__project_id=str(project_id), set__env_id=str(env_id or ""),
            set__import_run_id=str(import_run_id or ""),
        )
        for pathid in pathids:
            ProjectAssetLink.objects(
                project_id=str(project_id), pathid=int(pathid), env_id=str(env_id or "")
            ).update_one(
                set__relationship="owned", set__confidence=1.0,
                set__reason_codes=["explicit_import_project"], upsert=True,
            )
        summary["project_id"] = str(project_id)
        summary["env_id"] = str(env_id or "")
    worker = analysis()
    worker.classify_raw_data(raw_ids=normalized)

    if run_parameters:
        if not pathids:
            summary["scope_warning"] = "imported assets could not be resolved to path ids"
            return summary
        parameter_disassemble_mongodb(raw_ids=normalized)
        parameter_date_mongodb(raw_ids=normalized)
        summary["archived_parameter_groups"] = worker.parameter_archive(
            pathids=pathids,
            account_id=account_id,
            project_id=project_id or "",
            env_id=env_id or "",
        )
        worker.infer_weak_relations(pathids=pathids)
        if project_id:
            # Incremental project discovery uses the complete documentation
            # graph but only revisits pairs touching this import batch.  It
            # preserves verified/manual relations and flags schema drift.
            summary["relation_discovery"] = discover_project_relations(
                str(project_id), changed_pathids=pathids,
            )
            summary["relation_preprocessing"] = preprocess_relations(
                str(project_id), env_id=str(env_id or ""), pathids=pathids, limit=20,
            )
        worker.build_request_compose(pathids=pathids)
        summary["parameter_analysis"] = True

    return summary
