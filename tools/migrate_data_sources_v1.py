"""Backfill first-class data sources and source references.

Dry-run is the default.  The migration creates no traffic, reads no
credentials, and does not change imported request/response payloads.
"""
import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from apiAnalysis.db.collection import (
    ApiProject,
    DataSource,
    ImportRun,
    ObservationRoutingDecision,
    ProjectSourceBinding,
    RequestObservation,
    Workspace,
    request_sample,
    raw_data,
)
from apiAnalysis.main import _ensure_mongo_connection
from apiAnalysis.project_context import ensure_data_source
from apiAnalysis.tool.observation_store import save_observation


def _text(value):
    return str(value or "").strip()


def _source_key(source_type, external_id):
    source_type = _text(source_type).lower() or "unknown"
    external_id = _text(external_id)
    if not external_id:
        return None
    return source_type, external_id


def _binding_key(binding):
    external_id = (
        _text(binding.workspace_id)
        if _text(binding.source_type).lower() == "workspace"
        else _text(binding.source_id)
    )
    external_id = external_id or _text(binding.workspace_id) or _text(binding.id)
    return _source_key(binding.source_type, external_id)


def _run_key(run):
    external_id = (
        _text(run.source_id)
        or _text(run.content_hash)
        or _text(run.import_run_id)
    )
    return _source_key(run.source_type, external_id)


def _observation_key(observation):
    external_id = (
        _text(observation.workspace_id)
        or _text(observation.source_id)
        or _text(observation.import_run_id)
        or _text(observation.observation_id)
    )
    return _source_key(observation.source_type, external_id)


def _workspace_key(workspace):
    return _source_key("workspace", _text(workspace.id))


def _legacy_asset_url(asset):
    domain = _text(getattr(asset, "domain", ""))
    path = _text(getattr(asset, "path", "")) or "/"
    if domain:
        return "https://{}{}".format(domain, path)
    return path


def _source_name(source_type, external_id, *, workspace=None, project_name=""):
    if workspace is not None:
        return (
            _text(workspace.cname)
            or _text(workspace.system_name)
            or "实时流量空间 {}".format(external_id)
        )
    labels = {
        "apifox": "Apifox",
        "openapi": "OpenAPI",
        "postman": "Postman",
        "har": "HAR",
        "mitm": "mitm 流量",
        "workspace": "实时流量",
    }
    prefix = labels.get(source_type, source_type)
    if project_name and source_type == "apifox":
        return "{} · {}".format(project_name, prefix)
    return "{} {}".format(prefix, external_id)


def _drop_legacy_binding_index(apply):
    collection = ProjectSourceBinding._get_collection()
    legacy = []
    expected = [("source_type", 1), ("source_id", 1), ("env_id", 1)]
    for name, spec in collection.index_information().items():
        if spec.get("unique") and list(spec.get("key") or []) == expected:
            legacy.append(name)
    if apply:
        for name in legacy:
            collection.drop_index(name)
    return legacy


def migrate(apply=False):
    projects = {
        item.project_id: item.name
        for item in ApiProject.objects.only("project_id", "name")
    }
    bindings = list(ProjectSourceBinding.objects())
    runs = list(ImportRun.objects())
    observations = list(RequestObservation.objects())
    workspaces = list(Workspace.objects())
    legacy_samples = list(
        request_sample.objects(project_id__in=["", None])
    )
    sample_asset_ids = {
        str(item.raw_data.id)
        for item in legacy_samples
        if item.raw_data
    }
    legacy_assets_without_samples = [
        item
        for item in raw_data.objects(project_id__in=["", None])
        if str(item.id) not in sample_asset_ids
    ]

    plans = {}

    def plan(key, name="", workspace_id=""):
        if not key:
            return
        source_type, external_id = key
        row = plans.setdefault(key, {
            "source_type": source_type,
            "external_id": external_id,
            "name": name or _source_name(source_type, external_id),
            "workspace_id": workspace_id,
        })
        if name and (
            not row.get("name")
            or row["name"].startswith(source_type)
            or row["name"].startswith("workspace")
        ):
            row["name"] = name
        if workspace_id:
            row["workspace_id"] = workspace_id

    for workspace in workspaces:
        key = _workspace_key(workspace)
        if key:
            plan(
                key,
                _source_name(*key, workspace=workspace),
                workspace_id=key[1],
            )
    for binding in bindings:
        key = _binding_key(binding)
        if key:
            plan(
                key,
                _source_name(
                    *key,
                    project_name=projects.get(binding.project_id, ""),
                ),
                workspace_id=_text(binding.workspace_id),
            )
    for run in runs:
        if _text(run.data_source_id):
            continue
        key = _run_key(run)
        if key:
            plan(key)
    for observation in observations:
        if _text(observation.data_source_id):
            continue
        key = _observation_key(observation)
        if key:
            plan(
                key,
                workspace_id=_text(observation.workspace_id),
            )
    legacy_key = _source_key("legacy", "unscoped-traffic")
    if legacy_samples or legacy_assets_without_samples:
        plan(
            legacy_key,
            "历史未归属流量",
        )

    existing = {
        (item.source_type, item.external_id): item.data_source_id
        for item in DataSource.objects()
    }
    summary = {
        "mode": "apply" if apply else "dry-run",
        "planned_source_count": len(plans),
        "new_source_count": sum(1 for key in plans if key not in existing),
        "existing_source_count": len(existing),
        "bindings_backfilled": 0,
        "import_runs_backfilled": 0,
        "observations_backfilled": 0,
        "legacy_samples_planned": len(legacy_samples),
        "legacy_assets_without_samples_planned": len(
            legacy_assets_without_samples
        ),
        "legacy_observations_created": 0,
        "legacy_routing_status_counts": {},
        "legacy_binding_indexes": _drop_legacy_binding_index(apply),
        "indexes_ensured": False,
    }
    if not apply:
        summary["bindings_backfilled"] = sum(
            1 for item in bindings if not _text(item.data_source_id)
        )
        summary["import_runs_backfilled"] = sum(
            1 for item in runs if not _text(item.data_source_id)
        )
        summary["observations_backfilled"] = sum(
            1 for item in observations if not _text(item.data_source_id)
        )
        return summary

    source_ids = {}
    for key, row in sorted(plans.items()):
        source = ensure_data_source(
            row["source_type"],
            row["external_id"],
            name=row["name"],
            workspace_id=row.get("workspace_id") or "",
        )
        source_ids[key] = source.data_source_id

    for binding in bindings:
        key = _binding_key(binding)
        data_source_id = source_ids.get(key) if key else ""
        if data_source_id and binding.data_source_id != data_source_id:
            ProjectSourceBinding.objects(id=binding.id).update_one(
                set__data_source_id=data_source_id,
            )
            summary["bindings_backfilled"] += 1
    for run in runs:
        if _text(run.data_source_id):
            continue
        key = _run_key(run)
        data_source_id = source_ids.get(key) if key else ""
        if data_source_id and run.data_source_id != data_source_id:
            ImportRun.objects(id=run.id).update_one(
                set__data_source_id=data_source_id,
            )
            summary["import_runs_backfilled"] += 1
    for observation in observations:
        if _text(observation.data_source_id):
            continue
        key = _observation_key(observation)
        data_source_id = source_ids.get(key) if key else ""
        if data_source_id and observation.data_source_id != data_source_id:
            RequestObservation.objects(id=observation.id).update_one(
                set__data_source_id=data_source_id,
            )
            summary["observations_backfilled"] += 1

    legacy_source_id = source_ids.get(legacy_key, "")
    legacy_observation_ids = []
    if legacy_source_id:
        before_count = RequestObservation.objects(
            data_source_id=legacy_source_id,
        ).count()
        for sample in legacy_samples:
            asset = sample.raw_data
            if not asset:
                continue
            observation, _ = save_observation(
                source_type="legacy",
                source_id="sample:{}".format(sample.id),
                data_source_id=legacy_source_id,
                method=sample.method,
                url=sample.url,
                path=sample.path,
                request_headers=sample.headers or {},
                request_body=sample.body,
                response_status=sample.response_status_code,
                response_len=sample.response_len,
                response_hash=sample.response_hash,
                sample=sample,
                asset=asset,
            )
            legacy_observation_ids.append(observation.observation_id)
        for asset in legacy_assets_without_samples:
            observation, _ = save_observation(
                source_type="legacy",
                source_id="asset:{}".format(asset.ptah_id),
                data_source_id=legacy_source_id,
                method=asset.method,
                url=_legacy_asset_url(asset),
                path=asset.path,
                request_headers={},
                request_body=None,
                asset=asset,
            )
            legacy_observation_ids.append(observation.observation_id)
        after_count = RequestObservation.objects(
            data_source_id=legacy_source_id,
        ).count()
        summary["legacy_observations_created"] = max(
            0, after_count - before_count,
        )
        status_counts = {}
        for observation_id in set(legacy_observation_ids):
            latest = ObservationRoutingDecision.objects(
                observation_id=observation_id,
            ).order_by("-ctime", "-id").first()
            if latest:
                status_counts[latest.decision] = (
                    status_counts.get(latest.decision, 0) + 1
                )
        summary["legacy_routing_status_counts"] = status_counts

    for model in (
        DataSource,
        ProjectSourceBinding,
        ImportRun,
        RequestObservation,
    ):
        model.ensure_indexes()
    summary["indexes_ensured"] = True
    summary["source_count"] = DataSource.objects.count()
    return summary


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    _ensure_mongo_connection()
    print(json.dumps(
        migrate(apply=args.apply),
        ensure_ascii=False,
        sort_keys=True,
    ))


if __name__ == "__main__":
    main()
