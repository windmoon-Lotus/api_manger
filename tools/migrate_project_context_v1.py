"""Backfill first-class project context without guessing ambiguous ownership.

Dry-run by default. Use --apply to write ApiProject/source bindings, project ids
on safely attributable records, project-asset links, and the project-scoped
interface-chain index.
"""
import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from mongoengine.connection import get_db

from apiAnalysis.db.collection import (
    ProjectAssetLink,
    idor_parameter_candidate,
    parameter_archive,
    parameter_relation,
    raw_data,
    request_sample,
    request_snapshot,
    security_test_result,
    security_test_run,
)
from apiAnalysis.main import _ensure_mongo_connection
from apiAnalysis.project_context import ensure_project_for_source


DEFAULT_NAMES = {}


def _source_project_id(asset):
    return str((asset.source_meta or {}).get("apifox_project_id") or "")


def migrate(apply=False):
    apifox_assets = list(raw_data.objects(source="apifox").only("ptah_id", "source_meta", "project_id"))
    source_counts = Counter(_source_project_id(item) for item in apifox_assets if _source_project_id(item))
    mapping = {}
    if apply:
        for source_id in sorted(source_counts):
            mapping[source_id] = ensure_project_for_source(
                "apifox", source_id, name=DEFAULT_NAMES.get(source_id, f"Apifox {source_id}")
            )["project_id"]
    else:
        mapping = {source_id: "<create-or-resolve>" for source_id in source_counts}

    summary = {
        "mode": "apply" if apply else "dry-run",
        "source_asset_counts": dict(source_counts),
        "projects": mapping,
        "raw_assets_backfilled": 0,
        "asset_links_upserted": 0,
        "parameter_archives_backfilled": 0,
        "parameter_archives_ambiguous": 0,
        "parameter_relations_backfilled": 0,
        "parameter_relations_ambiguous": 0,
        "idor_candidates_backfilled": 0,
        "snapshots_backfilled": 0,
        "samples_backfilled": 0,
        "results_backfilled": 0,
        "runs_backfilled": 0,
        "legacy_family_index_dropped": False,
    }

    if not apply:
        summary["raw_assets_backfilled"] = sum(source_counts.values())
        return summary

    path_project = {}
    for asset in apifox_assets:
        project_id = mapping.get(_source_project_id(asset), "")
        if not project_id:
            continue
        path_project[int(asset.ptah_id)] = project_id
        if asset.project_id != project_id:
            raw_data.objects(pk=asset.pk).update_one(set__project_id=project_id)
            summary["raw_assets_backfilled"] += 1
        ProjectAssetLink.objects(project_id=project_id, pathid=int(asset.ptah_id), env_id="").update_one(
            set__relationship="owned", set__confidence=1.0,
            set__reason_codes=["apifox_source_binding"], upsert=True,
        )
        summary["asset_links_upserted"] += 1

    def projects_for_pathids(pathids):
        return {path_project[int(pathid)] for pathid in pathids or [] if int(pathid) in path_project}

    for item in parameter_archive.objects.only("req_pathid", "res_pathid", "project_id"):
        projects = projects_for_pathids(list(item.req_pathid or []) + list(item.res_pathid or []))
        if len(projects) == 1:
            project_id = next(iter(projects))
            if item.project_id != project_id:
                parameter_archive.objects(id=item.id).update_one(set__project_id=project_id)
                summary["parameter_archives_backfilled"] += 1
        elif len(projects) > 1:
            summary["parameter_archives_ambiguous"] += 1

    for item in parameter_relation.objects.only("req_pathid", "res_pathid", "project_id"):
        projects = projects_for_pathids([item.req_pathid, item.res_pathid])
        if len(projects) == 1:
            project_id = next(iter(projects))
            if item.project_id != project_id:
                parameter_relation.objects(id=item.id).update_one(set__project_id=project_id)
                summary["parameter_relations_backfilled"] += 1
        elif len(projects) > 1:
            summary["parameter_relations_ambiguous"] += 1

    simple_models = [
        (idor_parameter_candidate, "idor_candidates_backfilled"),
        (request_snapshot, "snapshots_backfilled"),
        (request_sample, "samples_backfilled"),
        (security_test_result, "results_backfilled"),
    ]
    for model, counter_name in simple_models:
        path_field = "related_pathid" if model is security_test_result else "pathid"
        for item in model.objects.only(path_field, "project_id"):
            pathid = getattr(item, path_field, None)
            project_id = path_project.get(int(pathid)) if pathid is not None else ""
            if project_id and item.project_id != project_id:
                model.objects(id=item.id).update_one(set__project_id=project_id)
                summary[counter_name] += 1

    run_projects = defaultdict(set)
    for result in security_test_result.objects(project_id__ne="").only("run_id", "project_id"):
        run_projects[str(result.run_id)].add(result.project_id)
    for run in security_test_run.objects.only("project_id"):
        projects = run_projects.get(str(run.id), set())
        if len(projects) == 1 and run.project_id != next(iter(projects)):
            security_test_run.objects(id=run.id).update_one(set__project_id=next(iter(projects)))
            summary["runs_backfilled"] += 1

    collection = get_db().get_collection("interfaceChainFeedback")
    old_index = collection.index_information().get("family_1")
    if old_index and old_index.get("unique"):
        collection.drop_index("family_1")
        summary["legacy_family_index_dropped"] = True
    collection.create_index(
        [("project_id", 1), ("env_id", 1), ("family", 1)],
        name="project_env_family_unique", unique=True,
    )
    return summary


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    _ensure_mongo_connection()
    print(json.dumps(migrate(apply=args.apply), ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()
