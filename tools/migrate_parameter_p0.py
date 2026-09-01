"""Backfill P0 parameter identity, project environments and retention indexes.

Dry-run by default. ``--apply`` performs additive locator/environment updates,
moves unambiguous legacy Apifox-scoped priority/experience rows to the stable
project id, binds relation locations, and creates the new unique/TTL indexes.
It never guesses account-to-project bindings and never performs network login.
"""
import argparse
import datetime as dt
import ipaddress
import json
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from mongoengine.connection import get_db

from apiAnalysis.db.collection import (
    ApiProject,
    ProjectAccountBinding,
    ProjectAuthProfile,
    ProjectEnvironment,
    ProjectRequestFixture,
    ProjectSourceBinding,
    parameter_experience,
    parameter_priority_item,
    parameter_priority_review,
    parameter_relation,
    parameter_validation_result,
    raw_data,
    req_data,
    request_snapshot,
    res_data,
    security_execution_checkpoint,
    security_test_result,
    security_test_run,
)
from apiAnalysis.main import _ensure_mongo_connection
from apiAnalysis.tool.parameter_locator import LOCATOR_VERSION, locator_document_fields
from apiAnalysis.tool.parameter_validation import bind_relation_locations
from apiAnalysis.tool.project_auth import normalize_host


def _duplicates(collection, field):
    return list(collection.aggregate([
        {"$match": {field: {"$exists": True, "$nin": [None, ""]}}},
        {"$group": {"_id": "${}".format(field), "count": {"$sum": 1}}},
        {"$match": {"count": {"$gt": 1}}},
        {"$limit": 10},
    ]))


def _needs_locator(row):
    locator = dict(row.locator or {})
    return not (
        locator.get("version") == LOCATOR_VERSION
        and locator.get("tokens")
        and row.raw_path
        and row.schema_path
        and row.display_path
        and row.canonical_name
    )


def _backfill_locator(model, direction, apply, summary_key):
    count = 0
    for row in model.objects.only(
            "parameter", "position", "source_meta", "locator", "raw_path",
            "schema_path", "display_path", "canonical_name"):
        if not row.parameter or not _needs_locator(row):
            continue
        count += 1
        if not apply:
            continue
        position = str(row.position or "body").lower()
        schema = "[]" in str(row.parameter) if position == "body" else None
        values = locator_document_fields(
            row.parameter,
            direction=direction,
            position=position,
            source_meta=row.source_meta or {},
            schema=schema,
        )
        model.objects(id=row.id).update_one(**{
            "set__{}".format(key): value for key, value in values.items()
        })
    return count


def _project_env_id(project_id):
    binding = ProjectSourceBinding.objects(
        project_id=project_id, active=True, env_id__ne="",
    ).first()
    return str(binding.env_id or "default") if binding else "default"


def _discovered_hosts(project_id):
    result = []
    seen = set()
    for value in raw_data.objects(project_id=project_id).distinct("domain"):
        raw_value = str(value or "").strip()
        if "{" in raw_value or "}" in raw_value:
            continue
        host = normalize_host(raw_value)
        if not host or host in seen:
            continue
        result.append({
            "host": host,
            "base_url": (raw_value if "://" in raw_value else "https://" + raw_value)[:500],
        })
        seen.add(host)
    return result


def _preferred_default_host(entries):
    for item in entries:
        host = str(item.get("host") or "")
        if not host or host == "localhost" or "{" in host or "}" in host:
            continue
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            return host
        if not (address.is_private or address.is_loopback or address.is_link_local):
            return host
    return str(entries[0].get("host") or "") if entries else ""


def _backfill_environments(apply):
    counts = {
        "created": 0, "extended": 0, "without_host": 0,
        "default_updated": 0, "invalid_removed": 0,
    }
    env_by_project = {}
    for project in ApiProject.objects(status=ApiProject.ACTIVE):
        env_id = _project_env_id(project.project_id)
        env_by_project[project.project_id] = env_id
        discovered = _discovered_hosts(project.project_id)
        if not discovered:
            counts["without_host"] += 1
            continue
        environment = ProjectEnvironment.objects(
            project_id=project.project_id, env_id=env_id,
        ).first()
        if not environment:
            counts["created"] += 1
            if apply:
                ProjectEnvironment(
                    project_id=project.project_id,
                    env_id=env_id,
                    name="默认环境" if env_id == "default" else env_id,
                    default_host=_preferred_default_host(discovered),
                    hosts=discovered,
                    metadata={"backfilled_from": "raw_data.domain"},
                ).save()
            continue
        clean_existing = [
            item for item in (environment.hosts or [])
            if isinstance(item, dict)
            and "{" not in str(item.get("host") or item.get("base_url") or "")
            and "}" not in str(item.get("host") or item.get("base_url") or "")
        ]
        removed = len(environment.hosts or []) - len(clean_existing)
        counts["invalid_removed"] += removed
        existing_hosts = {
            normalize_host(item.get("host") or item.get("base_url") or "")
            for item in clean_existing
        }
        additions = [item for item in discovered if item["host"] not in existing_hosts]
        preferred = _preferred_default_host(clean_existing + additions)
        current_default = normalize_host(environment.default_host)
        default_changed = bool(preferred and current_default != preferred and (
            not current_default
            or current_default == "localhost"
            or current_default.startswith("127.")
            or current_default.startswith("10.")
            or current_default.startswith("192.168.")
            or "{" in current_default
        ))
        if default_changed:
            counts["default_updated"] += 1
        if additions:
            counts["extended"] += len(additions)
        if apply and (additions or removed or default_changed):
            environment.hosts = clean_existing + additions
            if default_changed:
                environment.default_host = preferred
            environment.mtime = dt.datetime.utcnow()
            environment.save()
    return counts, env_by_project


def _move_legacy_project_rows(model, binding, unique_fields, apply):
    moved = 0
    conflicts = 0
    for row in model.objects(project_id=binding.source_id):
        query = {"project_id": binding.project_id}
        for field in unique_fields:
            query[field] = getattr(row, field, None)
        existing = model.objects(**query).first()
        if existing and existing.id != row.id:
            conflicts += 1
            continue
        moved += 1
        if apply:
            model.objects(id=row.id).update_one(set__project_id=binding.project_id)
    return moved, conflicts


def _backfill_project_scopes(apply, env_by_project):
    summary = defaultdict(int)
    models = (
        (parameter_priority_item, ("parameter",), "priority"),
        (parameter_priority_review, ("parameter",), "reviews"),
        (parameter_experience, ("parameter", "group_key"), "experiences"),
        (parameter_validation_result, ("case_key",), "validation_results"),
    )
    for binding in ProjectSourceBinding.objects(source_type="apifox", active=True):
        for model, fields, label in models:
            moved, conflicts = _move_legacy_project_rows(model, binding, fields, apply)
            summary[label + "_moved"] += moved
            summary[label + "_conflicts"] += conflicts

    path_projects = {
        int(item.ptah_id): str(item.project_id or "")
        for item in raw_data.objects(project_id__ne="").only("ptah_id", "project_id")
    }
    for relation in parameter_relation.objects.only(
            "req_pathid", "res_pathid", "project_id", "env_id"):
        projects = {
            path_projects.get(int(pathid))
            for pathid in (relation.req_pathid, relation.res_pathid)
            if pathid is not None and path_projects.get(int(pathid))
        }
        if len(projects) != 1:
            if len(projects) > 1:
                summary["relation_project_conflicts"] += 1
            continue
        project_id = next(iter(projects))
        updates = {}
        if relation.project_id != project_id:
            updates["set__project_id"] = project_id
        env_id = env_by_project.get(project_id, "")
        if env_id and not relation.env_id:
            updates["set__env_id"] = env_id
        if updates:
            summary["relations_scoped"] += 1
            if apply:
                parameter_relation.objects(id=relation.id).update_one(**updates)
    return dict(summary)


def _backfill_relation_locators(apply):
    count = 0
    failed = 0
    status_updates = 0
    for relation in parameter_relation.objects:
        complete = bool(
            relation.source_locator and relation.target_locator
            and relation.source_position and relation.target_position
        )
        if complete and relation.locator_version == LOCATOR_VERSION:
            if relation.location_status != "resolved":
                status_updates += 1
                if apply:
                    parameter_relation.objects(id=relation.id).update_one(
                        set__location_status="resolved",
                        set__location_note="",
                    )
            continue
        if relation.location_status == "unresolved" and not complete:
            continue
        count += 1
        if not apply:
            continue
        try:
            bind_relation_locations(relation)
        except Exception:
            failed += 1
    return count, failed, status_updates


def _ensure_indexes(apply):
    models = (
        req_data, res_data, parameter_relation,
        ProjectEnvironment, ProjectAccountBinding, ProjectAuthProfile,
        ProjectRequestFixture, parameter_priority_item,
        idor_parameter_candidate, parameter_relation_analysis_run,
        request_snapshot, parameter_validation_result,
        security_test_run, security_execution_checkpoint, security_test_result,
    )
    if apply:
        for model in models:
            model.ensure_indexes()
    db = get_db()
    return {
        model._get_collection_name(): sorted(
            db.get_collection(model._get_collection_name()).index_information()
        ) for model in models
    }


def migrate(apply=False):
    models = (
        raw_data, req_data, res_data, parameter_relation,
        ApiProject, ProjectSourceBinding, ProjectEnvironment,
        ProjectAccountBinding, ProjectAuthProfile,
        ProjectRequestFixture,
        parameter_priority_item, parameter_priority_review,
        parameter_experience, idor_parameter_candidate,
        parameter_relation_analysis_run, parameter_validation_result,
        request_snapshot, security_test_run,
        security_execution_checkpoint, security_test_result,
    )
    if not apply:
        # MongoEngine normally creates declared indexes on the first QuerySet.
        # Disable that process-local behavior so a dry-run remains read-only.
        for model in models:
            model._meta["auto_create_index"] = False
    db = get_db()
    duplicate_template_keys = _duplicates(db.requestSnapshot, "template_key")
    duplicate_case_keys = _duplicates(db.parameterValidationResult, "case_key")
    if apply and (duplicate_template_keys or duplicate_case_keys):
        raise ValueError("P0 unique-index preflight found duplicate template/case keys")
    summary = {
        "mode": "apply" if apply else "dry-run",
        "request_locators": _backfill_locator(req_data, "request", apply, "request_locators"),
        "response_locators": _backfill_locator(res_data, "response", apply, "response_locators"),
        "duplicate_template_keys": len(duplicate_template_keys),
        "duplicate_case_keys": len(duplicate_case_keys),
    }
    environments, env_by_project = _backfill_environments(apply)
    summary["environments"] = environments
    summary["project_scopes"] = _backfill_project_scopes(apply, env_by_project)
    relation_count, relation_failed, relation_status_updates = _backfill_relation_locators(apply)
    summary["relation_locators"] = relation_count
    summary["relation_locator_failures"] = relation_failed
    summary["relation_location_statuses"] = relation_status_updates
    summary["indexes"] = _ensure_indexes(apply)
    return summary


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    _ensure_mongo_connection()
    print(json.dumps(migrate(apply=args.apply), ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()
