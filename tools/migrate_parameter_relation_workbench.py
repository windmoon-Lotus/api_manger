"""Backfill machine-first parameter-relation preprocessing fields.

Dry-run is the default.  The migration never sends a network request and never
reads or writes credential values.
"""
import argparse
import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from apiAnalysis.db.collection import (
    ProjectAccountBinding,
    ProjectEnvironment,
    parameter_relation,
)
from apiAnalysis.main import _ensure_mongo_connection
from apiAnalysis.tool.parameter_relation_workbench import (
    infer_environment_type,
    preprocess_relations,
)


def migrate(apply=False):
    _ensure_mongo_connection()
    summary = {
        "apply": bool(apply),
        "environments": Counter(),
        "environment_updates": 0,
        "binding_updates": 0,
        "relations": parameter_relation.objects.count(),
        "projects": {},
    }
    for environment in ProjectEnvironment.objects():
        inferred = infer_environment_type(environment)
        summary["environments"][inferred] += 1
        changed = False
        if (environment.environment_type or "unknown") == "unknown" and inferred != "unknown":
            environment.environment_type = inferred
            changed = True
        if inferred in {"test", "preprod"} and not environment.allow_mutation:
            environment.allow_mutation = True
            changed = True
        if not environment.auto_request_limit:
            environment.auto_request_limit = 3
            changed = True
        if changed:
            summary["environment_updates"] += 1
            if apply:
                environment.save()

    for binding in ProjectAccountBinding.objects():
        is_test = str(binding.role or "").lower() in {
            "test", "tester", "testing", "qa", "owner", "attacker",
        }
        if binding.is_test_account != is_test:
            summary["binding_updates"] += 1
            if apply:
                binding.is_test_account = is_test
                binding.save()

    if apply:
        project_ids = sorted(set(
            str(item) for item in parameter_relation.objects().distinct("project_id") if item
        ))
        for project_id in project_ids:
            result = preprocess_relations(project_id)
            summary["projects"][project_id] = result
    else:
        summary["preprocess_statuses_before"] = dict(Counter(
            str(item or "pending") for item in parameter_relation.objects().scalar("preprocess_status")
        ))
    summary["environments"] = dict(summary["environments"])
    return summary


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    print(json.dumps(migrate(apply=args.apply), ensure_ascii=False, indent=2, default=str))


if __name__ == "__main__":
    main()
