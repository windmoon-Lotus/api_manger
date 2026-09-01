"""Validate/create scheduler indexes without rewriting historical runs.

Dry-run by default. The scheduler only manages newly queued runs, so no legacy
security_test_run/result document needs a status or field backfill.
"""
import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from mongoengine.connection import get_db

from apiAnalysis.db.collection import (
    security_execution_checkpoint,
    security_test_result,
    security_test_run,
)
from apiAnalysis.main import _ensure_mongo_connection


def _duplicate_values(collection, field, extra_match=None):
    match = {field: {"$exists": True, "$nin": [None, ""]}}
    match.update(extra_match or {})
    rows = collection.aggregate([
        {"$match": match},
        {"$group": {"_id": "${}".format(field), "count": {"$sum": 1}}},
        {"$match": {"count": {"$gt": 1}}},
        {"$limit": 10},
    ])
    return [{"value": str(item["_id"]), "count": item["count"]} for item in rows]


def migrate(apply=False):
    db = get_db()
    run_collection = db.get_collection("securityTestRun")
    result_collection = db.get_collection("securityTestResult")
    checkpoint_collection = db.get_collection("securityExecutionCheckpoint")
    duplicate_run_keys = _duplicate_values(run_collection, "idempotency_key")
    duplicate_result_keys = _duplicate_values(result_collection, "execution_key")
    duplicate_checkpoints = list(checkpoint_collection.aggregate([
        {"$group": {
            "_id": {"run_id": "$run_id", "snapshot_id": "$snapshot_id"},
            "count": {"$sum": 1},
        }},
        {"$match": {"count": {"$gt": 1}}},
        {"$limit": 10},
    ]))
    if apply and (duplicate_run_keys or duplicate_result_keys or duplicate_checkpoints):
        raise ValueError("scheduler unique-index preflight found duplicate keys")
    if apply:
        security_test_run.ensure_indexes()
        security_test_result.ensure_indexes()
        security_execution_checkpoint.ensure_indexes()
    return {
        "mode": "apply" if apply else "dry-run",
        "legacy_runs_rewritten": 0,
        "legacy_results_rewritten": 0,
        "duplicate_run_keys": duplicate_run_keys,
        "duplicate_result_keys": duplicate_result_keys,
        "duplicate_checkpoints": len(duplicate_checkpoints),
        "indexes": {
            "securityTestRun": sorted(run_collection.index_information()),
            "securityTestResult": sorted(result_collection.index_information()),
            "securityExecutionCheckpoint": sorted(checkpoint_collection.index_information()),
        },
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    _ensure_mongo_connection()
    print(json.dumps(migrate(apply=args.apply), ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()
