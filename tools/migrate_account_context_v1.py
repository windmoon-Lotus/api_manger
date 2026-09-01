"""Create AccountContext indexes and report legacy gaps without moving secrets.

Dry-run by default. This migration never reads a private credential file and
never backfills credential values or provider references.
"""
import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from mongoengine.connection import get_db

from apiAnalysis.db.collection import request_snapshot, security_test_result, security_test_run
from apiAnalysis.main import _ensure_mongo_connection


def _missing(field):
    return {"$or": [{field: {"$exists": False}}, {field: {"$in": [None, ""]}}]}


def migrate(apply=False):
    db = get_db()
    runs = db.get_collection("securityTestRun")
    snapshots = db.get_collection("requestSnapshot")
    results = db.get_collection("securityTestResult")
    scheduler_account = {"scheduler_managed": True, "auth_mode": "account"}
    legacy_run_gaps = runs.count_documents({
        "$and": [scheduler_account, _missing("auth_provider_id")],
    })
    legacy_snapshot_gaps = snapshots.count_documents({
        "$and": [{"auth_mode": "account"}, _missing("auth_provider_id")],
    })
    generic_account_runs = runs.count_documents({
        "scheduler_managed": True,
        "auth_mode": "account",
        "adapter_id": "snapshot_batch",
    })
    # These field names are forbidden in scheduler records. Values are never read.
    forbidden_fields = (
        "authorization", "cookie", "access_token", "refresh_token", "password",
        "auth_context_summary.authorization", "auth_context_summary.cookie",
        "auth_context_summary.headers", "auth_context_summary.cookies",
    )
    run_forbidden_field_counts = {
        field: runs.count_documents({field: {"$exists": True}}) for field in forbidden_fields
    }
    result_forbidden_field_counts = {
        field: results.count_documents({field: {"$exists": True}}) for field in forbidden_fields
    }
    if apply:
        request_snapshot.ensure_indexes()
        security_test_run.ensure_indexes()
        security_test_result.ensure_indexes()
    return {
        "mode": "apply" if apply else "dry-run",
        "legacy_values_rewritten": 0,
        "credential_values_read": 0,
        "credential_values_written": 0,
        "scheduler_account_runs_missing_provider_ref": legacy_run_gaps,
        "account_snapshots_missing_provider_ref": legacy_snapshot_gaps,
        "account_runs_using_legacy_generic_adapter": generic_account_runs,
        "forbidden_run_field_counts": run_forbidden_field_counts,
        "forbidden_result_field_counts": result_forbidden_field_counts,
        "indexes": {
            "requestSnapshot": sorted(snapshots.index_information()),
            "securityTestRun": sorted(runs.index_information()),
            "securityTestResult": sorted(results.index_information()),
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
