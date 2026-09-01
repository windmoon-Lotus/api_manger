"""Inspect, cancel, or retry a persistent execution without exposing evidence."""
import argparse
import json
import sys
from pathlib import Path

from bson import ObjectId

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from apiAnalysis.db.collection import security_execution_checkpoint, security_test_run
from apiAnalysis.main import _ensure_mongo_connection
from apiAnalysis.tool.execution_scheduler import (
    request_execution_cancel,
    resume_execution,
    retry_execution,
)


def _summary(run):
    return {
        "run_id": str(run.id),
        "name": run.name,
        "status": run.status,
        "project_id": run.project_id,
        "env_id": run.env_id,
        "auth_mode": run.auth_mode,
        "account_id": run.account_id or "",
        "auth_provider_id": run.auth_provider_id or "",
        "auth_context_ref": run.auth_context_ref or run.account_id or "",
        "auth_context_summary": run.auth_context_summary or {},
        "adapter_id": run.adapter_id or "",
        "adapter_version": run.adapter_version or "",
        "total_cases": run.total_cases,
        "pending_cases": run.pending_cases,
        "running_cases": run.running_cases,
        "completed_cases": run.completed_cases,
        "failed_cases": run.failed_cases,
        "skipped_cases": run.skipped_cases,
        "cancelled_cases": run.cancelled_cases,
        "dispatch_attempt": run.dispatch_attempt,
        "lease_owner": run.lease_owner or "",
        "last_error_type": run.last_error_type or "",
        "host_state": run.host_state or {},
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("run_id")
    action = parser.add_mutually_exclusive_group()
    action.add_argument("--cancel", action="store_true")
    action.add_argument("--retry", action="store_true")
    action.add_argument("--resume", action="store_true")
    parser.add_argument("--reason", default="operator_requested")
    parser.add_argument("--operator", default="")
    parser.add_argument(
        "--retry-status",
        action="append",
        choices=[
            security_execution_checkpoint.ERROR,
            security_execution_checkpoint.SKIPPED,
            security_execution_checkpoint.CANCELLED,
        ],
        default=[],
    )
    args = parser.parse_args()
    _ensure_mongo_connection()
    if args.cancel:
        run = request_execution_cancel(args.run_id, reason=args.reason)
    elif args.retry:
        statuses = args.retry_status or [
            security_execution_checkpoint.ERROR,
            security_execution_checkpoint.SKIPPED,
            security_execution_checkpoint.CANCELLED,
        ]
        run, created = retry_execution(args.run_id, statuses, operator=args.operator)
        output = _summary(run)
        output["created"] = created
        print(json.dumps(output, ensure_ascii=False, sort_keys=True))
        return
    elif args.resume:
        run = resume_execution(args.run_id)
    else:
        run = security_test_run.objects(id=ObjectId(str(args.run_id)), scheduler_managed=True).first()
    if not run:
        raise ValueError("scheduled run not found")
    print(json.dumps(_summary(run), ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()
