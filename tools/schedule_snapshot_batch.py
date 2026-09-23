"""Create a persistent snapshot batch without executing it in this process."""
import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from apiAnalysis.main import _ensure_mongo_connection
from apiAnalysis.tool.execution_contract import ExecutionContext, create_execution_snapshot
from apiAnalysis.tool.execution_scheduler import ExecutionPolicy, enqueue_snapshot_batch


def _read_snapshot_file(path):
    text = Path(path).read_text(encoding="utf-8-sig")
    try:
        value = json.loads(text)
    except json.JSONDecodeError:
        value = [line.strip() for line in text.splitlines() if line.strip()]
    if isinstance(value, dict):
        value = value.get("snapshot_ids") or []
    if not isinstance(value, list):
        raise ValueError("snapshot file must contain a JSON list or one id per line")
    return [str(item) for item in value]


def main():
    parser = argparse.ArgumentParser(description="Persist a resumable request-snapshot batch.")
    parser.add_argument("--name", required=True)
    parser.add_argument("--check-type", default="snapshot_baseline")
    parser.add_argument("--project-id", required=True)
    parser.add_argument("--env-id", default="")
    parser.add_argument("--account-id", default="")
    parser.add_argument("--auth-mode", choices=["anonymous", "account", "inherit"], default="anonymous")
    parser.add_argument("--auth-provider-id", default="")
    parser.add_argument("--auth-context-ref", default="")
    parser.add_argument(
        "--auth-profile-revision-id",
        default="",
        help="Pinned project auth profile revision id (required for auth_recipe). "
        "For recipe auth pass the profile revision id (pr-...) as --auth-context-ref too.",
    )
    parser.add_argument("--auth-realm-revision-id", default="", help="Pinned auth realm revision id (required for auth_recipe).")
    parser.add_argument("--auth-adapter-version-id", default="", help="Pinned auth adapter version id (required for auth_recipe).")
    parser.add_argument(
        "--adapter-id",
        default="",
        help="Defaults to authenticated_snapshot_batch for account mode, otherwise snapshot_batch.",
    )
    parser.add_argument("--adapter-version", default="1")
    parser.add_argument("--plan-version", default="")
    parser.add_argument("--plan-sha256", default="")
    parser.add_argument("--snapshot-id", action="append", default=[])
    parser.add_argument("--snapshot-file")
    parser.add_argument("--pathid", action="append", type=int, default=[])
    parser.add_argument("--priority", type=int, default=100)
    parser.add_argument("--queue-name", default="snapshot")
    parser.add_argument("--operator", default="")
    parser.add_argument("--evidence-ref", default="")
    parser.add_argument("--idempotency-key", default="")
    parser.add_argument("--max-workers", type=int, default=8)
    parser.add_argument("--per-host-workers", type=int, default=4)
    parser.add_argument("--min-interval-ms", type=int, default=25)
    parser.add_argument("--request-timeout", type=int, default=5)
    parser.add_argument("--lease-seconds", type=int, default=60)
    parser.add_argument("--transport-error-stop", type=int, default=2)
    parser.add_argument("--rate-limit-stop", type=int, default=3)
    parser.add_argument("--server-error-stop", type=int, default=3)
    parser.add_argument("--max-dispatch-attempts", type=int, default=3)
    parser.add_argument(
        "--allow-mutation",
        action="store_true",
        help="Explicitly acknowledge that the batch may contain non-read methods.",
    )
    args = parser.parse_args()

    _ensure_mongo_connection()
    adapter_id = args.adapter_id or (
        "authenticated_snapshot_batch" if args.auth_mode == "account" else "snapshot_batch"
    )
    context = ExecutionContext(
        project_id=args.project_id,
        env_id=args.env_id,
        account_id=args.account_id,
        auth_mode=args.auth_mode,
        auth_provider_id=args.auth_provider_id,
        auth_context_ref=args.auth_context_ref,
        auth_profile_revision_id=args.auth_profile_revision_id,
        auth_realm_revision_id=args.auth_realm_revision_id,
        auth_adapter_version_id=args.auth_adapter_version_id,
        adapter_id=adapter_id,
        adapter_version=args.adapter_version,
        plan_version=args.plan_version,
        plan_sha256=args.plan_sha256,
    )
    snapshot_ids = list(args.snapshot_id)
    if args.snapshot_file:
        snapshot_ids.extend(_read_snapshot_file(args.snapshot_file))
    for pathid in args.pathid:
        snapshot = create_execution_snapshot(pathid, context)
        if not snapshot:
            raise ValueError("pathid not found: {}".format(pathid))
        snapshot_ids.append(str(snapshot.id))
    policy = ExecutionPolicy(
        max_workers=args.max_workers,
        per_host_workers=args.per_host_workers,
        min_interval_ms=args.min_interval_ms,
        request_timeout_seconds=args.request_timeout,
        lease_seconds=args.lease_seconds,
        transport_error_stop=args.transport_error_stop,
        rate_limit_stop=args.rate_limit_stop,
        server_error_stop=args.server_error_stop,
        max_dispatch_attempts=1 if args.allow_mutation else args.max_dispatch_attempts,
        allow_mutation=args.allow_mutation,
        mutation_acknowledged=args.allow_mutation,
    )
    run, created = enqueue_snapshot_batch(
        name=args.name,
        check_type=args.check_type,
        context=context,
        snapshot_ids=snapshot_ids,
        policy=policy,
        evidence_ref=args.evidence_ref,
        operator=args.operator,
        priority=args.priority,
        queue_name=args.queue_name,
        idempotency_key=args.idempotency_key,
    )
    print(json.dumps({
        "run_id": str(run.id),
        "created": created,
        "status": run.status,
        "total_cases": run.total_cases,
        "project_id": run.project_id,
        "auth_mode": run.auth_mode,
        "auth_provider_id": run.auth_provider_id or "",
        "auth_context_ref": run.auth_context_ref or run.account_id or "",
        "auth_profile_revision_id": run.auth_profile_revision_id or "",
        "auth_realm_revision_id": run.auth_realm_revision_id or "",
        "auth_adapter_version_id": run.auth_adapter_version_id or "",
        "adapter_id": run.adapter_id,
    }, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()
