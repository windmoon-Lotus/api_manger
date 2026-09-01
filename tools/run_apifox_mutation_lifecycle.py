"""Plan or enqueue conservative Apifox mutation readback/cleanup lifecycles."""
import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from apiAnalysis.main import _ensure_mongo_connection
from apiAnalysis.tool.apifox_mutation_lifecycle import (
    MutationLifecycleError,
    MutationLifecycleLimits,
    build_mutation_lifecycle_plan,
    enqueue_mutation_lifecycle,
    mutation_lifecycle_report,
)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-id", required=True)
    parser.add_argument("--env-id", required=True)
    parser.add_argument("--profile-revision-id", required=True)
    parser.add_argument("--pathid", action="append", type=int, default=[])
    parser.add_argument(
        "--preflight-only", action="store_true",
        help="Execute only before-readback and restore-shape checks; never send mutation.",
    )
    parser.add_argument("--archive-value-index", type=int, default=0)
    parser.add_argument("--enqueue", action="store_true")
    parser.add_argument("--expected-plan-sha256", default="")
    parser.add_argument("--max-assets", type=int, default=50000)
    parser.add_argument("--max-candidates", type=int, default=1000)
    parser.add_argument("--max-workers", type=int, default=4)
    parser.add_argument("--per-host-workers", type=int, default=2)
    parser.add_argument("--min-interval-ms", type=int, default=100)
    parser.add_argument("--request-timeout", type=int, default=10)
    parser.add_argument("--operator", default="")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    if args.enqueue and not args.expected_plan_sha256:
        parser.error("--enqueue requires --expected-plan-sha256")
    try:
        _ensure_mongo_connection()
        plan = build_mutation_lifecycle_plan(
            args.project_id, args.env_id, args.profile_revision_id,
            pathids=args.pathid,
            preflight_only=args.preflight_only,
            archive_value_index=args.archive_value_index,
            limits=MutationLifecycleLimits(
                max_assets=args.max_assets, max_candidates=args.max_candidates,
            ),
        )
        report = (
            enqueue_mutation_lifecycle(
                plan, args.expected_plan_sha256,
                max_workers=args.max_workers,
                per_host_workers=args.per_host_workers,
                min_interval_ms=args.min_interval_ms,
                request_timeout_seconds=args.request_timeout,
                operator=args.operator,
            ) if args.enqueue else mutation_lifecycle_report(plan, mode="dry_run")
        )
        code = 0
    except MutationLifecycleError as exc:
        report = {
            "schema_version": "apifox-mutation-lifecycle.v1", "status": "blocked",
            "error_type": exc.__class__.__name__, "error": str(exc),
            "business_network_requests": 0, "database_records_created": 0,
        }
        code = 3
    except Exception as exc:
        report = {
            "schema_version": "apifox-mutation-lifecycle.v1", "status": "error",
            "error_type": exc.__class__.__name__,
            "error": "mutation lifecycle planning failed; inspect local service health",
            "business_network_requests": 0, "database_records_created": 0,
        }
        code = 1
    payload = json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    sys.stdout.write(payload)
    if args.output:
        args.output.write_text(payload, encoding="utf-8")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
