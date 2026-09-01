"""Plan or enqueue all-method Apifox experiments for an explicit test environment."""
import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from apiAnalysis.main import _ensure_mongo_connection
from apiAnalysis.tool.apifox_experiment import (
    ApifoxExperimentError,
    ApifoxExperimentLimits,
    apifox_experiment_report,
    build_apifox_experiment_plan,
    enqueue_apifox_experiment,
)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-id", required=True)
    parser.add_argument("--env-id", required=True)
    parser.add_argument("--profile-revision-id", required=True)
    parser.add_argument("--import-run-id", default="")
    parser.add_argument("--pathid", action="append", type=int, default=[])
    parser.add_argument("--enqueue", action="store_true")
    parser.add_argument("--expected-plan-sha256", default="")
    parser.add_argument("--max-endpoints", type=int, default=50000)
    parser.add_argument("--max-workers", type=int, default=8)
    parser.add_argument("--per-host-workers", type=int, default=4)
    parser.add_argument("--min-interval-ms", type=int, default=25)
    parser.add_argument("--request-timeout", type=int, default=10)
    parser.add_argument("--lease-seconds", type=int, default=60)
    parser.add_argument("--max-dispatch-attempts", type=int, default=3)
    parser.add_argument("--operator", default="")
    parser.add_argument("--output", type=Path, help="Explicit optional value-free JSON report path.")
    args = parser.parse_args(argv)
    if args.enqueue and not args.expected_plan_sha256:
        parser.error("--enqueue requires --expected-plan-sha256")
    try:
        _ensure_mongo_connection()
        plan = build_apifox_experiment_plan(
            args.project_id,
            args.env_id,
            args.profile_revision_id,
            import_run_id=args.import_run_id,
            pathids=args.pathid,
            limits=ApifoxExperimentLimits(max_endpoints=args.max_endpoints),
        )
        if args.enqueue:
            report = enqueue_apifox_experiment(
                plan,
                args.expected_plan_sha256,
                max_workers=args.max_workers,
                per_host_workers=args.per_host_workers,
                min_interval_ms=args.min_interval_ms,
                request_timeout_seconds=args.request_timeout,
                lease_seconds=args.lease_seconds,
                max_dispatch_attempts=args.max_dispatch_attempts,
                operator=args.operator,
            )
        else:
            report = apifox_experiment_report(plan, mode="dry_run")
    except ApifoxExperimentError as exc:
        report = {
            "schema_version": "apifox-test-experiment.v1",
            "status": "blocked",
            "error_type": exc.__class__.__name__,
            "error": str(exc),
            "business_network_requests": 0,
            "database_writes": 0,
        }
        payload = json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
        sys.stdout.write(payload)
        return 3
    except Exception as exc:
        report = {
            "schema_version": "apifox-test-experiment.v1",
            "status": "error",
            "error_type": exc.__class__.__name__,
            "error": "Apifox experiment planning failed; inspect local service health",
            "business_network_requests": 0,
            "database_writes": 0,
        }
        payload = json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
        sys.stdout.write(payload)
        return 1
    payload = json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    sys.stdout.write(payload)
    if args.output:
        args.output.write_text(payload, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
