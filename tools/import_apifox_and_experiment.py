"""Import Apifox details through import.v1, then plan or enqueue test experiments."""
import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from apiAnalysis.import_pipeline import ImportRequest, execute_import
from apiAnalysis.main import _ensure_mongo_connection
from apiAnalysis.tool.apifox_experiment import (
    ApifoxExperimentError,
    ApifoxExperimentLimits,
    apifox_experiment_report,
    build_apifox_experiment_plan,
    enqueue_apifox_experiment,
)


def _emit(report, output=None) -> None:
    payload = json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    sys.stdout.write(payload)
    if output:
        output.write_text(payload, encoding="utf-8")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--details-dir", required=True)
    parser.add_argument("--source-id", required=True, help="Stable Apifox project/source id.")
    parser.add_argument("--source-name", default="")
    parser.add_argument("--project-id", required=True)
    parser.add_argument("--env-id", required=True)
    parser.add_argument("--profile-revision-id", required=True)
    parser.add_argument("--base-url", default="")
    parser.add_argument("--server-map", type=Path)
    parser.add_argument("--run-parameter-analysis", action="store_true")
    parser.add_argument("--enqueue", action="store_true")
    parser.add_argument("--max-endpoints", type=int, default=50000)
    parser.add_argument("--max-workers", type=int, default=8)
    parser.add_argument("--per-host-workers", type=int, default=4)
    parser.add_argument("--min-interval-ms", type=int, default=25)
    parser.add_argument("--request-timeout", type=int, default=10)
    parser.add_argument("--lease-seconds", type=int, default=60)
    parser.add_argument("--max-dispatch-attempts", type=int, default=3)
    parser.add_argument("--operator", default="")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    server_map = None
    if args.server_map:
        server_map = json.loads(args.server_map.read_text(encoding="utf-8-sig"))
        if not isinstance(server_map, dict):
            parser.error("--server-map must contain a JSON object")
    try:
        _ensure_mongo_connection()
        outcome = execute_import(ImportRequest(
            source_type="apifox",
            source_path=args.details_dir,
            project_id=args.project_id,
            env_id=args.env_id,
            source_id=args.source_id,
            source_name=args.source_name,
            base_url=args.base_url,
            run_parameters=args.run_parameter_analysis,
            server_map=server_map,
        ))
        plan = build_apifox_experiment_plan(
            args.project_id,
            args.env_id,
            args.profile_revision_id,
            import_run_id=outcome.run.import_run_id,
            limits=ApifoxExperimentLimits(max_endpoints=args.max_endpoints),
        )
        if args.enqueue:
            experiment = enqueue_apifox_experiment(
                plan,
                plan.plan_sha256,
                max_workers=args.max_workers,
                per_host_workers=args.per_host_workers,
                min_interval_ms=args.min_interval_ms,
                request_timeout_seconds=args.request_timeout,
                lease_seconds=args.lease_seconds,
                max_dispatch_attempts=args.max_dispatch_attempts,
                operator=args.operator,
            )
        else:
            experiment = apifox_experiment_report(plan, mode="dry_run")
    except ApifoxExperimentError as exc:
        _emit({
            "schema_version": "apifox-import-experiment.v1",
            "status": "blocked",
            "error_type": exc.__class__.__name__,
            "error": str(exc),
            "business_network_requests": 0,
        }, args.output)
        return 3
    except Exception as exc:
        _emit({
            "schema_version": "apifox-import-experiment.v1",
            "status": "error",
            "error_type": exc.__class__.__name__,
            "error": "Apifox import/experiment preparation failed; inspect local service health",
            "business_network_requests": 0,
        }, args.output)
        return 1
    report = {
        "schema_version": "apifox-import-experiment.v1",
        "import": {
            "import_run_id": outcome.run.import_run_id,
            "status": outcome.run.status,
            "asset_count": int(outcome.summary.get("asset_count") or 0),
            "parameter_analysis": bool(outcome.summary.get("parameter_analysis")),
        },
        "experiment": experiment,
    }
    _emit(report, args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
