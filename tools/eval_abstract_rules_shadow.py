"""Compare legacy and P0 rules against one project using bounded Mongo reads."""
import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from apiAnalysis.main import _ensure_mongo_connection
from apiAnalysis.rule.shadow_evaluation import (
    ShadowEvaluationError,
    ShadowLimits,
    evaluate_project_shadow,
)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-id", required=True)
    parser.add_argument("--env-id", required=True)
    parser.add_argument("--profile-revision-id", required=True)
    parser.add_argument("--max-endpoints", type=int, default=5000)
    parser.add_argument("--max-occurrences", type=int, default=20000)
    parser.add_argument("--max-pair-combinations", type=int, default=100000)
    parser.add_argument("--max-values-per-occurrence", type=int, default=1000)
    parser.add_argument("--sample-limit", type=int, default=20)
    parser.add_argument("--output", type=Path, help="Explicit optional JSON output path.")
    args = parser.parse_args(argv)
    limits = ShadowLimits(
        max_endpoints=args.max_endpoints,
        max_occurrences=args.max_occurrences,
        max_pair_combinations=args.max_pair_combinations,
        max_values_per_occurrence=args.max_values_per_occurrence,
        sample_limit=args.sample_limit,
    )
    try:
        _ensure_mongo_connection()
        report = evaluate_project_shadow(
            args.project_id, args.env_id, args.profile_revision_id, limits,
        )
    except ShadowEvaluationError as exc:
        json.dump({
            "schema_version": "abstract-rule-shadow.v1",
            "status": "blocked",
            "error_type": exc.__class__.__name__,
            "error": str(exc),
            "business_network_requests": 0,
            "database_writes": 0,
        }, sys.stdout, ensure_ascii=False, sort_keys=True, indent=2)
        sys.stdout.write("\n")
        return 3
    except Exception as exc:
        json.dump({
            "schema_version": "abstract-rule-shadow.v1",
            "status": "error",
            "error_type": exc.__class__.__name__,
            "error": "shadow evaluation failed; inspect local service health",
            "business_network_requests": 0,
            "database_writes": 0,
        }, sys.stdout, ensure_ascii=False, sort_keys=True, indent=2)
        sys.stdout.write("\n")
        return 1
    payload = json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    sys.stdout.write(payload)
    if args.output:
        args.output.write_text(payload, encoding="utf-8")
    return 0 if report.get("status") == "complete" else 3


if __name__ == "__main__":
    raise SystemExit(main())
