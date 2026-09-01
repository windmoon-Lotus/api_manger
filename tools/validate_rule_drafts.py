"""Plan or enqueue test-environment validation for offline RuleSpec drafts."""
import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from apiAnalysis.main import _ensure_mongo_connection
from apiAnalysis.tool.apifox_mutation_lifecycle import MutationLifecycleLimits
from apiAnalysis.tool.rule_plan_validation import (
    RuleDraftValidationError,
    build_rule_draft_validation_plan,
    enqueue_rule_draft_validation,
    rule_draft_validation_report,
)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-id", required=True)
    parser.add_argument("--env-id", required=True)
    parser.add_argument("--profile-revision-id", required=True)
    parser.add_argument(
        "--mutation-lifecycle", action="store_true",
        help="Plan full mutation/readback/cleanup; default is read-only preflight.",
    )
    parser.add_argument("--pathid", action="append", type=int, default=[])
    parser.add_argument("--archive-value-index", type=int, default=0)
    parser.add_argument("--enqueue", action="store_true")
    parser.add_argument("--expected-promotion-sha256", default="")
    parser.add_argument("--max-drafts", type=int, default=500)
    parser.add_argument("--max-assets", type=int, default=50000)
    parser.add_argument("--max-candidates", type=int, default=1000)
    parser.add_argument("--max-workers", type=int, default=2)
    parser.add_argument("--per-host-workers", type=int, default=1)
    parser.add_argument("--min-interval-ms", type=int, default=250)
    parser.add_argument("--request-timeout", type=int, default=10)
    parser.add_argument("--operator", default="rule-draft-validator")
    args = parser.parse_args(argv)
    if args.enqueue and not args.expected_promotion_sha256:
        parser.error("--enqueue requires --expected-promotion-sha256")
    try:
        _ensure_mongo_connection()
        plan = build_rule_draft_validation_plan(
            args.project_id, args.env_id, args.profile_revision_id,
            preflight_only=not args.mutation_lifecycle,
            max_drafts=args.max_drafts,
            selected_pathids=tuple(args.pathid),
            archive_value_index=args.archive_value_index,
            lifecycle_limits=MutationLifecycleLimits(
                max_assets=args.max_assets, max_candidates=args.max_candidates,
            ),
        )
        report = enqueue_rule_draft_validation(
            plan, args.expected_promotion_sha256,
            max_workers=args.max_workers, per_host_workers=args.per_host_workers,
            min_interval_ms=args.min_interval_ms,
            request_timeout_seconds=args.request_timeout, operator=args.operator,
        ) if args.enqueue else rule_draft_validation_report(plan)
        code = 0
    except Exception as exc:
        report = {
            "schema_version": "rule-draft-validation.v1", "status": "blocked",
            "error_type": exc.__class__.__name__, "error": str(exc),
            "business_network_requests": 0,
        }
        code = 3 if isinstance(exc, RuleDraftValidationError) else 1
    print(json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
