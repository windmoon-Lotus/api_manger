"""Dry-run or enqueue the unified P1 offline RuleSpec analysis."""
import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from apiAnalysis.main import _ensure_mongo_connection
from apiAnalysis.tool.parameter_analysis import enqueue_relation_analysis
from apiAnalysis.tool.unified_rule_analysis import (
    UnifiedAnalysisLimits,
    UnifiedRuleAnalysisError,
    analyze_project,
)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Run bounded offline RuleSpec analysis; no business request is sent.",
    )
    parser.add_argument("--project-id", required=True)
    parser.add_argument("--env-id", required=True)
    parser.add_argument("--profile-id", default="")
    parser.add_argument("--enqueue", action="store_true")
    parser.add_argument("--expected-input-watermark-sha256", default="")
    parser.add_argument("--operator", default="")
    parser.add_argument("--max-relation-pairs", type=int, default=1000000)
    args = parser.parse_args(argv)
    _ensure_mongo_connection()
    try:
        analysis = analyze_project(
            args.project_id, env_id=args.env_id, profile_id=args.profile_id,
            limits=UnifiedAnalysisLimits(max_relation_pairs=args.max_relation_pairs),
        )
        report = dict(analysis.summary)
        report["database_writes"] = 0
        report["queued"] = False
        if args.enqueue:
            if args.expected_input_watermark_sha256 != analysis.input_watermark_sha256:
                raise UnifiedRuleAnalysisError(
                    "expected input watermark does not match the current projection"
                )
            run, created = enqueue_relation_analysis(
                args.project_id, env_id=analysis.env_id,
                source_profile_id=analysis.profile_id,
                consumer_profile_id=analysis.profile_id,
                operator=args.operator,
            )
            report["queued"] = True
            report["run_id"] = str(run.id)
            report["run_created"] = bool(created)
            report["database_writes"] = 1 if created else 0
        print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
        return 0
    except UnifiedRuleAnalysisError as exc:
        print(json.dumps({
            "schema_version": "unified-rule-analysis-report.v1",
            "status": "blocked", "error_type": exc.__class__.__name__,
            "error": str(exc), "business_network_requests": 0,
            "database_writes": 0,
        }, ensure_ascii=False, sort_keys=True))
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
