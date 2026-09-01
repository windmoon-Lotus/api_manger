"""Build Profile-scoped parameter archives from stored request samples."""
import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from apiAnalysis.main import _ensure_mongo_connection
from apiAnalysis.rule.profile_parameter_archive import (
    ProfileArchiveError,
    ProfileArchiveLimits,
    generate_profile_parameter_archive,
)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-id", required=True)
    parser.add_argument("--env-id", required=True)
    parser.add_argument("--profile-revision-id", required=True)
    parser.add_argument("--apply", action="store_true", help="Write the exact reviewed plan to Mongo.")
    parser.add_argument(
        "--expected-plan-sha256",
        help="Required with --apply; must equal the hash from the current dry-run.",
    )
    parser.add_argument("--max-samples", type=int, default=5000)
    parser.add_argument("--max-occurrences", type=int, default=20000)
    parser.add_argument("--max-values-per-archive", type=int, default=100)
    parser.add_argument("--max-value-bytes", type=int, default=512)
    parser.add_argument("--max-payload-bytes", type=int, default=65536)
    parser.add_argument("--report-sample-limit", type=int, default=20)
    parser.add_argument("--output", type=Path, help="Explicit optional value-free JSON output path.")
    args = parser.parse_args(argv)
    if args.apply and not args.expected_plan_sha256:
        parser.error("--apply requires --expected-plan-sha256")
    limits = ProfileArchiveLimits(
        max_samples=args.max_samples,
        max_occurrences=args.max_occurrences,
        max_values_per_archive=args.max_values_per_archive,
        max_value_bytes=args.max_value_bytes,
        max_payload_bytes=args.max_payload_bytes,
        report_sample_limit=args.report_sample_limit,
    )
    try:
        _ensure_mongo_connection()
        report = generate_profile_parameter_archive(
            args.project_id,
            args.env_id,
            args.profile_revision_id,
            apply=args.apply,
            expected_plan_sha256=args.expected_plan_sha256 or "",
            limits=limits,
        )
    except ProfileArchiveError as exc:
        report = {
            "schema_version": "profile-parameter-archive.v1",
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
            "schema_version": "profile-parameter-archive.v1",
            "status": "error",
            "error_type": exc.__class__.__name__,
            "error": "profile archive generation failed; inspect local service health",
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
    return 0 if report.get("status") == "complete" else 3


if __name__ == "__main__":
    raise SystemExit(main())
