"""
Backfill outcome_class for existing security_test_result documents.

Usage:
    py -3.9 tools/backfill_outcome_class.py [--run-id RUN_ID] [--dry-run]
"""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from apiAnalysis.db.collection import security_test_result
from apiAnalysis.tool.result_review import backfill_outcome_class, project_outcome_class


def main():
    parser = argparse.ArgumentParser(description="Backfill outcome_class on security_test_result")
    parser.add_argument("--run-id", help="Only backfill results for this run ID")
    parser.add_argument("--dry-run", action="store_true", help="Show what would change without writing")
    args = parser.parse_args()

    from mongoengine import connect
    from apiAnalysis.conf.secret import MONGODB_HOST, MONGODB_PORT, MONGODB_DB
    connect(db=MONGODB_DB, host=MONGODB_HOST, port=MONGODB_PORT)

    qs = security_test_result.objects(outcome_class__in=[None, ""])
    if args.run_id:
        from bson import ObjectId
        qs = qs.filter(run_id=ObjectId(args.run_id))

    total = qs.count()
    print(f"Found {total} results without outcome_class")

    if args.dry_run:
        for r in qs.limit(20):
            projected = project_outcome_class(r.verdict)
            print(f"  {r.id} verdict={r.verdict} -> outcome_class={projected}")
        if total > 20:
            print(f"  ... and {total - 20} more")
        return

    updated = backfill_outcome_class(
        run_id=args.run_id,
        batch_size=total or 500,
    )
    print(f"Updated {updated} results")


if __name__ == "__main__":
    main()
