"""Schedule one active, immutable authorization policy version."""
import argparse
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from apiAnalysis.main import _ensure_mongo_connection
from apiAnalysis.tool.authorization_matrix import schedule_authorization_matrix


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Expand and queue a bounded multi-principal authorization matrix.",
    )
    parser.add_argument("policy_version_id")
    parser.add_argument("--operator", default="cli")
    parser.add_argument("--retention-days", type=int, default=30)
    args = parser.parse_args()
    _ensure_mongo_connection()
    run, created = schedule_authorization_matrix(
        args.policy_version_id,
        operator=args.operator,
        retention_days=args.retention_days,
    )
    print(json.dumps({
        "run_id": str(run.id),
        "created": bool(created),
        "status": run.status,
        "case_count": int(run.total_cases or 0),
        "maximum_request_count": int((run.scope or {}).get("maximum_request_count") or 0),
    }, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()
