"""Print bounded real request previews for an existing execution run."""
import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from apiAnalysis.main import _ensure_mongo_connection
from apiAnalysis.tool.execution_request_evidence import (
    ExecutionRequestEvidenceError,
    build_run_request_evidence,
)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Read an existing run and print redacted, bounded request values without network access.",
    )
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--limit", type=int, default=20)
    parser.add_argument("--ordinal", type=int, action="append", default=[])
    args = parser.parse_args()
    _ensure_mongo_connection()
    try:
        report = build_run_request_evidence(
            args.run_id, limit=args.limit, ordinals=args.ordinal,
        )
    except ExecutionRequestEvidenceError as exc:
        parser.error(str(exc))
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
