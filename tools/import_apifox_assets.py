import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from apiAnalysis.main import _ensure_mongo_connection
from apiAnalysis.tool.apifox_importer import import_apifox_details


def main() -> int:
    parser = argparse.ArgumentParser(description="Import Apifox endpoint detail JSON into api_manger assets.")
    parser.add_argument("--details-dir", required=True, help="Directory containing `apifox endpoint get` JSON files.")
    parser.add_argument("--base-url", required=True, help="Execution base URL, for example https://api.example.com.")
    parser.add_argument("--limit", type=int, default=0, help="Optional file limit for a trial import.")
    parser.add_argument("--server-map", default="", help="Optional JSON file: Apifox serverId -> baseUrl, for multi-host projects.")
    args = parser.parse_args()

    _ensure_mongo_connection()
    server_map = {}
    if args.server_map:
        server_map = json.loads(Path(args.server_map).read_text(encoding="utf-8-sig"))
    summary = import_apifox_details(Path(args.details_dir), base_url=args.base_url, limit=args.limit, server_map=server_map)
    public_summary = dict(summary)
    public_summary["pathids_sample"] = public_summary.pop("pathids", [])[:20]
    print(json.dumps(public_summary, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
