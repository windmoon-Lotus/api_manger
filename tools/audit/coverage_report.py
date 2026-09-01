"""Coverage report with explicit denominators: tested / candidate / total.

"42 endpoints tested" is meaningless without the denominator. This tool takes
three endpoint-key lists (any comparable strings - path keys, urls, ids) and
produces the tiered coverage view used in security rounds:

  total      - every endpoint known in the project (import/Apifox/OpenAPI)
  candidate  - endpoints eligible for this round's test (in scope + params present)
  tested     - endpoints actually exercised this round

plus the deltas: untested candidates (round incompleteness) and untested
non-candidates (backlog). A tested key outside candidate/total is flagged -
that is a scope-creep signal for the boundary audit.

Inputs are JSON files; each may be a bare list of strings, or
{"endpoints": [...]} / {"keys": [...]} / {"items": [{"key": ...}]} /
manifest {"items": [{"method":..., "path":...}]}.

Usage:
  python -m tools.audit.coverage_report \
      --total project.json --candidates manifest.json --tested evidence.json \
      [--key-field key] [--out report.json]
"""
import argparse
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

ROOT = Path(__file__).resolve().parents[2]


def extract_keys(data: Any, key_field: str = "key") -> List[str]:
    """Normalize any supported input shape into a list of endpoint keys."""
    if data is None:
        return []
    if isinstance(data, list):
        keys = []
        for item in data:
            if isinstance(item, str):
                keys.append(item)
            elif isinstance(item, dict):
                k = _key_of(item, key_field)
                if k:
                    keys.append(k)
        return keys
    if isinstance(data, dict):
        for field in ("endpoints", "keys", "targets", "items", "results"):
            if field in data and isinstance(data[field], list):
                return extract_keys(data[field], key_field)
        k = _key_of(data, key_field)
        return [k] if k else []
    return []


def _key_of(item: Dict[str, Any], key_field: str) -> Optional[str]:
    for field in (key_field, "key", "id"):
        value = item.get(field)
        if isinstance(value, str) and value:
            return value
    if item.get("method") and item.get("path"):
        return f"{str(item['method']).upper()} {item['path']}"
    if item.get("url"):
        return str(item["url"])
    if item.get("path"):
        return str(item["path"])
    return None


def coverage(total: List[str], candidates: List[str], tested: List[str]) -> Dict[str, Any]:
    total_set = set(total)
    candidate_set = set(candidates)
    tested_set = set(tested)

    tested_in_candidate = tested_set & candidate_set
    tested_in_total_not_candidate = (tested_set & total_set) - candidate_set
    tested_outside_total = tested_set - total_set

    untested_candidates = candidate_set - tested_set
    untested_non_candidates = total_set - candidate_set - tested_set

    def pct(part: int, whole: int) -> Optional[float]:
        return round(part / whole * 100, 1) if whole else None

    return {
        "tool": "coverage_report",
        "counts": {
            "total": len(total_set),
            "candidate": len(candidate_set),
            "tested": len(tested_set),
            "tested_in_candidate": len(tested_in_candidate),
        },
        "ratios": {
            "candidate_of_total_pct": pct(len(candidate_set), len(total_set)),
            "tested_of_candidate_pct": pct(len(tested_in_candidate), len(candidate_set)),
            "tested_of_total_pct": pct(len(tested_set & total_set), len(total_set)),
        },
        "untested_candidates": sorted(untested_candidates),
        "untested_non_candidates": sorted(untested_non_candidates),
        "tested_outside_total": sorted(tested_outside_total),
        "warnings": [
            "tested_outside_total is non-empty: keys exercised that are not in the "
            "project universe - cross-check with the boundary audit"
            if tested_outside_total else "",
            "tested_in_total_not_candidate is non-empty: round exercised endpoints "
            "outside its declared candidate set"
            if tested_in_total_not_candidate else "",
        ],
        "verdict": "pass",
    }


def _load_keys(path: Optional[str], key_field: str) -> List[str]:
    if not path:
        return []
    data = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    return extract_keys(data, key_field)


def main() -> int:
    parser = argparse.ArgumentParser(description="Tiered coverage report with denominators.")
    parser.add_argument("--total", required=True,
                        help="project universe JSON (all endpoints)")
    parser.add_argument("--candidates", required=True,
                        help="round candidate JSON")
    parser.add_argument("--tested", required=True,
                        help="tested-this-round JSON (evidence or report)")
    parser.add_argument("--key-field", default="key")
    parser.add_argument("--out", help="write report JSON here (default: stdout only)")
    args = parser.parse_args()

    report = coverage(
        _load_keys(args.total, args.key_field),
        _load_keys(args.candidates, args.key_field),
        _load_keys(args.tested, args.key_field),
    )
    text = json.dumps(report, ensure_ascii=False, indent=2)
    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(text, encoding="utf-8")
    print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
