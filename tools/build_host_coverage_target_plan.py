"""Build a prioritized safe-GET module plan for a target placement coverage."""
from __future__ import annotations

import argparse
import json
import math
import re
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Mapping, Sequence, Tuple


HTTP_METHODS = {"get", "post", "put", "patch", "delete", "head", "options"}
PROJECT_RE = re.compile(r"apifox-export-(\d+)-(.+)\.openapi\.json$")
ENDPOINT_ID_RE = re.compile(r"/apis/api-(\d+)-run(?:$|[/?#])")


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def safe_gets(openapi_dir: Path) -> Dict[Tuple[str, str], List[Dict[str, Any]]]:
    result: Dict[Tuple[str, str], List[Dict[str, Any]]] = defaultdict(list)
    for path in openapi_dir.glob("*.openapi.json"):
        match = PROJECT_RE.match(path.name)
        if not match:
            continue
        project_id = match.group(1)
        doc = load_json(path)
        for route, path_item in (doc.get("paths") or {}).items():
            if not isinstance(path_item, Mapping):
                continue
            operation = path_item.get("get")
            if not isinstance(operation, Mapping) or "{" in route:
                continue
            parameters = list(path_item.get("parameters") or []) + list(operation.get("parameters") or [])
            if any(isinstance(item, Mapping) and item.get("required") for item in parameters):
                continue
            run_url = str(operation.get("x-run-in-apifox") or "")
            endpoint_match = ENDPOINT_ID_RE.search(run_url)
            result[(project_id, str(operation.get("x-apifox-folder") or "(root)"))].append({
                "id": int(endpoint_match.group(1)) if endpoint_match else None,
                "method": "get", "path": route,
                "name": str(operation.get("summary") or ""),
                "status": str(operation.get("x-apifox-status") or "unknown"),
                "folder": str(operation.get("x-apifox-folder") or "(root)"),
            })
    return result


def choose_representative(items: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
    rank = {"released": 0, "testing": 1, "developing": 2, "deprecated": 3, "obsolete": 4}
    return dict(sorted(items, key=lambda x: (
        rank.get(str(x.get("status") or "").lower(), 5),
        0 if x.get("id") else 1,
        len(str(x.get("path") or "")),
        str(x.get("path") or ""),
    ))[0])


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--openapi-dir", type=Path, required=True)
    parser.add_argument("--placement-jsonl", type=Path, required=True)
    parser.add_argument("--target-percent", type=float, default=75.0)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    rows = [json.loads(line) for line in args.placement_jsonl.read_text(encoding="utf-8").splitlines()]
    total = len(rows)
    accepted = {"runtime_confirmed", "direct_candidate", "module_candidate"}
    base = sum(row.get("placement_status") in accepted for row in rows)
    target = math.ceil(total * max(0.0, min(args.target_percent, 100.0)) / 100.0)
    needed = max(0, target - base)
    grouped: Dict[Tuple[str, str], List[Dict[str, Any]]] = defaultdict(list)
    for row in rows:
        grouped[(str(row["project_id"]), str(row["folder"]))].append(row)
    safe = safe_gets(args.openapi_dir)
    candidates = []
    for key, module_rows in grouped.items():
        unknown = sum(row.get("placement_status") == "mapping_unknown" for row in module_rows)
        if not unknown or key not in safe:
            continue
        representative = choose_representative(safe[key])
        evidence_hosts = sorted({
            candidate["host"] for row in module_rows
            for candidate in row.get("host_candidates") or []
        })
        candidates.append({
            "project_id": key[0], "folder": key[1],
            "unknown_operations_covered": unknown,
            "representative": representative,
            "existing_evidence_hosts": evidence_hosts,
        })
    candidates.sort(key=lambda x: (
        -int(x["unknown_operations_covered"]),
        str(x["project_id"]), str(x["folder"]),
    ))
    selected = []
    covered = 0
    for item in candidates:
        if covered >= needed:
            break
        selected.append(item)
        covered += int(item["unknown_operations_covered"])
    args.output_dir.mkdir(parents=True, exist_ok=True)
    plan = {
        "schema_version": "host-coverage-target-plan.v1",
        "total_operations": total,
        "base_accepted_operations": base,
        "target_percent": args.target_percent,
        "target_operations": target,
        "additional_operations_needed": needed,
        "selected_modules": len(selected),
        "selected_unknown_operations": covered,
        "projected_operations": base + covered,
        "projected_percent": round(100.0 * (base + covered) / total, 2),
        "selection_boundary": "One safe GET route-confirmation representative may promote only its exact folder to module_candidate.",
        "modules": selected,
    }
    (args.output_dir / "coverage-target-plan.json").write_text(
        json.dumps(plan, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8",
    )
    by_project: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for item in selected:
        representative = item["representative"]
        if representative.get("id"):
            by_project[item["project_id"]].append(representative)
    detail_dir = args.output_dir / "representative-endpoint-lists"
    detail_dir.mkdir(parents=True, exist_ok=True)
    for project_id, endpoints in by_project.items():
        (detail_dir / ("project-{}.json".format(project_id))).write_text(
            json.dumps({"success": True, "data": endpoints}, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
    print(json.dumps({
        "base": base, "target": target, "selected_modules": len(selected),
        "selected_unknown_operations": covered,
        "projected_percent": plan["projected_percent"],
        "output_dir": str(args.output_dir),
    }, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()
