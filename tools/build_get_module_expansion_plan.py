"""Build a read-only GET Host-probe expansion plan.

Unlike the conservative first pass, this includes templated GET routes and
required query parameters.  Only inert synthetic values are used; the original
OpenAPI path is retained as the asset key while ``probe_path`` is sent on wire.
"""
from __future__ import annotations

import argparse
import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Mapping, Sequence, Tuple
from urllib.parse import urlencode

from build_host_coverage_target_plan import PROJECT_RE, ENDPOINT_ID_RE


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def synthetic_value(parameter: Mapping[str, Any]) -> str:
    schema = parameter.get("schema") if isinstance(parameter.get("schema"), Mapping) else {}
    kind = str(schema.get("type") or parameter.get("type") or "").lower()
    fmt = str(schema.get("format") or "").lower()
    name = str(parameter.get("name") or "").lower()
    if fmt == "uuid" or "uuid" in name:
        return "00000000-0000-4000-8000-000000000000"
    if kind in {"integer", "number"} or name.endswith("id") or name == "id":
        return "0"
    if kind == "boolean":
        return "false"
    return "__host_probe__"


def parameters_by_key(path_item: Mapping[str, Any], operation: Mapping[str, Any]) -> Dict[Tuple[str, str], Mapping[str, Any]]:
    result: Dict[Tuple[str, str], Mapping[str, Any]] = {}
    for item in list(path_item.get("parameters") or []) + list(operation.get("parameters") or []):
        if not isinstance(item, Mapping) or "$ref" in item:
            continue
        result[(str(item.get("in") or ""), str(item.get("name") or ""))] = item
    return result


def build_probe_path(route: str, parameters: Mapping[Tuple[str, str], Mapping[str, Any]]) -> str:
    probe = route
    for name in re.findall(r"\{([^{}]+)\}", route):
        parameter = parameters.get(("path", name), {"name": name})
        probe = probe.replace("{" + name + "}", synthetic_value(parameter))
    query = []
    for (location, name), parameter in sorted(parameters.items()):
        if location == "query" and parameter.get("required"):
            query.append((name, synthetic_value(parameter)))
    if query:
        probe += ("&" if "?" in probe else "?") + urlencode(query)
    return probe


def choose_representative(items: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
    rank = {"released": 0, "testing": 1, "developing": 2, "deprecated": 3, "obsolete": 4}
    return dict(sorted(items, key=lambda x: (
        rank.get(str(x.get("status") or "").lower(), 5),
        0 if "{" not in str(x.get("path") or "") else 1,
        len(str(x.get("probe_path") or "")),
        str(x.get("path") or ""),
    ))[0])


def get_routes(openapi_dir: Path) -> Dict[Tuple[str, str], List[Dict[str, Any]]]:
    grouped: Dict[Tuple[str, str], List[Dict[str, Any]]] = defaultdict(list)
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
            if not isinstance(operation, Mapping):
                continue
            params = parameters_by_key(path_item, operation)
            run_url = str(operation.get("x-run-in-apifox") or "")
            endpoint_match = ENDPOINT_ID_RE.search(run_url)
            folder = str(operation.get("x-apifox-folder") or "(root)")
            grouped[(project_id, folder)].append({
                "id": int(endpoint_match.group(1)) if endpoint_match else None,
                "method": "get",
                "path": str(route),
                "probe_path": build_probe_path(str(route), params),
                "name": str(operation.get("summary") or ""),
                "status": str(operation.get("x-apifox-status") or "unknown"),
                "folder": folder,
                "synthetic_probe": True,
            })
    return grouped


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--openapi-dir", type=Path, required=True)
    parser.add_argument("--placement-jsonl", type=Path, required=True)
    parser.add_argument("--exclude-plan", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    rows = [json.loads(line) for line in args.placement_jsonl.read_text(encoding="utf-8").splitlines()]
    module_rows: Dict[Tuple[str, str], List[Dict[str, Any]]] = defaultdict(list)
    for row in rows:
        module_rows[(str(row["project_id"]), str(row["folder"]))].append(row)
    excluded_doc = load_json(args.exclude_plan)
    excluded = {
        (str(item.get("project_id") or ""), str(item.get("folder") or ""))
        for item in excluded_doc.get("modules") or []
    }
    routes = get_routes(args.openapi_dir)
    modules = []
    for key, candidates in routes.items():
        if key in excluded:
            continue
        unknown = sum(row.get("placement_status") == "mapping_unknown" for row in module_rows.get(key, []))
        if not unknown:
            continue
        modules.append({
            "project_id": key[0],
            "folder": key[1],
            "unknown_operations_covered": unknown,
            "representative": choose_representative(candidates),
            "existing_evidence_hosts": sorted({
                candidate["host"]
                for row in module_rows.get(key, [])
                for candidate in row.get("host_candidates") or []
            }),
        })
    modules.sort(key=lambda item: (
        -int(item["unknown_operations_covered"]),
        str(item["project_id"]), str(item["folder"]),
    ))
    output = {
        "schema_version": "host-coverage-expansion-plan.v1",
        "request_policy": {
            "method": "GET",
            "authentication": "none",
            "path_and_required_query_values": "inert_synthetic_only",
            "no_real_resource_identifiers": True,
        },
        "excluded_modules": len(excluded),
        "selected_modules": len(modules),
        "selected_unknown_operations": sum(int(item["unknown_operations_covered"]) for item in modules),
        "modules": modules,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(output, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps({
        "modules": output["selected_modules"],
        "unknown_operations": output["selected_unknown_operations"],
        "output": str(args.output),
    }, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()
