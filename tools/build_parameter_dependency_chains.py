import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from apiAnalysis.db.collection import raw_data, req_data, res_data, parameter_relation  # noqa: E402
from apiAnalysis.main import _ensure_mongo_connection  # noqa: E402
from apiAnalysis.tool.parameter_dependency import CANONICAL_ALIASES, canonical_name, leaf  # noqa: E402


READ_METHODS = {"GET", "HEAD", "OPTIONS"}
WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
LOW_VALUE_PARAMS = {"page", "offset", "limit", "size", "keyword", "keywords", "lang", "locale", "r", "_t"}
DO_NOT_AUTO = {"blacklist_user_id", "blacklist_client_id", "mobile", "email", "code", "seccode", "sign", "signature", "id"}


def load_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def family(path: str) -> str:
    parts = [p for p in re.sub(r"https?://[^/]+", "", str(path or "")).strip("/").split("/") if p]
    stable = []
    for part in parts:
        if part.startswith("{") or part.startswith("{{"):
            continue
        if part in {"v1", "v2", "single", "multiple", "batch"}:
            continue
        stable.append(part)
    return "/".join(stable[:2]) if stable else ""


def endpoint_text(endpoint: raw_data) -> str:
    meta = endpoint.source_meta or {}
    return " ".join(str(x or "") for x in [endpoint.path, endpoint.des, endpoint.tags, meta.get("name"), meta.get("operation_id")]).lower()


def pathid_filter_from_priority(path: Path, buckets: List[str], limit: int = 0) -> List[int]:
    if not path:
        return []
    doc = load_json(path)
    wanted = set(buckets or [])
    ids = []
    for item in doc.get("items") or []:
        if wanted and item.get("bucket") not in wanted and item.get("priority_bucket") not in wanted:
            continue
        try:
            ids.append(int(item.get("pathid")))
        except Exception:
            continue
        if limit and len(ids) >= limit:
            break
    return ids


def aliases_for(name: str) -> List[str]:
    low = leaf(name)
    canonical = canonical_name(name)
    return sorted({low, canonical, *CANONICAL_ALIASES.get(canonical, set())})


def build_response_index(needed_keys: List[str]) -> Dict[str, List[res_data]]:
    index: Dict[str, List[res_data]] = {}
    needed = sorted({key for key in needed_keys if key})
    if not needed:
        return index
    for response in res_data.objects(parameter__in=needed):
        keys = {leaf(response.parameter), canonical_name(response.parameter)}
        for key in keys:
            if key:
                index.setdefault(key, []).append(response)
    return index


def build_request_index(needed_keys: List[str]) -> Dict[str, List[req_data]]:
    index: Dict[str, List[req_data]] = {}
    needed = sorted({key for key in needed_keys if key})
    if not needed:
        return index
    for request in req_data.objects(parameter__in=needed):
        keys = {leaf(request.parameter), canonical_name(request.parameter)}
        for key in keys:
            if key:
                index.setdefault(key, []).append(request)
    return index


def project_id(endpoint: raw_data) -> str:
    meta = endpoint.source_meta or {}
    return str(meta.get("apifox_project_id") or meta.get("project_id") or meta.get("projectId") or "")


def _first_value(values: Any) -> Any:
    if isinstance(values, list):
        return next((value for value in values if value not in (None, "", [], {})), None)
    if values not in (None, "", [], {}):
        return values
    return None


def response_candidates(
    param: str,
    target: raw_data,
    max_candidates: int,
    response_index: Dict[str, List[res_data]],
    request_index: Dict[str, List[req_data]],
) -> List[Tuple[float, Dict[str, Any]]]:
    low = leaf(param)
    if low in LOW_VALUE_PARAMS:
        return []
    aliases = set(aliases_for(param))
    rows = []
    target_family = family(target.path)
    target_project = project_id(target)
    candidates_pool = []
    for key in aliases:
        candidates_pool.extend(response_index.get(key) or [])
    seen = set()
    for response in candidates_pool:
        if response.id in seen:
            continue
        seen.add(response.id)
        source = response.raw_data
        resp_leaf = leaf(response.parameter)
        resp_canonical = canonical_name(response.parameter)
        if not source or (source.method or "").upper() not in READ_METHODS:
            continue
        if target_project and project_id(source) != target_project:
            continue
        score = 0.30
        reasons = ["PARAM_ALIAS_MATCH" if resp_leaf != low else "PARAM_EXACT_MATCH"]
        if family(source.path) and family(source.path) == target_family:
            score += 0.25
            reasons.append("SAME_FAMILY")
        if target_family and target_family.split("/")[0] in family(source.path):
            score += 0.10
            reasons.append("RELATED_ROOT")
        if resp_leaf == low:
            score += 0.15
        if response.value:
            score += 0.15
            reasons.append("HAS_RESPONSE_SAMPLE_VALUE")
        relation = parameter_relation.objects(parameter=low, req_pathid=target.ptah_id, res_pathid=source.ptah_id).first()
        if relation:
            score += min(0.20, float(relation.score or 0) / 100.0)
            reasons.append(f"PARAMETER_RELATION:{relation.rule or ''}")
        rows.append((score, {
            "source_kind": "response_parameter",
            "res_pathid": source.ptah_id,
            "res_method": source.method,
            "res_path": source.path,
            "res_parameter": response.parameter,
            "source_value": _first_value(response.value),
            "res_family": family(source.path),
            "score": round(score, 4),
            "reason_codes": reasons,
        }))
    for key in aliases:
        for request in request_index.get(key) or []:
            source = request.raw_data
            if not source or (source.method or "").upper() not in READ_METHODS:
                continue
            if target_project and project_id(source) != target_project:
                continue
            value = _first_value(request.value)
            if value in (None, "", [], {}):
                continue
            req_leaf = leaf(request.parameter)
            score = 0.20
            reasons = ["UPSTREAM_REQUEST_PARAM_ALIAS_MATCH" if req_leaf != low else "UPSTREAM_REQUEST_PARAM_EXACT_MATCH"]
            if family(source.path) and family(source.path) == target_family:
                score += 0.25
                reasons.append("SAME_FAMILY")
            if target_family and target_family.split("/")[0] in family(source.path):
                score += 0.10
                reasons.append("RELATED_ROOT")
            if req_leaf == low:
                score += 0.10
            score += 0.08
            reasons.append("HAS_REQUEST_SAMPLE_VALUE")
            rows.append((score, {
                "source_kind": "request_parameter",
                "res_pathid": source.ptah_id,
                "res_method": source.method,
                "res_path": source.path,
                "res_parameter": request.parameter,
                "source_value": value,
                "res_family": family(source.path),
                "score": round(score, 4),
                "reason_codes": reasons,
            }))
    rows.sort(key=lambda item: (-item[0], item[1]["res_pathid"]))
    return rows[:max_candidates]


def build_chain_for(endpoint: raw_data, max_candidates: int, response_index: Dict[str, List[res_data]], request_index: Dict[str, List[req_data]]) -> Dict[str, Any]:
    params = []
    for req in req_data.objects(raw_data=endpoint):
        name = req.parameter or ""
        low = leaf(name)
        if not name or low in LOW_VALUE_PARAMS:
            continue
        candidates = response_candidates(name, endpoint, max_candidates=max_candidates, response_index=response_index, request_index=request_index)
        params.append({
            "parameter": name,
            "position": req.position,
            "required": bool(req.required),
            "type": req.type or "",
            "canonical": canonical_name(name),
            "auto_use": low not in DO_NOT_AUTO and bool(candidates) and (candidates[0][0] >= 0.65),
            "auto_use_reason": "high_confidence_reusable_dependency" if low not in DO_NOT_AUTO and candidates and candidates[0][0] >= 0.65 else "candidate_only_or_semantic_target",
            "upstreams": [item for _, item in candidates],
        })
    return {
        "pathid": endpoint.ptah_id,
        "method": endpoint.method,
        "path": endpoint.path,
        "name": (endpoint.source_meta or {}).get("name") or endpoint.des or "",
        "family": family(endpoint.path),
        "params": params,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Build explainable request-parameter dependency chains.")
    parser.add_argument("--priority", default="")
    parser.add_argument("--bucket", action="append", default=[])
    parser.add_argument("--pathid", action="append", default=[])
    parser.add_argument("--limit", type=int, default=80)
    parser.add_argument("--max-candidates", type=int, default=5)
    parser.add_argument("--out", default=str(Path("..") / ".secrets" / "parameter-dependency-chains.private.json"))
    args = parser.parse_args()

    _ensure_mongo_connection()
    pathids = [int(v) for v in args.pathid if str(v).strip()]
    if args.priority:
        pathids.extend(pathid_filter_from_priority(Path(args.priority), args.bucket, limit=args.limit))
    pathids = list(dict.fromkeys(pathids))
    if args.limit and not args.priority:
        pathids = pathids[: args.limit]

    endpoints = []
    if pathids:
        for pid in pathids:
            endpoint = raw_data.objects(ptah_id=pid).first()
            if endpoint:
                endpoints.append(endpoint)
    else:
        endpoints = list(raw_data.objects(method__in=list(WRITE_METHODS)).order_by("ptah_id").limit(args.limit))

    needed_keys = []
    for endpoint in endpoints:
        for req in req_data.objects(raw_data=endpoint):
            needed_keys.extend(aliases_for(req.parameter or ""))
    response_index = build_response_index(needed_keys)
    request_index = build_request_index(needed_keys)
    chains = [build_chain_for(endpoint, args.max_candidates, response_index, request_index) for endpoint in endpoints]
    summary = {
        "endpoints": len(chains),
        "params": sum(len(chain["params"]) for chain in chains),
        "auto_use_params": sum(1 for chain in chains for param in chain["params"] if param.get("auto_use")),
        "candidate_only_params": sum(1 for chain in chains for param in chain["params"] if not param.get("auto_use") and param.get("upstreams")),
    }
    output = {"summary": summary, "items": chains}
    Path(args.out).write_text(json.dumps(output, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"out": args.out, "summary": summary}, ensure_ascii=False, sort_keys=True))
    for chain in chains[:10]:
        print(f"{chain['pathid']} {chain['method']} {chain['path']}")
        for param in chain["params"][:8]:
            if param["upstreams"]:
                top = param["upstreams"][0]
                print(f"  {param['parameter']} -> {top['res_pathid']} {top['res_path']} score={top['score']} auto={param['auto_use']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
