"""Route mixed Workspace/HAR observations to ApiProjects conservatively."""
from collections import defaultdict
from typing import Any, Dict, Iterable, List
from urllib.parse import urlparse

from apiAnalysis.tool.api_signature import abstract_signature


ROUTING_RULE_VERSION = "v1"
AUTO_ASSIGN_THRESHOLD = 0.80


def _normalized_observation(observation: Dict[str, Any]) -> Dict[str, str]:
    url = str(observation.get("url") or "")
    parsed = urlparse(url)
    method = str(observation.get("method") or "GET").upper()
    path = str(observation.get("path") or parsed.path or "/")
    domain = str(observation.get("domain") or parsed.netloc or "").lower()
    signature = str(observation.get("abstract_signature") or abstract_signature(method, path))
    return {"method": method, "path": path, "domain": domain, "abstract_signature": signature}


def route_observation(
    observation: Dict[str, Any],
    assets: Iterable[Dict[str, Any]],
    bindings: Iterable[Dict[str, Any]] = (),
    explicit_project_id: str = "",
) -> Dict[str, Any]:
    """Return assigned/ambiguous/unassigned without silently guessing by domain."""
    if explicit_project_id:
        return {
            "decision": "assigned",
            "selected_project_id": str(explicit_project_id),
            "confidence": 1.0,
            "reason_codes": ["explicit_project_selection"],
            "candidate_projects": [{"project_id": str(explicit_project_id), "score": 1.0, "reason_codes": ["explicit_project_selection"]}],
            "rule_version": ROUTING_RULE_VERSION,
        }

    obs = _normalized_observation(observation)
    scores: Dict[str, float] = defaultdict(float)
    reasons: Dict[str, List[str]] = defaultdict(list)

    for asset in assets or []:
        project_id = str(asset.get("project_id") or "")
        if not project_id:
            continue
        method = str(asset.get("method") or "").upper()
        domain = str(asset.get("domain") or "").lower()
        path = str(asset.get("path") or "")
        signature = str(asset.get("abstract_signature") or (abstract_signature(method, path) if method and path else ""))
        if method == obs["method"] and signature and signature == obs["abstract_signature"]:
            score = 0.98 if domain and domain == obs["domain"] else 0.90
            if score > scores[project_id]:
                scores[project_id] = score
            reasons[project_id].append("abstract_signature_match")
            if domain and domain == obs["domain"]:
                reasons[project_id].append("exact_host_match")
        elif method == obs["method"] and domain == obs["domain"] and path == obs["path"]:
            scores[project_id] = max(scores[project_id], 0.95)
            reasons[project_id].append("exact_host_method_path")

    for binding in bindings or []:
        project_id = str(binding.get("project_id") or "")
        rules = binding.get("routing_rules") or {}
        hosts = {str(item).lower() for item in rules.get("hosts") or []}
        prefixes = [str(item) for item in rules.get("path_prefixes") or []]
        signatures = {str(item) for item in rules.get("signatures") or []}
        signature_key = "{} {}".format(obs["method"], obs["abstract_signature"])
        if project_id and signature_key in signatures:
            scores[project_id] = max(scores[project_id], 0.99)
            reasons[project_id].append("binding_signature")
            continue
        if project_id and obs["domain"] in hosts:
            score = 0.82 if any(obs["path"].startswith(prefix) for prefix in prefixes) else 0.65
            scores[project_id] = max(scores[project_id], score)
            reasons[project_id].append("binding_host_path" if score >= 0.8 else "binding_host_only")

    candidates = sorted(
        ({"project_id": project_id, "score": round(score, 3), "reason_codes": sorted(set(reasons[project_id]))}
         for project_id, score in scores.items()),
        key=lambda item: (-item["score"], item["project_id"]),
    )
    if not candidates or candidates[0]["score"] < AUTO_ASSIGN_THRESHOLD:
        return {"decision": "unassigned", "selected_project_id": "", "confidence": candidates[0]["score"] if candidates else 0.0, "reason_codes": ["no_high_confidence_project_match"], "candidate_projects": candidates, "rule_version": ROUTING_RULE_VERSION}
    top = candidates[0]
    tied = [item for item in candidates if abs(item["score"] - top["score"]) < 0.02]
    if len(tied) > 1:
        return {"decision": "ambiguous", "selected_project_id": "", "confidence": top["score"], "reason_codes": ["multiple_equal_project_matches"], "candidate_projects": candidates, "rule_version": ROUTING_RULE_VERSION}
    return {"decision": "assigned", "selected_project_id": top["project_id"], "confidence": top["score"], "reason_codes": top["reason_codes"], "candidate_projects": candidates, "rule_version": ROUTING_RULE_VERSION}
