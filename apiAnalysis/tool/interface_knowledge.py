"""Project-scoped relation discovery and live interface-chain projection.

Documentation and traffic contribute different evidence:

* Apifox/OpenAPI/Postman describe complete endpoint structure and project groups.
* HAR/mitm/request samples provide concrete values and observed frequency.

The discovery pass combines both without replacing confirmed relations.  It is
safe to run after every import: only pairs touching newly imported endpoints
are reconsidered, while verified/manual conclusions remain an auditable
baseline and schema drift merely sends them back to re-validation.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import re
from collections import Counter, defaultdict
from types import SimpleNamespace
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from apiAnalysis.db.collection import (
    parameter_relation,
    raw_data,
    req_data,
    request_sample,
    res_data,
)
from apiAnalysis.tool.parameter_identity import normalized_leaf, parameter_identity
from apiAnalysis.tool.parameter_locator import LOCATOR_VERSION, locator_from_path


DISCOVERY_VERSION = "interface-knowledge-v3"
READ_METHODS = {"GET", "HEAD", "OPTIONS"}
MUTATION_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
DOCUMENT_SOURCES = {"apifox", "openapi", "swagger", "postman"}
TRAFFIC_SOURCES = {"traffic", "har", "mitm", "mitmproxy", "flow"}

GENERIC_PATH_SEGMENTS = {
    "api", "v1", "v2", "v3", "v4", "std", "webapi", "single", "multiple",
    "batch", "list", "detail", "details", "info", "infos", "search", "page",
}
ACTION_SEGMENTS = {
    "create", "add", "new", "insert", "update", "edit", "modify", "delete",
    "remove", "query", "get", "set", "cancel", "enable", "disable",
}
NOISE_PARAMETERS = {
    "page", "page_size", "pagesize", "size", "limit", "offset", "cursor",
    "keyword", "keywords", "sort", "order", "locale", "lang", "timestamp",
    "nonce", "sign", "signature", "authorization", "access_token", "token",
    "cookie", "password", "passwd", "secret", "content_type", "message", "msg",
    "data",
}
GENERIC_IDENTITIES = {
    "id", "user_id", "userid", "client_id", "clientid", "group_id", "groupid",
    "network_id", "networkid", "sn", "account", "code", "key", "name", "type",
    "status",
}
IDENTITY_RE = re.compile(
    r"(^id$|_id$|id$|_ids$|ids$|uuid$|guid$|sn$|account$|tenant$|entid$)", re.I,
)


def _text(value: Any) -> str:
    return str(value or "").strip()


def _path_parts(path: Any) -> List[str]:
    value = re.sub(r"^https?://[^/]+", "", _text(path))
    return [item for item in value.strip("/").split("/") if item]


def resource_family(path: Any) -> str:
    """Return a readable resource family without version/action noise."""
    stable: List[str] = []
    for raw in _path_parts(path):
        item = raw.lower()
        if item.startswith("{") and item.endswith("}"):
            continue
        if item in GENERIC_PATH_SEGMENTS:
            continue
        if item in ACTION_SEGMENTS and stable:
            continue
        stable.append(item)
    return "/".join(stable[:2]) if stable else "root"


def _type_family(value: Any) -> str:
    value = _text(value).lower()
    if value in {"integer", "int", "long", "number", "float", "double", "decimal"}:
        return "number"
    if value in {"str", "string", "char", "text"}:
        return "string"
    if value in {"bool", "boolean"}:
        return "boolean"
    if value in {"array", "list"}:
        return "array"
    if value in {"object", "dict", "map"}:
        return "object"
    return value


def _normalized_values(row: Any) -> set:
    values = set()
    for value in getattr(row, "value", None) or []:
        if value in (None, "", [], {}):
            continue
        try:
            text = json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
        except (TypeError, ValueError):
            text = _text(value)
        if text.lower() not in {"0", "1", "true", "false", "null", '""'}:
            values.add(text)
    return values


def _is_identity(identity: str, target: Any) -> bool:
    return bool(
        IDENTITY_RE.search(identity or "")
        or _text(getattr(target, "position", "")).lower() == "path"
    )


def _endpoint_group(endpoint: Any) -> Tuple[str, str, str]:
    meta = dict(getattr(endpoint, "source_meta", None) or {})
    return (
        _text(meta.get("apifox_module_id") or meta.get("module_id")),
        _text(meta.get("apifox_folder_id") or meta.get("folder_id")),
        resource_family(getattr(endpoint, "path", "")),
    )


def _evidence_sources(source: Any, target: Any, traffic_pathids: set,
                      value_overlap: bool = False) -> List[str]:
    result = set()
    for endpoint in (source, target):
        origin = _text(getattr(endpoint, "source", "")).lower()
        if origin in DOCUMENT_SOURCES or _text(getattr(endpoint, "asset_kind", "")) == "abstract":
            result.add("document")
        if origin in TRAFFIC_SOURCES or _text(getattr(endpoint, "asset_kind", "")) == "concrete":
            result.add("traffic")
        if getattr(endpoint, "ptah_id", None) in traffic_pathids:
            result.add("traffic")
    return sorted(result or {"document"})


def relation_candidate_score(source_doc: Any, target_doc: Any, source_endpoint: Any,
                             target_endpoint: Any, *, traffic_pathids: Optional[set] = None
                             ) -> Optional[Dict[str, Any]]:
    """Score one same-identity response -> request mapping.

    Generic fields such as ``id`` need same-folder or same-resource evidence;
    optional business fields need even stronger grouping.  This keeps a large
    specification useful without creating a project-wide Cartesian product.
    """
    traffic_pathids = traffic_pathids or set()
    identity = parameter_identity(
        getattr(target_doc, "parameter", ""), getattr(target_doc, "canonical_name", ""),
    )
    source_identity = parameter_identity(
        getattr(source_doc, "parameter", ""), getattr(source_doc, "canonical_name", ""),
    )
    if not identity or identity != source_identity or identity in NOISE_PARAMETERS:
        return None
    if _text(getattr(source_endpoint, "method", "")).upper() not in READ_METHODS:
        return None
    if getattr(source_endpoint, "ptah_id", None) == getattr(target_endpoint, "ptah_id", None):
        return None

    score = 40.0
    reasons = ["PARAMETER_IDENTITY_MATCH", "PROJECT_SCOPE_MATCH"]
    if normalized_leaf(getattr(source_doc, "parameter", "")) == normalized_leaf(
            getattr(target_doc, "parameter", "")):
        score += 10.0
        reasons.append("PARAMETER_EXACT_MATCH")

    source_module, source_folder, source_family = _endpoint_group(source_endpoint)
    target_module, target_folder, target_family = _endpoint_group(target_endpoint)
    same_folder = bool(source_folder and source_folder == target_folder)
    same_family = bool(source_family and source_family == target_family)
    if same_folder:
        score += 25.0
        reasons.append("DOCUMENT_SAME_FOLDER")
    elif source_module and source_module == target_module:
        score += 8.0
        reasons.append("DOCUMENT_SAME_MODULE")
    if same_family:
        score += 20.0
        reasons.append("SAME_RESOURCE_FAMILY")
    elif source_family.split("/")[0] == target_family.split("/")[0]:
        score += 7.0
        reasons.append("RELATED_RESOURCE_ROOT")

    source_type = _type_family(getattr(source_doc, "type", ""))
    target_type = _type_family(getattr(target_doc, "type", ""))
    if source_type and source_type == target_type:
        score += 5.0
        reasons.append("TYPE_COMPATIBLE")
    if bool(getattr(target_doc, "required", False)):
        score += 5.0
        reasons.append("TARGET_REQUIRED")
    if _text(getattr(target_doc, "position", "")).lower() == "path":
        score += 8.0
        reasons.append("TARGET_PATH_PARAMETER")
    if _text(getattr(target_endpoint, "method", "")).upper() in MUTATION_METHODS:
        score += 5.0
        reasons.append("TARGET_MUTATION_INPUT")

    overlap = _normalized_values(source_doc) & _normalized_values(target_doc)
    traffic_supported = bool(
        getattr(source_endpoint, "ptah_id", None) in traffic_pathids
        or getattr(target_endpoint, "ptah_id", None) in traffic_pathids
        or _text(getattr(source_endpoint, "source", "")).lower() in TRAFFIC_SOURCES
        or _text(getattr(target_endpoint, "source", "")).lower() in TRAFFIC_SOURCES
    )
    if overlap:
        score += min(20.0, 10.0 + len(overlap) * 3.0)
        reasons.append("TRAFFIC_VALUE_OVERLAP" if traffic_supported else "DOCUMENT_EXAMPLE_OVERLAP")
    if traffic_supported:
        score += 5.0
        reasons.append("TRAFFIC_SAMPLE_SUPPORT")

    identity_field = _is_identity(identity, target_doc)
    if identity in GENERIC_IDENTITIES and not (same_folder or same_family):
        score -= 30.0
        reasons.append("GENERIC_NAME_CROSS_GROUP_PENALTY")
    minimum = 68.0 if identity_field or bool(getattr(target_doc, "required", False)) else 90.0
    if score < minimum:
        return None
    return {
        "parameter": identity,
        "score": round(min(100.0, score), 2),
        "reason_codes": reasons,
        "relation_kind": "identifier" if identity_field else (
            "required_input" if bool(getattr(target_doc, "required", False)) else "business_field"
        ),
        "value_overlap_count": len(overlap),
        "evidence_sources": _evidence_sources(
            source_endpoint, target_endpoint, traffic_pathids, bool(overlap),
        ),
    }


def _best_occurrence(current: Optional[Any], candidate: Any) -> Any:
    if current is None:
        return candidate
    current_score = (
        bool(getattr(current, "locator", None)), bool(getattr(current, "required", False)),
        -len(_text(getattr(current, "parameter", ""))),
    )
    candidate_score = (
        bool(getattr(candidate, "locator", None)), bool(getattr(candidate, "required", False)),
        -len(_text(getattr(candidate, "parameter", ""))),
    )
    return candidate if candidate_score > current_score else current


def _locator(row: Any, direction: str) -> Dict[str, Any]:
    return dict(getattr(row, "locator", None) or {}) or locator_from_path(
        getattr(row, "parameter", ""),
        direction=direction,
        position=getattr(row, "position", "") or "body",
    )


def _schema_fingerprint(source_doc: Any, target_doc: Any, source_endpoint: Any,
                        target_endpoint: Any) -> str:
    payload = {
        "source_pathid": int(source_endpoint.ptah_id),
        "target_pathid": int(target_endpoint.ptah_id),
        "source_method": _text(source_endpoint.method).upper(),
        "target_method": _text(target_endpoint.method).upper(),
        "source_path": _text(source_endpoint.path),
        "target_path": _text(target_endpoint.path),
        "source_group": _endpoint_group(source_endpoint),
        "target_group": _endpoint_group(target_endpoint),
        "source_parameter": _text(getattr(source_doc, "parameter", "")),
        "target_parameter": _text(getattr(target_doc, "parameter", "")),
        "source_position": _text(getattr(source_doc, "position", "") or "body"),
        "target_position": _text(getattr(target_doc, "position", "") or "body"),
        "source_type": _type_family(getattr(source_doc, "type", "")),
        "target_type": _type_family(getattr(target_doc, "type", "")),
        "source_locator": _locator(source_doc, "response"),
        "target_locator": _locator(target_doc, "request"),
    }
    raw = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _protected(relation: parameter_relation) -> bool:
    return bool(
        relation.verified
        or relation.manual_decision in {"trusted", "rejected", "deleted"}
        or relation.discovery_source in {"manual_override", "manual_tombstone"}
    )


def _endpoint_for_occurrence(row: Any, endpoint_by_oid: Mapping[Any, Any]) -> Optional[Any]:
    reference = getattr(row, "raw_data", None)
    object_id = getattr(reference, "id", reference)
    return endpoint_by_oid.get(object_id)


def _occurrence_from_mongo(record: Mapping[str, Any], endpoint_by_oid: Mapping[Any, Any]
                           ) -> Tuple[Optional[Any], Any]:
    endpoint = endpoint_by_oid.get(record.get("raw_data"))
    row = SimpleNamespace()
    for field, default in (
        ("parameter", ""), ("canonical_name", ""), ("position", "body"),
        ("type", ""), ("required", False), ("value", []), ("locator", {}),
        ("display_path", ""), ("schema_path", ""), ("des", ""),
    ):
        setattr(row, field, record.get(field, default))
    row.raw_data = endpoint
    return endpoint, row


def _occurrence_records(model: Any, endpoints: Sequence[Any], endpoint_by_oid: Mapping[Any, Any]):
    fields = (
        "raw_data", "parameter", "canonical_name", "position", "type", "required",
        "value", "locator", "display_path", "schema_path", "des",
    )
    selected_fields = [field for field in fields if field in model._fields]
    for record in model.objects(raw_data__in=list(endpoints)).only(*selected_fields).as_pymongo():
        yield _occurrence_from_mongo(record, endpoint_by_oid)


def discover_project_relations(project_id: str, *, changed_pathids: Optional[Sequence[int]] = None,
                               max_sources_per_target: int = 2) -> Dict[str, Any]:
    """Incrementally discover project relations from structure and traffic."""
    project_id = _text(project_id)
    endpoints = list(raw_data.objects(project_id=project_id).order_by("ptah_id"))
    endpoint_by_id = {int(item.ptah_id): item for item in endpoints}
    endpoint_by_oid = {item.id: item for item in endpoints}
    selected = {int(item) for item in (changed_pathids or []) if int(item) in endpoint_by_id}
    if not endpoints:
        return {
            "project_id": project_id, "endpoints": 0, "candidates": 0,
            "created": 0, "updated": 0, "preserved": 0, "stale": 0,
            "incremental": bool(changed_pathids),
        }

    traffic_pathids = set()
    for sample in request_sample.objects(pathid__in=list(endpoint_by_id)).only("pathid", "source"):
        if _text(sample.source).lower() in TRAFFIC_SOURCES:
            traffic_pathids.add(int(sample.pathid))

    sources: Dict[str, Dict[int, Any]] = defaultdict(dict)
    targets: Dict[str, Dict[int, Any]] = defaultdict(dict)
    for endpoint, row in _occurrence_records(res_data, endpoints, endpoint_by_oid):
        if not endpoint or _text(endpoint.method).upper() not in READ_METHODS:
            continue
        identity = parameter_identity(row.parameter, getattr(row, "canonical_name", ""))
        if identity:
            sources[identity][int(endpoint.ptah_id)] = _best_occurrence(
                sources[identity].get(int(endpoint.ptah_id)), row,
            )
    for endpoint, row in _occurrence_records(req_data, endpoints, endpoint_by_oid):
        if not endpoint:
            continue
        identity = parameter_identity(row.parameter, getattr(row, "canonical_name", ""))
        if identity:
            targets[identity][int(endpoint.ptah_id)] = _best_occurrence(
                targets[identity].get(int(endpoint.ptah_id)), row,
            )

    candidates = []
    for identity in sorted(set(sources) & set(targets)):
        for target_pathid, target_doc in targets[identity].items():
            target_endpoint = endpoint_by_id[target_pathid]
            ranked = []
            for source_pathid, source_doc in sources[identity].items():
                if selected and source_pathid not in selected and target_pathid not in selected:
                    continue
                source_endpoint = endpoint_by_id[source_pathid]
                assessment = relation_candidate_score(
                    source_doc, target_doc, source_endpoint, target_endpoint,
                    traffic_pathids=traffic_pathids,
                )
                if assessment:
                    ranked.append((assessment["score"], source_pathid, source_doc, assessment))
            ranked.sort(key=lambda item: (-item[0], item[1]))
            if not ranked:
                continue
            best_score = ranked[0][0]
            kept = 0
            for score, source_pathid, source_doc, assessment in ranked:
                if kept >= max(1, int(max_sources_per_target)) or score < best_score - 5.0:
                    break
                candidates.append({
                    "identity": identity,
                    "source_pathid": source_pathid,
                    "target_pathid": target_pathid,
                    "source_doc": source_doc,
                    "target_doc": target_doc,
                    "assessment": assessment,
                    "fingerprint": _schema_fingerprint(
                        source_doc, target_doc, endpoint_by_id[source_pathid], target_endpoint,
                    ),
                })
                kept += 1

    existing_rows = list(parameter_relation.objects(project_id=project_id))
    existing_by_key: Dict[Tuple[str, int, int], parameter_relation] = {}
    for row in existing_rows:
        key = (parameter_identity(row.parameter), int(row.res_pathid), int(row.req_pathid))
        existing_by_key.setdefault(key, row)

    now = dt.datetime.utcnow()
    seen_keys = set()
    counts = Counter()
    for candidate in candidates:
        key = (
            candidate["identity"], candidate["source_pathid"], candidate["target_pathid"],
        )
        seen_keys.add(key)
        source_doc = candidate["source_doc"]
        target_doc = candidate["target_doc"]
        assessment = candidate["assessment"]
        fingerprint = candidate["fingerprint"]
        relation = existing_by_key.get(key)
        if relation is not None and relation.manual_decision == "deleted":
            counts["preserved"] += 1
            continue
        if relation is None:
            relation = parameter_relation(
                project_id=project_id,
                parameter=candidate["identity"],
                req_pathid=candidate["target_pathid"],
                res_pathid=candidate["source_pathid"],
                first_seen_at=now,
            )
            counts["created"] += 1
        else:
            counts["preserved" if _protected(relation) else "updated"] += 1

        protected = _protected(relation)
        previous_discovery_version = _text(relation.discovery_version)
        relation.discovery_version = DISCOVERY_VERSION
        if relation.discovery_source not in {"manual_override", "manual_tombstone"}:
            relation.discovery_source = "project_schema_and_traffic"
        relation.evidence_sources = sorted(set(
            list(relation.evidence_sources or []) + list(assessment["evidence_sources"]),
        ))
        relation.last_seen_at = now
        relation.first_seen_at = relation.first_seen_at or now
        if protected:
            if previous_discovery_version and previous_discovery_version != DISCOVERY_VERSION:
                # Fingerprint format changed; establish the new baseline while
                # retaining the protected mapping. Subsequent imports compare
                # against this complete endpoint+schema fingerprint.
                relation.confirmed_schema_fingerprint = fingerprint
                relation.schema_fingerprint = fingerprint
            else:
                relation.confirmed_schema_fingerprint = (
                    relation.confirmed_schema_fingerprint or relation.schema_fingerprint or fingerprint
                )
                relation.schema_fingerprint = fingerprint
                if relation.confirmed_schema_fingerprint != fingerprint:
                    relation.stale_reason = "schema_changed_after_confirmation"
                    relation.preprocess_status = "stale"
                    counts["stale"] += 1
        else:
            relation.parameter = candidate["identity"]
            relation.source_parameter = _text(source_doc.parameter) or candidate["identity"]
            relation.target_parameter = _text(target_doc.parameter) or candidate["identity"]
            relation.source_position = _text(source_doc.position) or "body"
            relation.target_position = _text(target_doc.position) or "body"
            relation.source_locator = _locator(source_doc, "response")
            relation.target_locator = _locator(target_doc, "request")
            relation.locator_version = LOCATOR_VERSION
            relation.location_status = (
                "resolved" if relation.source_locator and relation.target_locator else "unresolved"
            )
            relation.location_note = "" if relation.location_status == "resolved" else "schema locator unavailable"
            relation.rule = "project_schema_traffic_match" if "traffic" in assessment["evidence_sources"] else "project_schema_match"
            relation.relation = assessment["relation_kind"]
            relation.score = assessment["score"]
            relation.reason_codes = list(dict.fromkeys(
                list(relation.reason_codes or []) + list(assessment["reason_codes"]),
            ))
            relation.evidence = [{
                "kind": "project_relation_discovery",
                "version": DISCOVERY_VERSION,
                "score": assessment["score"],
                "relation_kind": assessment["relation_kind"],
                "evidence_sources": assessment["evidence_sources"],
                "value_overlap_count": assessment["value_overlap_count"],
            }]
            relation.schema_fingerprint = fingerprint
            relation.stale_reason = ""
        relation.mtime = now
        relation.save()

    # A re-import can remove or move a previously discovered field.  Keep the
    # relation for audit, but do not silently present it as current.
    for relation in existing_rows:
        if relation.discovery_version != DISCOVERY_VERSION:
            continue
        key = (parameter_identity(relation.parameter), int(relation.res_pathid), int(relation.req_pathid))
        in_scope = not selected or relation.res_pathid in selected or relation.req_pathid in selected
        if in_scope and key not in seen_keys:
            relation.stale_reason = "mapping_missing_after_import"
            relation.preprocess_status = "stale"
            relation.mtime = now
            relation.save()
            counts["stale"] += 1

    return {
        "project_id": project_id,
        "endpoints": len(endpoints),
        "candidates": len(candidates),
        "created": counts["created"],
        "updated": counts["updated"],
        "preserved": counts["preserved"],
        "stale": counts["stale"],
        "incremental": bool(selected),
        "changed_pathids": len(selected),
        "evidence": {
            "document_endpoints": sum(
                1 for item in endpoints
                if _text(item.source).lower() in DOCUMENT_SOURCES or item.asset_kind == "abstract"
            ),
            "traffic_endpoints": len(traffic_pathids),
        },
        "discovery_version": DISCOVERY_VERSION,
    }


def _endpoint_action(endpoint: Any, request_params: Iterable[Any], response_params: Iterable[Any]) -> str:
    method = _text(endpoint.method).upper()
    parts = _path_parts(endpoint.path)
    text = " ".join((
        _text(endpoint.path), _text(endpoint.des), _text(endpoint.tags),
        _text((endpoint.source_meta or {}).get("name")),
    )).lower()
    has_placeholder = any(part.startswith("{") and part.endswith("}") for part in parts)
    request_ids = {
        parameter_identity(row.parameter, getattr(row, "canonical_name", ""))
        for row in request_params
        if _is_identity(parameter_identity(row.parameter, getattr(row, "canonical_name", "")), row)
    }
    response_ids = {
        parameter_identity(row.parameter, getattr(row, "canonical_name", ""))
        for row in response_params
        if _is_identity(parameter_identity(row.parameter, getattr(row, "canonical_name", "")), row)
    }
    if method == "GET":
        return "detail" if has_placeholder or request_ids else "list"
    if method == "DELETE":
        return "delete"
    if method in {"PUT", "PATCH"}:
        return "update"
    if method == "POST":
        if any(word in text for word in ("delete", "remove", "删除", "移除")):
            return "delete"
        if any(word in text for word in ("update", "edit", "modify", "修改", "更新")):
            return "update"
        if (
            any(word in text for word in ("create", "add", "insert", "创建", "新增", "添加"))
            or bool(response_ids - request_ids)
        ):
            return "create"
        return "submit"
    return "other"


def _compatible_parameter(left: str, right: str) -> bool:
    if not left or not right:
        return False
    if left == right:
        return True
    return bool((left == "id" and IDENTITY_RE.search(right)) or (right == "id" and IDENTITY_RE.search(left)))


def _chain_strategy(actions: set) -> Tuple[str, str]:
    if {"create", "detail", "update", "delete"} <= actions:
        return "create_detail_update_delete", "创建 → 详情 → 更新 → 删除"
    if {"create", "detail", "delete"} <= actions:
        return "create_detail_delete", "创建 → 详情 → 删除"
    if {"list", "detail", "update"} <= actions:
        return "list_detail_update", "列表 → 详情 → 更新/恢复"
    if {"list", "detail"} <= actions:
        return "list_detail", "列表 → 详情"
    if "create" in actions and "delete" in actions:
        return "create_delete", "创建 → 删除（缺少回读）"
    if "list" in actions:
        return "list_seed", "列表取样"
    return "manual", "尚未形成完整链路"


def _origin_for_endpoints(endpoints: Iterable[Any], traffic_pathids: set) -> str:
    document = False
    traffic = False
    for endpoint in endpoints:
        source = _text(endpoint.source).lower()
        document = document or source in DOCUMENT_SOURCES or endpoint.asset_kind == "abstract"
        traffic = traffic or source in TRAFFIC_SOURCES or endpoint.asset_kind == "concrete" or endpoint.ptah_id in traffic_pathids
    if document and traffic:
        return "mixed"
    return "traffic" if traffic else "document"


def _chain_group_key(endpoint: Any) -> Tuple[str, str, str]:
    module, folder, family = _endpoint_group(endpoint)
    # Apifox/OpenAPI group identity prevents unrelated same-name resources from
    # being merged.  Path family remains the stable human-readable part.
    return (module, folder, family)


def project_chain_candidates(project_id: str) -> Dict[str, Any]:
    """Build a live, project-scoped chain view without historical JSON files."""
    project_id = _text(project_id)
    endpoints = list(raw_data.objects(project_id=project_id).order_by("ptah_id"))
    endpoint_by_id = {int(item.ptah_id): item for item in endpoints}
    endpoint_by_oid = {item.id: item for item in endpoints}
    request_by_path: Dict[int, List[Any]] = defaultdict(list)
    response_by_path: Dict[int, List[Any]] = defaultdict(list)
    for endpoint, row in _occurrence_records(req_data, endpoints, endpoint_by_oid):
        if endpoint:
            request_by_path[int(endpoint.ptah_id)].append(row)
    for endpoint, row in _occurrence_records(res_data, endpoints, endpoint_by_oid):
        if endpoint:
            response_by_path[int(endpoint.ptah_id)].append(row)

    sample_stats: Dict[int, Dict[str, Any]] = defaultdict(lambda: {
        "samples": 0, "hits": 0, "sources": set(), "last_seen": None,
    })
    for sample in request_sample.objects(pathid__in=list(endpoint_by_id)).only(
            "pathid", "source", "hit_count", "last_seen"):
        item = sample_stats[int(sample.pathid)]
        item["samples"] += 1
        item["hits"] += int(sample.hit_count or 0)
        item["sources"].add(_text(sample.source).lower() or "traffic")
        if sample.last_seen and (not item["last_seen"] or sample.last_seen > item["last_seen"]):
            item["last_seen"] = sample.last_seen
    traffic_pathids = {
        pathid for pathid, item in sample_stats.items()
        if item["sources"] & TRAFFIC_SOURCES
    }

    endpoint_views: Dict[int, Dict[str, Any]] = {}
    grouped: Dict[Tuple[str, str, str], List[Dict[str, Any]]] = defaultdict(list)
    for endpoint in endpoints:
        pathid = int(endpoint.ptah_id)
        request_rows = request_by_path[pathid]
        response_rows = response_by_path[pathid]
        request_ids = sorted({
            parameter_identity(row.parameter, getattr(row, "canonical_name", ""))
            for row in request_rows
            if _is_identity(parameter_identity(row.parameter, getattr(row, "canonical_name", "")), row)
        } - {""})
        response_ids = sorted({
            parameter_identity(row.parameter, getattr(row, "canonical_name", ""))
            for row in response_rows
            if _is_identity(parameter_identity(row.parameter, getattr(row, "canonical_name", "")), row)
        } - {""})
        action = _endpoint_action(endpoint, request_rows, response_rows)
        meta = dict(endpoint.source_meta or {})
        sample = sample_stats[pathid]
        view = {
            "pathid": pathid,
            "method": _text(endpoint.method).upper(),
            "path": _text(endpoint.path),
            "name": _text(meta.get("name") or endpoint.des),
            "description": _text(endpoint.des),
            "action": action,
            "request_ids": request_ids,
            "response_ids": response_ids,
            "required_count": sum(1 for row in request_rows if row.required),
            "request_count": len(request_rows),
            "response_count": len(response_rows),
            "source": _text(endpoint.source).lower(),
            "asset_kind": _text(endpoint.asset_kind),
            "module_id": _text(meta.get("apifox_module_id") or meta.get("module_id")),
            "folder_id": _text(meta.get("apifox_folder_id") or meta.get("folder_id")),
            "status": _text(meta.get("status")),
            "sample_count": sample["samples"],
            "hit_count": sample["hits"],
            "sample_sources": sorted(sample["sources"]),
            "last_seen": sample["last_seen"],
        }
        endpoint_views[pathid] = view
        grouped[_chain_group_key(endpoint)].append(view)

    relations = list(parameter_relation.objects(
        project_id=project_id, manual_decision__ne="rejected",
    ))
    relations_by_pair: Dict[Tuple[int, int], List[parameter_relation]] = defaultdict(list)
    for relation in relations:
        if relation.stale_reason:
            continue
        relations_by_pair[(int(relation.res_pathid), int(relation.req_pathid))].append(relation)

    rows = []
    for (module_id, folder_id, family), items in grouped.items():
        if len(items) < 2:
            continue
        actions = {item["action"] for item in items}
        if not (actions & {"list", "detail", "create", "update", "delete"}):
            continue
        item_by_id = {item["pathid"]: item for item in items}
        links = []
        seen_links = set()
        for (source_pathid, target_pathid), pair_relations in relations_by_pair.items():
            if source_pathid not in item_by_id or target_pathid not in item_by_id:
                continue
            for relation in pair_relations:
                key = (source_pathid, target_pathid, parameter_identity(relation.parameter))
                if key in seen_links:
                    continue
                seen_links.add(key)
                status = "trusted" if relation.manual_decision == "trusted" else (
                    "verified" if relation.verified or relation.preprocess_status == "verified" else "candidate"
                )
                links.append({
                    "from": source_pathid,
                    "to": target_pathid,
                    "parameter": parameter_identity(relation.parameter),
                    "source_parameter": _text(relation.source_parameter or relation.parameter),
                    "target_parameter": _text(relation.target_parameter or relation.parameter),
                    "status": status,
                    "confidence": float(relation.machine_confidence or relation.score or 0),
                    "origin": "relation",
                })

        # Complete the visual chain from documentation even before relation
        # persistence/runtime verification has happened.
        producers = [item for item in items if item["action"] in {"list", "detail", "create"}]
        consumers = [item for item in items if item["action"] in {"detail", "update", "delete"}]
        for producer in producers:
            for consumer in consumers:
                if producer["pathid"] == consumer["pathid"]:
                    continue
                for left in producer["response_ids"]:
                    for right in consumer["request_ids"]:
                        if not _compatible_parameter(left, right):
                            continue
                        key = (producer["pathid"], consumer["pathid"], right)
                        if key in seen_links:
                            continue
                        seen_links.add(key)
                        links.append({
                            "from": producer["pathid"], "to": consumer["pathid"],
                            "parameter": right, "source_parameter": left,
                            "target_parameter": right, "status": "document_candidate",
                            "confidence": 65.0, "origin": "document",
                        })

        strategy, strategy_label = _chain_strategy(actions)
        origin = _origin_for_endpoints(
            [endpoint_by_id[item["pathid"]] for item in items], traffic_pathids,
        )
        verified_links = [item for item in links if item["status"] in {"verified", "trusted"}]
        relation_links = [item for item in links if item["origin"] == "relation"]
        confidence = 45.0 if origin == "traffic" else 58.0
        confidence += min(18.0, len(links) * 3.0)
        confidence += min(12.0, sum(item["hit_count"] for item in items) ** 0.5)
        confidence += min(20.0, len(verified_links) * 7.0)
        confidence = round(min(100.0, confidence), 1)
        if verified_links and strategy != "manual":
            readiness = "verified"
            next_action = "已验证字段关系，可进入链路执行计划"
        elif relation_links and strategy != "manual":
            readiness = "relation_ready"
            next_action = "关系已形成，按环境预算执行一次链路验证"
        elif links and origin in {"document", "mixed"}:
            readiness = "document_ready"
            next_action = "文档结构已成链；补真实样本后验证取值"
        elif origin == "traffic":
            readiness = "traffic_review"
            next_action = "真实值已具备；需确认流量接口是否属于同一资源组"
        else:
            readiness = "needs_relation"
            next_action = "尚缺可传递的资源标识关系"

        action_order = {"list": 0, "create": 1, "detail": 2, "update": 3, "delete": 4, "submit": 5}
        sequence = []
        for action in ("list", "create", "detail", "update", "delete", "submit"):
            candidates = [item for item in items if item["action"] == action]
            if not candidates:
                continue
            candidates.sort(key=lambda item: (
                -int(bool(item["status"] == "released")), -len(item["response_ids"]),
                item["required_count"], item["pathid"],
            ))
            sequence.append(candidates[0])
        sequence.sort(key=lambda item: action_order.get(item["action"], 99))
        rows.append({
            "key": "{}:{}:{}".format(module_id or "project", folder_id or "ungrouped", family),
            "family": family,
            "module_id": module_id,
            "folder_id": folder_id,
            "strategy": strategy,
            "strategy_label": strategy_label,
            "origin": origin,
            "readiness": readiness,
            "confidence": confidence,
            "next_action": next_action,
            "endpoint_count": len(items),
            "link_count": len(links),
            "verified_link_count": len(verified_links),
            "traffic_hits": sum(item["hit_count"] for item in items),
            "sample_count": sum(item["sample_count"] for item in items),
            "sequence": sequence,
            "endpoints": sorted(items, key=lambda item: (action_order.get(item["action"], 99), item["pathid"])),
            "links": sorted(links, key=lambda item: (-item["confidence"], item["parameter"])),
        })

    readiness_order = {
        "verified": 0, "relation_ready": 1, "document_ready": 2,
        "traffic_review": 3, "needs_relation": 4,
    }
    rows.sort(key=lambda item: (
        readiness_order.get(item["readiness"], 9), -item["confidence"], item["family"],
    ))
    return {
        "project_id": project_id,
        "rows": rows,
        "stats": {
            "endpoints": len(endpoints),
            "chains": len(rows),
            "document": sum(1 for item in rows if item["origin"] == "document"),
            "traffic": sum(1 for item in rows if item["origin"] == "traffic"),
            "mixed": sum(1 for item in rows if item["origin"] == "mixed"),
            "verified": sum(1 for item in rows if item["readiness"] == "verified"),
            "relation_ready": sum(1 for item in rows if item["readiness"] == "relation_ready"),
            "needs_relation": sum(1 for item in rows if item["readiness"] == "needs_relation"),
        },
    }
