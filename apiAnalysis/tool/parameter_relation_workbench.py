"""Machine-first preprocessing and readable projections for parameter relations.

The legacy relation table mixed raw heuristic signals, runtime failures and
manual decisions.  This module turns those facts into an execution decision:
static work is completed automatically, a project-environment request budget
is enforced when runtime checks are safe, and only ambiguous or large work is
left for human approval/correction. Production and unknown environments retain
a hard three-request ceiling.
"""
from __future__ import annotations

import datetime as dt
from collections import Counter
from types import SimpleNamespace
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from apiAnalysis.db.collection import (
    ProjectAccountBinding,
    ProjectAuthProfile,
    ProjectEnvironment,
    parameter_experience,
    parameter_priority_item,
    parameter_relation,
    parameter_validation_result,
    raw_data,
    req_data,
    res_data,
)
from apiAnalysis.tool.execution_scheduler import utcnow
from apiAnalysis.tool.parameter_locator import LOCATOR_VERSION, locator_from_path
from apiAnalysis.tool.parameter_identity import parameter_identity
from apiAnalysis.tool.project_auth import environment_host_names, normalize_host
from apiAnalysis.tool.request_fixture import request_input_view


PREPROCESS_VERSION = "relation-preprocess-v1"
READ_METHODS = {"GET", "HEAD", "OPTIONS"}
MUTATION_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
SAFE_ENVIRONMENT_TYPES = {"test", "preprod"}
MAX_AUTOMATIC_REQUESTS = 3
PRODUCTION_REQUEST_LIMIT = 3
MAX_CONFIGURABLE_REQUESTS = 1000
MAX_APPROVED_REQUESTS = MAX_CONFIGURABLE_REQUESTS


REASON_CATALOG: Dict[str, Tuple[str, str, str]] = {
    "LOCATION_RESOLVED": (
        "参数位置已定位", "已找到来源响应字段和消费请求字段的精确位置。", "structure",
    ),
    "LOCATION_UNRESOLVED": (
        "参数位置不完整", "缺少来源响应或消费请求中的精确字段位置，不能可靠注入。", "blocker",
    ),
    "LOCATOR_AMBIGUOUS": (
        "存在多个同名位置", "同一接口中存在多个同名字段，机器无法在不冒险的情况下唯一选择。", "blocker",
    ),
    "DIRECTION_CONFIRMED": (
        "上下游方向成立", "来源接口提供响应值，消费接口在请求中使用该值。", "structure",
    ),
    "DIRECTION_AUTO_SWAPPED": (
        "已自动纠正上下游", "原方向缺少完整字段，而反向关系完整，系统已交换来源和消费接口。", "action",
    ),
    "DIRECTION_AMBIGUOUS": (
        "上下游方向有歧义", "正反两个方向都存在完整字段，需要人工选择业务方向。", "blocker",
    ),
    "DIRECTION_CANDIDATE": (
        "已选定最可能的上下游", "正反方向都能形成结构关系；系统先沿现有高分方向做小成本真实验证，失败后才交给人工纠偏。", "action",
    ),
    "SOURCE_NOT_READ_ONLY": (
        "来源接口不是安全读取", "获取参数值本身可能修改数据，系统不会把它作为自动来源。", "blocker",
    ),
    "ENVIRONMENT_REQUIRED": (
        "缺少执行环境", "请配置测试或预发环境以及允许的 Host。", "configuration",
    ),
    "AUTH_PROFILE_REQUIRED": (
        "缺少认证方案", "请为来源和消费接口选择测试账号认证方案。", "configuration",
    ),
    "REQUEST_INPUT_GAPS": (
        "仍有必填测试数据缺口", "文档示例、历史样本、参数经验和当前关系均未提供这些必填字段；请为接口补充可复用测试数据模板。", "configuration",
    ),
    "REQUEST_INPUT_READY": (
        "请求数据已可组成", "关系字段与测试数据模板合并后，接口的必填输入已具备。", "structure",
    ),
    "MULTI_PARAMETER_CASE": (
        "同一接口对合并验证", "该来源与消费接口之间的多个参数会在一次来源请求和一次消费请求中共同验证。", "action",
    ),
    "HOST_REQUIRED": (
        "缺少可用 Host", "环境或认证方案中没有覆盖该接口的 Host。", "configuration",
    ),
    "HOST_EXACT_MATCH": (
        "Host 与接口文档一致", "优先使用接口资产记录的域名，避免把路由错误误判为关系错误。", "structure",
    ),
    "HOST_FALLBACK": (
        "使用环境候选 Host", "接口域名未精确命中，按环境默认顺序选择候选 Host。", "action",
    ),
    "MUTATION_POLICY_ALLOWED": (
        "允许测试数据写入", "环境已标记为测试/预发，账号为测试账号，并启用了写入验证。", "safety",
    ),
    "MUTATION_POLICY_BLOCKED": (
        "写入验证未获授权", "只有测试/预发环境、测试账号且显式启用写入时才会自动执行。", "blocker",
    ),
    "AUTO_REQUEST_BUDGET_OK": (
        "请求预算可自动执行", "预计最多三次请求即可得出结论，无需逐条人工批准。", "safety",
    ),
    "LARGE_RUN_APPROVAL_REQUIRED": (
        "需要批量执行确认", "预计请求总量超过自动预算，只需人工确认执行范围，无需人工判断每条关系。", "approval",
    ),
    "HOST_SWEEP_APPROVAL_REQUIRED": (
        "候选 Host 超出自动预算", "机器已完成前三次以内的尝试；批准后会自动继续验证剩余候选 Host，无需人工逐个试。", "approval",
    ),
    "LATEST_VALIDATION_PASSED": (
        "最近验证通过", "来源值已成功提取并被消费接口接受。", "runtime",
    ),
    "LATEST_VALIDATION_FAILED": (
        "最近自动验证未完成", "系统已执行过验证，但仍存在路由、认证、业务数据或接口响应问题。", "runtime",
    ),
    "LEGACY_RUNTIME_OBSERVED": (
        "历史运行样本支持", "旧系统曾在运行数据中观察到同名值，但这不是来源到消费端的闭环验证，仍需机器真实验证。", "runtime",
    ),
    "MUTATION_EFFECT_AFTER_ERROR": (
        "发现接口错误处理缺陷", "写/删请求返回超时或服务错误，但回读确认数据已变化；参数关系成立，同时应作为开发缺陷处理。", "runtime",
    ),
    "MANUAL_RELATION_CONFIRMED": (
        "人工已纠正并确认", "人工只补充了机器无法获知的业务方向或语义，该关系可进入经验与链路复用。", "action",
    ),
    "MANUAL_DATA_REQUIRED": (
        "等待业务样本", "机器已完成结构分析，但当前测试账号缺少可用于验证的业务数据。", "configuration",
    ),
    "EXPERIENCE_STALE": (
        "经验需要重新验证", "接口或业务已变化，旧结论不再直接复用；系统将在具备样本后重新验证。", "runtime",
    ),
    "UPSTREAM_HTTP_401": (
        "来源认证失败（历史）", "历史尝试返回 401；应先刷新或切换认证方案，不代表参数关系错误。", "runtime",
    ),
    "UPSTREAM_HTTP_404": (
        "来源路由未命中（历史）", "历史尝试返回 404；优先核对环境和 Host，不代表参数关系错误。", "runtime",
    ),
    "UPSTREAM_HTTP_500": (
        "来源服务异常（历史）", "历史尝试返回 500；属于运行环境证据，不应直接否定关系。", "runtime",
    ),
    "UPSTREAM_HTTP_503": (
        "来源服务暂不可用（历史）", "历史尝试返回 503；可稍后自动重试或切换候选 Host。", "runtime",
    ),
    "UPSTREAM_BUSINESS_ERROR": (
        "来源缺少业务前置数据（历史）", "接口可达但业务响应失败，需要先补齐测试数据或账号上下文。", "runtime",
    ),
    "UPSTREAM_STATUS_204": (
        "来源暂无响应数据（历史）", "接口返回 204，当前样本无法提取参数值。", "runtime",
    ),
    "UPSTREAM_SUCCESS_NO_VALUE": (
        "来源响应未找到目标值（历史）", "接口成功但指定字段没有值，系统会检查其他定位或样本。", "runtime",
    ),
    "OVERLAP_COUNT": (
        "请求与响应存在相同样本", "历史数据中来源值与消费值有交集。", "structure",
    ),
    "OVERLAP_RATIO_HIGH": (
        "样本重合度高", "历史样本对这条关系提供了较强支持。", "structure",
    ),
    "OVERLAP_RATIO_MID": (
        "样本有部分重合", "历史样本提供中等支持，仍应以真实验证为准。", "structure",
    ),
    "LEAF_NOT_BLACKLIST": (
        "参数名称具备业务区分度", "该名称不是分页、时间戳等低信息参数。", "structure",
    ),
    "NAME_FALLBACK": (
        "仅根据名称建立候选", "当前关系缺少值交集证据，可信度低于真实运行验证。", "structure",
    ),
    "LATEST_REQUEST_DATA_REJECTED": (
        "真实请求被业务参数校验拒绝",
        "接口已经命中，当前应补充测试 Fixture，而不是继续跨 Host。",
        "runtime",
    ),
    "LATEST_BUSINESS_AUTH_REJECTED": (
        "业务接口拒绝当前认证或角色",
        "接口已经命中，应检查登录场景、角色和认证方案，而不是继续跨 Host。",
        "runtime",
    ),
}


STATUS_LABELS = {
    "stale": "结构变化·待复验",
    "deleted": "已删除",
    "pending": "待预处理",
    "auto_ready": "可自动验证",
    "running": "自动验证中",
    "verified": "机器验证通过",
    "trusted": "人工纠偏确认",
    "accepted": "接口已接受",
    "mutation_verified": "写/删效果已确认",
    "mutation_accepted": "写/删请求已接受",
    "mutation_effect_after_error": "关系成立且发现接口缺陷",
    "source_failed": "来源请求未完成",
    "source_request_rejected": "来源请求数据被拒绝",
    "source_auth_rejected": "来源接口认证被拒绝",
    "source_rate_limited": "来源接口限流",
    "value_not_found": "来源响应缺少目标值",
    "consumer_failed": "消费请求未完成",
    "consumer_request_rejected": "消费请求数据被拒绝",
    "consumer_auth_rejected": "消费接口认证被拒绝",
    "consumer_rate_limited": "消费接口限流",
    "request_budget_exhausted": "请求预算不足",
    "host_scope_approval_required": "待扩大 Host 范围确认",
    "needs_context": "待配置环境/账号",
    "needs_data": "待补测试数据",
    "needs_correction": "待人工纠偏",
    "approval_required": "待批量确认",
    "automatic_failed": "自动验证未完成",
    "policy_blocked": "执行策略阻断",
    "rejected": "已排除",
}


def _text(value: Any) -> str:
    return str(value or "").strip()


def _method(endpoint: Any) -> str:
    return _text(getattr(endpoint, "method", "")).upper()


def _leaf_name(value: Any) -> str:
    parts = [item for item in _text(value).replace("[", ".[").split(".") if item]
    for item in reversed(parts):
        cleaned = item.replace("[]", "").strip("[]")
        if cleaned and not cleaned.isdigit():
            return cleaned.lower().replace("-", "_")
    return ""


def _compact(value: Any) -> str:
    return "".join(char for char in _leaf_name(value) if char.isalnum())


def normalize_environment_type(value: Any) -> str:
    normalized = _text(value).lower().replace("_", "-")
    aliases = {
        "testing": "test", "qa": "test", "dev": "test", "development": "test",
        "staging": "preprod", "stage": "preprod", "uat": "preprod",
        "pre-production": "preprod", "preproduction": "preprod", "beta": "preprod",
        "prod": "production", "formal": "production", "production": "production",
    }
    return aliases.get(normalized, normalized if normalized in {"test", "preprod", "production"} else "unknown")


def infer_environment_type(environment: Optional[ProjectEnvironment]) -> str:
    if not environment:
        return "unknown"
    explicit = normalize_environment_type(
        getattr(environment, "environment_type", "")
        or (getattr(environment, "metadata", None) or {}).get("environment_type")
    )
    if explicit != "unknown":
        return explicit
    values = [environment.env_id, environment.name, environment.default_host]
    values.extend(environment_host_names(environment))
    joined = " ".join(_text(item).lower() for item in values)
    if any(token in joined for token in ("preprod", "staging", "stage", "uat", "beta")):
        return "preprod"
    if any(token in joined for token in ("test", "testing", "qa.", "dev.")):
        return "test"
    if any(token in joined for token in ("production", "formal", "prod.")):
        return "production"
    return "unknown"


def environment_execution_policy(environment: Optional[ProjectEnvironment]) -> Dict[str, Any]:
    environment_type = infer_environment_type(environment)
    limit = getattr(environment, "auto_request_limit", None) if environment else None
    if limit in (None, 0):
        limit = (getattr(environment, "metadata", None) or {}).get("auto_request_limit", 3) if environment else 3
    maximum = (
        MAX_CONFIGURABLE_REQUESTS
        if environment_type in SAFE_ENVIRONMENT_TYPES
        else PRODUCTION_REQUEST_LIMIT
    )
    try:
        limit = max(1, min(int(limit), maximum))
    except (TypeError, ValueError):
        limit = MAX_AUTOMATIC_REQUESTS
    allow_mutation = bool(
        environment
        and environment_type in SAFE_ENVIRONMENT_TYPES
        and (
            bool(getattr(environment, "allow_mutation", False))
            or bool((getattr(environment, "metadata", None) or {}).get("allow_mutation"))
        )
    )
    return {
        "environment_type": environment_type,
        "allow_mutation": allow_mutation,
        "auto_request_limit": limit,
        "approved_request_limit": (
            MAX_CONFIGURABLE_REQUESTS
            if environment_type in SAFE_ENVIRONMENT_TYPES
            else PRODUCTION_REQUEST_LIMIT
        ),
        "hard_limited": environment_type not in SAFE_ENVIRONMENT_TYPES,
        "automatic": environment_type in SAFE_ENVIRONMENT_TYPES,
    }


def relation_request_estimate(consumer_method: Any) -> int:
    """Bounded network cost for source -> consumer -> optional after-read."""
    return 3 if _text(consumer_method).upper() in MUTATION_METHODS else 2


def reason_view(code: Any) -> Dict[str, str]:
    normalized = _text(code)
    title, detail, category = REASON_CATALOG.get(
        normalized,
        ("补充运行信号", "系统记录了内部信号 {}，它仅作为辅助证据。".format(normalized or "unknown"), "other"),
    )
    return {"code": normalized, "title": title, "detail": detail, "category": category}


def reason_views(codes: Iterable[Any]) -> List[Dict[str, str]]:
    result = []
    seen = set()
    for code in codes or []:
        normalized = _text(code)
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        result.append(reason_view(normalized))
    return result


def _endpoint(pathid: Any, project_id: str = "") -> Optional[raw_data]:
    try:
        pathid = int(pathid)
    except (TypeError, ValueError):
        return None
    query: Dict[str, Any] = {"ptah_id": pathid}
    if project_id:
        query["project_id"] = _text(project_id)
    endpoint = raw_data.objects(**query).first()
    if not endpoint and project_id:
        endpoint = raw_data.objects(ptah_id=pathid).first()
    return endpoint


def endpoint_view(endpoint: Optional[raw_data]) -> Dict[str, Any]:
    if not endpoint:
        return {}
    return {
        "pathid": endpoint.ptah_id,
        "method": _method(endpoint),
        "path": _text(endpoint.path),
        "domain": normalize_host(endpoint.domain or endpoint.url),
        "description": _text(endpoint.des),
        "action": _text(endpoint.action),
    }


def _occurrence_score(item: Any, relation_parameter: str, selected_parameter: str = "") -> int:
    parameter = _text(getattr(item, "parameter", ""))
    canonical = _text(getattr(item, "canonical_name", ""))
    target_leaf = _leaf_name(relation_parameter)
    score = 0
    if selected_parameter and parameter == selected_parameter:
        score += 100
    if canonical and canonical.lower().replace("-", "_") == target_leaf:
        score += 80
    if _leaf_name(parameter) == target_leaf:
        score += 60
    if _compact(parameter) and _compact(parameter) == _compact(relation_parameter):
        score += 30
    if getattr(item, "locator", None):
        score += 10
    if getattr(item, "required", False):
        score += 5
    return score


def _occurrence_candidates(model: Any, endpoint: Optional[raw_data], parameter: str,
                           selected_parameter: str = "") -> List[Any]:
    if not endpoint:
        return []
    candidates = []
    for item in model.objects(raw_data=endpoint):
        score = _occurrence_score(item, parameter, selected_parameter=selected_parameter)
        if score:
            candidates.append((score, _text(item.parameter), item))
    candidates.sort(key=lambda value: (-value[0], value[1]))
    return [item for _score, _parameter, item in candidates]


def _choose_occurrence(candidates: Sequence[Any], parameter: str,
                       selected_parameter: str = "") -> Tuple[Optional[Any], bool]:
    if not candidates:
        return None, False
    first = candidates[0]
    first_score = _occurrence_score(first, parameter, selected_parameter=selected_parameter)
    tied = [
        item for item in candidates
        if _occurrence_score(item, parameter, selected_parameter=selected_parameter) == first_score
    ]
    unique = {
        (_text(item.parameter), _text(item.position), str(dict(item.locator or {})))
        for item in tied
    }
    return first, len(unique) > 1


def _locator_label(item: Optional[Any], direction: str) -> str:
    if not item:
        return ""
    display = _text(getattr(item, "display_path", "")) or _text(getattr(item, "schema_path", ""))
    display = display or _text(getattr(item, "parameter", ""))
    position = _text(getattr(item, "position", "")) or ("body" if direction == "response" else "unknown")
    return "{} · {}".format(position, display)


def bind_relation_locations(relation: parameter_relation, *, allow_direction_fix: bool = True) -> Dict[str, Any]:
    """Resolve typed source/target occurrences and auto-fix an unequivocal reverse edge."""
    project_id = _text(relation.project_id)
    source_endpoint = _endpoint(relation.res_pathid, project_id)
    consumer_endpoint = _endpoint(relation.req_pathid, project_id)

    # V2 discovery/manual correction already stores exact typed locators.  Do
    # not rescan every request/response field for every peer mapping on every
    # page load; that turned one interface pair into dozens of Mongo queries.
    if (
        source_endpoint and consumer_endpoint
        and relation.location_status == "resolved"
        and relation.source_locator and relation.target_locator
        and relation.source_parameter and relation.target_parameter
    ):
        source = SimpleNamespace(
            parameter=relation.source_parameter,
            canonical_name=parameter_identity(relation.source_parameter),
            position=relation.source_position or "body",
            locator=dict(relation.source_locator or {}),
            display_path=relation.source_parameter,
            schema_path=relation.source_parameter,
            required=False,
        )
        target = SimpleNamespace(
            parameter=relation.target_parameter,
            canonical_name=parameter_identity(relation.target_parameter),
            position=relation.target_position or "body",
            locator=dict(relation.target_locator or {}),
            display_path=relation.target_parameter,
            schema_path=relation.target_parameter,
            required=False,
        )
        return {
            "relation": relation,
            "source_endpoint": source_endpoint,
            "consumer_endpoint": consumer_endpoint,
            "source_occurrence": source,
            "target_occurrence": target,
            "source_candidates": [source],
            "target_candidates": [target],
            "ambiguous": False,
            "complete": True,
            "reason_codes": ["DIRECTION_CONFIRMED", "LOCATION_RESOLVED"],
        }

    direct_sources = _occurrence_candidates(
        res_data, source_endpoint, relation.parameter, relation.source_parameter,
    )
    direct_targets = _occurrence_candidates(
        req_data, consumer_endpoint, relation.parameter, relation.target_parameter,
    )
    reverse_sources = _occurrence_candidates(res_data, consumer_endpoint, relation.parameter)
    reverse_targets = _occurrence_candidates(req_data, source_endpoint, relation.parameter)
    direct_complete = bool(direct_sources and direct_targets)
    reverse_complete = bool(reverse_sources and reverse_targets)

    direction_codes: List[str] = []
    should_swap = False
    if not direct_complete and reverse_complete:
        should_swap = True
    elif direct_complete and reverse_complete:
        source_method = _method(source_endpoint)
        consumer_method = _method(consumer_endpoint)
        source_action = _text(getattr(source_endpoint, "action", ""))
        clearly_mutating_source = source_method in {"PUT", "PATCH", "DELETE"} or (
            source_method == "POST" and source_action in {"C_Path", "M_Path", "D_Path"}
        )
        should_swap = bool(clearly_mutating_source and consumer_method in READ_METHODS)
        if not should_swap:
            # The existing inferred edge is still useful evidence.  Try it
            # within the automatic request budget before asking a person to
            # resolve a theoretical two-way relationship.
            direction_codes.append("DIRECTION_CANDIDATE")

    if should_swap and allow_direction_fix:
        relation.req_pathid, relation.res_pathid = relation.res_pathid, relation.req_pathid
        source_endpoint, consumer_endpoint = consumer_endpoint, source_endpoint
        direct_sources, direct_targets = reverse_sources, reverse_targets
        direct_complete = True
        direction_codes = ["DIRECTION_AUTO_SWAPPED"]
    elif direct_complete and not direction_codes:
        direction_codes.append("DIRECTION_CONFIRMED")

    source, source_ambiguous = _choose_occurrence(
        direct_sources, relation.parameter, relation.source_parameter,
    )
    target, target_ambiguous = _choose_occurrence(
        direct_targets, relation.parameter, relation.target_parameter,
    )
    ambiguous = source_ambiguous or target_ambiguous
    if source:
        relation.source_parameter = source.parameter or relation.parameter
        relation.source_position = source.position or "body"
        relation.source_locator = dict(source.locator or {}) or locator_from_path(
            source.parameter, direction="response", position=source.position or "body",
        )
    if target:
        relation.target_parameter = target.parameter or relation.parameter
        relation.target_position = target.position or "body"
        relation.target_locator = dict(target.locator or {}) or locator_from_path(
            target.parameter, direction="request", position=target.position or "body",
        )

    relation.locator_version = LOCATOR_VERSION
    complete = bool(source and target and relation.source_locator and relation.target_locator and not ambiguous)
    relation.location_status = "resolved" if complete else "unresolved"
    if ambiguous:
        relation.location_note = "multiple matching parameter occurrences"
    elif not source or not target:
        missing = []
        if not source:
            missing.append("source")
        if not target:
            missing.append("target")
        relation.location_note = "{} parameter occurrence is unavailable".format("/".join(missing))
    else:
        relation.location_note = ""
    codes = list(direction_codes)
    codes.append("LOCATION_RESOLVED" if complete else "LOCATION_UNRESOLVED")
    if ambiguous:
        codes.append("LOCATOR_AMBIGUOUS")
    return {
        "relation": relation,
        "source_endpoint": source_endpoint,
        "consumer_endpoint": consumer_endpoint,
        "source_occurrence": source,
        "target_occurrence": target,
        "source_candidates": direct_sources,
        "target_candidates": direct_targets,
        "ambiguous": ambiguous,
        "complete": complete,
        "reason_codes": codes,
    }


def _peer_relation_targets(peer_relations: Sequence[parameter_relation], *,
                           current_relation: Optional[parameter_relation] = None,
                           current_binding: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    """Build exact consumer locators even when legacy rows were not preprocessed yet."""
    targets: List[Dict[str, Any]] = []
    for item in peer_relations:
        if current_relation is not None and str(item.id) == str(current_relation.id):
            bound = current_binding or bind_relation_locations(item, allow_direction_fix=False)
            target = bound.get("target_occurrence")
            position = getattr(target, "position", "") or item.target_position or "body"
            parameter = getattr(target, "parameter", "") or item.target_parameter or item.parameter
            locator = dict(getattr(target, "locator", None) or item.target_locator or {})
            resolved = bool(target and locator and not bound.get("ambiguous"))
        elif (
            item.location_status == "resolved"
            and item.target_locator and item.target_parameter
        ):
            position = item.target_position or "body"
            parameter = item.target_parameter or item.parameter
            locator = dict(item.target_locator or {})
            resolved = True
        else:
            bound = bind_relation_locations(item, allow_direction_fix=False)
            target = bound.get("target_occurrence")
            position = getattr(target, "position", "") or item.target_position or "body"
            parameter = getattr(target, "parameter", "") or item.target_parameter or item.parameter
            locator = dict(getattr(target, "locator", None) or item.target_locator or {})
            resolved = bool(target and locator and not bound.get("ambiguous"))
        if resolved:
            targets.append({
                "position": position,
                "parameter": parameter,
                "locator": locator,
            })
    return targets


def _domain_suffix(host: str) -> str:
    parts = normalize_host(host).split(".")
    return ".".join(parts[-3:]) if len(parts) >= 3 else ".".join(parts)


def host_candidates(endpoint: Optional[raw_data], environment: Optional[ProjectEnvironment],
                    profile: Optional[ProjectAuthProfile] = None,
                    selected_host: str = "") -> List[Dict[str, Any]]:
    if not environment:
        return []
    endpoint_host = normalize_host(getattr(endpoint, "domain", "") or getattr(endpoint, "url", ""))
    allowed = {normalize_host(item) for item in (getattr(profile, "allowed_hosts", None) or [])}
    allowed.discard("")
    base_by_host: Dict[str, str] = {}
    for item in environment.hosts or []:
        if isinstance(item, dict):
            host = normalize_host(item.get("host") or item.get("base_url"))
            base_url = _text(item.get("base_url") or item.get("host"))
        else:
            host = normalize_host(item)
            base_url = _text(item)
        if host:
            base_by_host.setdefault(host, base_url if "://" in base_url else "https://" + base_url)
    for host in environment_host_names(environment):
        base_by_host.setdefault(host, "https://" + host)

    selected = normalize_host(selected_host)
    default_host = normalize_host(environment.default_host)
    result = []
    for host, base_url in base_by_host.items():
        if allowed and host not in allowed:
            continue
        score = 10
        reasons = []
        if selected and host == selected:
            score += 200
            reasons.append("人工/历史选定")
        if endpoint_host and host == endpoint_host:
            score += 100
            reasons.append("接口域名精确匹配")
        elif endpoint_host and _domain_suffix(host) == _domain_suffix(endpoint_host):
            score += 45
            reasons.append("同一产品域")
        if default_host and host == default_host:
            score += 25
            reasons.append("环境默认")
        result.append({
            "host": host,
            "base_url": base_url,
            "score": score,
            "reason": "、".join(reasons) or "环境候选",
            "exact": bool(endpoint_host and host == endpoint_host),
        })
    result.sort(key=lambda item: (-int(item["score"]), item["host"]))
    return result


def profile_is_test_account(profile: Optional[ProjectAuthProfile]) -> bool:
    if not profile:
        return False
    binding = ProjectAccountBinding.objects(
        project_id=profile.project_id,
        env_id=profile.env_id,
        account_key=profile.account_key,
        active=True,
    ).first()
    if not binding:
        return False
    explicit = getattr(binding, "is_test_account", None)
    if explicit is not None:
        return bool(explicit)
    return _text(binding.role).lower() in {"test", "tester", "testing", "qa", "owner", "attacker"}


def mutation_execution_allowed(environment: Optional[ProjectEnvironment],
                               source_profile: Optional[ProjectAuthProfile],
                               consumer_profile: Optional[ProjectAuthProfile]) -> bool:
    policy = environment_execution_policy(environment)
    return bool(
        policy["allow_mutation"]
        and profile_is_test_account(source_profile)
        and profile_is_test_account(consumer_profile)
    )


def _default_profiles(project_id: str, env_id: str) -> Tuple[Optional[ProjectAuthProfile], Optional[ProjectAuthProfile]]:
    profiles = list(ProjectAuthProfile.objects(
        project_id=_text(project_id), env_id=_text(env_id), active=True,
    ).order_by("-is_default", "name"))
    profile = next((item for item in profiles if item.is_default), profiles[0] if profiles else None)
    return profile, profile


def _latest_validation(relation: parameter_relation) -> Optional[parameter_validation_result]:
    return parameter_validation_result.objects(relation=relation).order_by("-ctime").first()


def _latest_source_validation(
    relation: parameter_relation,
    source_profile: Optional[ProjectAuthProfile],
    environment: Optional[ProjectEnvironment],
) -> Optional[parameter_validation_result]:
    """Return the latest observation for the shared source request context."""
    if not relation.project_id or not source_profile or not environment:
        return None
    return parameter_validation_result.objects(
        project_id=relation.project_id,
        env_id=environment.env_id,
        res_pathid=relation.res_pathid,
        source_profile_id=source_profile.profile_id,
    ).order_by("-ctime").first()


def _is_newer(candidate: Any, baseline: Any) -> bool:
    if not candidate or not baseline:
        return False
    try:
        return candidate > baseline
    except TypeError:
        return False


def _profile_changed_after(
    profile: Optional[ProjectAuthProfile],
    observed_at: Any,
) -> bool:
    if not profile:
        return False
    return any(
        _is_newer(value, observed_at)
        for value in (
            getattr(profile, "mtime", None),
            getattr(profile, "last_refresh_at", None),
        )
    )


def _validation_superseded(
    result: Optional[parameter_validation_result],
    source_input: Dict[str, Any],
    consumer_input: Dict[str, Any],
    source_profile: Optional[ProjectAuthProfile],
    consumer_profile: Optional[ProjectAuthProfile],
) -> bool:
    """A newer fixture/profile change re-enables a previously rejected case."""
    if not result:
        return False
    status = _text(result.status)
    observed_at = result.ctime
    if status in {"source_request_rejected", "consumer_request_rejected"}:
        input_view = (
            source_input if status == "source_request_rejected"
            else consumer_input
        )
        fixture = input_view.get("fixture")
        return _is_newer(getattr(fixture, "mtime", None), observed_at)
    if status in {"source_auth_rejected", "consumer_auth_rejected"}:
        profile = (
            source_profile if status == "source_auth_rejected"
            else consumer_profile
        )
        return _profile_changed_after(profile, observed_at)
    return False


def _result_has_explicit_request_rejection(
    result: Optional[parameter_validation_result],
    role: str,
) -> bool:
    if not result:
        return False
    payload = dict((
        result.source_result if role == "source" else result.consumer_result
    ) or {})
    if payload.get("status_code") in {409, 422}:
        return True
    summary = dict(payload.get("error_summary") or {})
    if (
        summary.get("explicit_business_rejection")
        or summary.get("error_code")
        or summary.get("error_fields")
        or summary.get("has_structured_errors")
    ):
        return True
    return any(
        bool(item.get("explicit_business_rejection"))
        for item in list(payload.get("attempts") or [])
    )


def _effective_validation(
    relation: parameter_relation,
    source_profile: Optional[ProjectAuthProfile],
    consumer_profile: Optional[ProjectAuthProfile],
    environment: Optional[ProjectEnvironment],
    source_input: Dict[str, Any],
    consumer_input: Dict[str, Any],
) -> Optional[parameter_validation_result]:
    """Combine pair-specific evidence with source-endpoint execution health."""
    pair_result = _latest_validation(relation)
    source_result = _latest_source_validation(
        relation, source_profile, environment,
    )
    def is_source_blocker(result: Optional[parameter_validation_result]) -> bool:
        if not result:
            return False
        status = _text(result.status)
        return (
            status == "source_auth_rejected"
            or (
                status == "source_request_rejected"
                and _result_has_explicit_request_rejection(result, "source")
            )
        )

    def source_request_succeeded(
        result: Optional[parameter_validation_result],
    ) -> bool:
        if not result:
            return False
        status = _text(result.status)
        if status == "host_scope_approval_required":
            return _text(
                dict(result.source_result or {}).get("approval_stage")
                or dict(result.consumer_result or {}).get("approval_stage")
            ) == "consumer"
        return status in {
            "verified",
            "mutation_verified",
            "mutation_accepted",
            "mutation_effect_after_error",
            "value_not_found",
            "consumer_failed",
            "consumer_request_rejected",
            "consumer_auth_rejected",
            "consumer_rate_limited",
            "request_budget_exhausted",
        }

    # A later successful source request on any downstream pair supersedes an
    # older source-only blocker for this relation.
    if (
        pair_result
        and _text(pair_result.status) in {
            "source_request_rejected", "source_auth_rejected",
        }
        and source_result
        and str(source_result.id) != str(pair_result.id)
        and _is_newer(source_result.ctime, pair_result.ctime)
        and source_request_succeeded(source_result)
    ):
        pair_result = None

    effective = pair_result
    if (
        is_source_blocker(source_result)
        and (
            not effective
            or str(source_result.id) == str(effective.id)
            or _is_newer(source_result.ctime, effective.ctime)
        )
    ):
        effective = source_result

    if _validation_superseded(
        effective,
        source_input,
        consumer_input,
        source_profile,
        consumer_profile,
    ):
        return None
    return effective


def _attempt_view(item: Dict[str, Any], *, mutation: bool = False) -> Dict[str, Any]:
    host = _text(item.get("host")) or "未记录 Host"
    status_code = item.get("status_code")
    error_type = _text(item.get("error_type"))
    if item.get("ok"):
        message, tone = "请求成功", "good"
    elif status_code in {401, 403}:
        message, tone = "认证或权限被拒绝，已停止跨 Host", "bad"
    elif status_code == 400 and item.get("explicit_business_rejection"):
        message, tone = "结构化业务错误已确认，已停止跨 Host", "bad"
    elif status_code == 400:
        message, tone = "错误性质不明确，按 Host/路由可疑尝试下一 Host", "warn"
    elif status_code in {404, 405, 421}:
        message, tone = "路由未命中，自动尝试下一 Host", "warn"
    elif isinstance(status_code, int) and status_code >= 500:
        message = "服务端异常；写/删已停止跨 Host 并执行回读" if mutation else "服务端异常，已停止跨 Host"
        tone = "bad"
    elif error_type in {"ConnectionError", "ConnectTimeout", "ProxyError", "SSLError", "InvalidURL", "InvalidSchema", "MissingSchema"}:
        message, tone = "尚未取得有效响应，自动尝试下一 Host", "warn"
    elif "Timeout" in error_type:
        message = "响应超时；写/删结果不确定，已停止跨 Host 并执行回读" if mutation else "读取超时"
        tone = "bad"
    elif status_code is not None:
        message, tone = "接口拒绝了当前业务请求，未盲目跨 Host", "bad"
    else:
        message, tone = "请求未完成", "bad"
    return {
        "host": host,
        "status_code": status_code,
        "error_type": error_type,
        "error_code": _text(item.get("error_code")),
        "error_fields": [
            _text(value) for value in list(item.get("error_fields") or []) if _text(value)
        ][:30],
        "response_top_level_keys": [
            _text(value)
            for value in list(item.get("response_top_level_keys") or [])
            if _text(value)
        ][:60],
        "request_method": _text(item.get("request_method")).upper()[:20],
        "request_origin": _text(item.get("request_origin"))[:300],
        "request_path": _text(item.get("request_path"))[:500],
        "request_query_names": [
            _text(value)[:100]
            for value in list(item.get("request_query_names") or [])
            if _text(value)
        ][:100],
        "request_header_names": [
            _text(value)[:100]
            for value in list(item.get("request_header_names") or [])
            if _text(value)
        ][:100],
        "request_cookie_names": [
            _text(value)[:100]
            for value in list(item.get("request_cookie_names") or [])
            if _text(value)
        ][:100],
        "request_auth_header_names": [
            _text(value)[:100]
            for value in list(item.get("request_auth_header_names") or [])
            if _text(value)
        ][:100],
        "request_auth_cookie_names": [
            _text(value)[:100]
            for value in list(item.get("request_auth_cookie_names") or [])
            if _text(value)
        ][:100],
        "request_body_bytes": max(
            0, min(int(item.get("request_body_bytes") or 0), 1_000_000_000),
        ),
        "request_content_type": _text(item.get("request_content_type"))[:120],
        "request_timeout_seconds": item.get("request_timeout_seconds"),
        "request_allow_redirects": bool(
            item.get("request_allow_redirects", False)
        ),
        "request_tls_verify": bool(item.get("request_tls_verify", True)),
        "auth_request_count": max(
            0, min(int(item.get("auth_request_count") or 0), 100),
        ),
        "message": message,
        "tone": tone,
    }


def _validation_view(result: Optional[parameter_validation_result]) -> Dict[str, Any]:
    if not result:
        return {}
    source = dict(result.source_result or {})
    consumer = dict(result.consumer_result or {})
    status = _text(result.status)
    if (
        status == "source_request_rejected"
        and not _result_has_explicit_request_rejection(result, "source")
    ):
        status = "source_failed"
    elif (
        status == "consumer_request_rejected"
        and not _result_has_explicit_request_rejection(result, "consumer")
    ):
        status = "consumer_failed"
    remaining_host_count = int(
        consumer.get("remaining_host_count")
        or source.get("remaining_host_count")
        or 0
    )
    untried_host_count = int(
        consumer.get("untried_host_count")
        or source.get("untried_host_count")
        or 0
    )
    approval_stage = _text(
        consumer.get("approval_stage") or source.get("approval_stage")
    )
    if status != "host_scope_approval_required":
        if status in {
            "source_request_rejected", "consumer_request_rejected",
            "source_auth_rejected", "consumer_auth_rejected",
            "source_rate_limited", "consumer_rate_limited",
        }:
            untried_host_count = max(
                untried_host_count, remaining_host_count,
            )
        remaining_host_count = 0
        approval_stage = ""
    status_messages = {
        "verified": "来源值已被消费接口接受，参数关系成立。",
        "mutation_verified": "写/删请求成功，且回读确认目标状态已发生预期变化。",
        "mutation_accepted": "写/删请求已被接口接受；本次预算用于 Host 尝试，尚未完成效果回读。",
        "mutation_effect_after_error": "接口返回超时或服务错误，但回读确认数据已变化：关系成立，同时发现开发缺陷。",
        "source_failed": "所有预算内的来源 Host 均未取得可用响应。",
        "source_request_rejected": "来源接口已命中，但当前请求数据被业务校验拒绝；消费接口未发送。",
        "source_auth_rejected": "来源接口已命中，但当前认证或角色没有访问权限；消费接口未发送。",
        "source_rate_limited": "来源接口触发限流；消费接口未发送，应等待后再试。",
        "value_not_found": "来源接口可达，但当前响应中没有可提取的目标值。",
        "consumer_failed": "已取得来源值，但消费接口未接受；请按下方 Host 尝试记录纠偏。",
        "consumer_request_rejected": "已取得来源值，但消费请求数据被业务校验拒绝。",
        "consumer_auth_rejected": "已取得来源值，但消费接口拒绝当前认证或角色。",
        "consumer_rate_limited": "已取得来源值，但消费接口触发限流。",
        "request_budget_exhausted": "候选 Host 超出当前环境请求预算，需要确认更大执行范围。",
        "host_scope_approval_required": "当前预算内未命中，但仍有候选 Host；批准后系统会在环境上限内继续。",
    }
    method = _text(consumer.get("method")).upper()
    mutation = method in MUTATION_METHODS
    effect_labels = {
        "delete_observed": "回读确认目标值已消失",
        "value_still_present": "回读发现目标值仍存在",
        "post_read_reachable": "写后来源接口仍可正常读取",
        "post_read_failed": "写后回读未完成",
        "not_checked": "本次请求预算内未执行回读",
    }
    return {
        "status": status,
        "status_label": STATUS_LABELS.get(status, status),
        "summary": status_messages.get(status, "验证已留下结构化运行证据。"),
        "api_defect": status == "mutation_effect_after_error",
        "run_id": str(result.run_id or ""),
        "source_host": _text(result.source_host),
        "consumer_host": _text(result.consumer_host),
        "source_status_code": source.get("status_code"),
        "consumer_status_code": consumer.get("status_code"),
        "request_count": int(consumer.get("request_count") or source.get("request_count") or 0),
        "effect_status": _text(consumer.get("effect_status")),
        "effect_label": effect_labels.get(_text(consumer.get("effect_status")), ""),
        "remaining_host_count": remaining_host_count,
        "untried_host_count": untried_host_count,
        "approval_stage": approval_stage,
        "source_error_summary": dict(source.get("error_summary") or {}),
        "consumer_error_summary": dict(consumer.get("error_summary") or {}),
        "source_attempts": [
            _attempt_view(item, mutation=False) for item in list(source.get("attempts") or [])
        ],
        "consumer_attempts": [
            _attempt_view(item, mutation=mutation) for item in list(consumer.get("attempts") or [])
        ],
        "ctime": result.ctime,
    }


def _confidence(relation: parameter_relation, binding: Dict[str, Any], latest: Dict[str, Any]) -> float:
    score = 0.1
    if relation.location_status == "resolved":
        score += 0.35
    if _leaf_name(relation.source_parameter) == _leaf_name(relation.target_parameter) == _leaf_name(relation.parameter):
        score += 0.2
    if _method(binding.get("source_endpoint")) in READ_METHODS:
        score += 0.1
    if latest.get("status") in {"verified", "mutation_verified", "mutation_effect_after_error"}:
        score += 0.25
    elif latest.get("status") == "mutation_accepted":
        score += 0.15
    if binding.get("ambiguous"):
        score -= 0.3
    return round(max(0.0, min(score, 1.0)), 2)


def _status_conclusion(status: str, mutation: bool = False,
                       latest: Optional[Dict[str, Any]] = None) -> Tuple[str, str]:
    latest = dict(latest or {})
    if status == "stale":
        return (
            "已确认关系的接口结构发生变化",
            "保留原结论和历史证据，但暂停直接复用；按新字段位置完成一次复验后恢复可信状态。",
        )
    if (
        status == "approval_required"
        and latest.get("status") == "host_scope_approval_required"
    ):
        stage = "来源" if latest.get("approval_stage") == "source" else "消费"
        remaining = int(latest.get("remaining_host_count") or 0)
        unsent = "，消费接口尚未发送" if stage == "来源" else ""
        return (
            "等待扩大 Host 范围确认",
            "当前预算内的{} Host 均未取得可用响应{}；还有 {} 个项目候选 Host 未尝试。"
            "确认更大请求预算后可重试，当前结果不代表参数关系错误。".format(
                stage, unsent, remaining,
            ),
        )
    if status == "needs_data" and latest.get("status") in {
        "source_request_rejected", "consumer_request_rejected",
    }:
        source_side = latest.get("status") == "source_request_rejected"
        error_summary = dict(
            latest.get(
                "source_error_summary" if source_side
                else "consumer_error_summary",
            ) or {}
        )
        details = []
        if error_summary.get("error_code"):
            details.append("错误码 {}".format(error_summary["error_code"]))
        if error_summary.get("error_fields"):
            details.append(
                "涉及字段 {}".format("、".join(error_summary["error_fields"][:8]))
            )
        suffix = "；{}".format("；".join(details)) if details else ""
        untried_host_count = int(latest.get("untried_host_count") or 0)
        untried_hint = (
            "另有 {} 个授权 Host 因已取得明确业务错误而未继续尝试。".format(
                untried_host_count,
            )
            if untried_host_count else ""
        )
        return (
            "{}请求数据被业务校验拒绝".format("来源" if source_side else "消费"),
            "接口已命中，系统已停止跨 Host{}。{}"
            "请补充或修正该接口的测试 Fixture 后重新预处理。".format(
                suffix, untried_hint,
            ),
        )
    if status == "needs_context" and latest.get("status") in {
        "source_auth_rejected", "consumer_auth_rejected",
    }:
        return (
            "当前认证或角色被业务接口拒绝",
            "接口已命中，系统没有继续跨 Host。请验证所选登录场景、角色和认证方案后重试。",
        )
    labels = {
        "verified": ("关系已由机器验证", "来源值可以提取并被消费接口正确接受。"),
        "trusted": ("人工纠偏已确认", "人工补充了业务事实，结论已同步到参数经验并可供链路使用。"),
        "accepted": ("写入接口已接受参数", "参数映射成立，但业务效果仍按回读证据分级。"),
        "auto_ready": ("机器可以继续处理", "位置、方向、Host 和账号均已具备，可在小请求预算内自动验证。"),
        "running": ("机器正在验证", "无需人工处理，等待调度结果回写。"),
        "needs_context": ("等待一次性项目配置", "配置环境、Host 和测试账号后，后续关系可批量自动处理。"),
        "needs_data": ("等待补充接口测试数据", "机器已自动填充可确定字段；只需补充剩余必填业务字段，模板会被同接口后续验证复用。"),
        "needs_correction": ("机器无法唯一消歧", "只需人工纠正方向、字段位置或 Host，不需要手工填写算法分数。"),
        "approval_required": ("等待批量执行确认", "关系判断已完成，只需确认较大的请求范围。"),
        "automatic_failed": ("自动验证尚未完成", "系统已尝试；请按结构化失败原因切换 Host、账号或补业务数据。"),
        "policy_blocked": ("执行策略阻止写入", "当前不是获准的测试/预发环境或所选账号不是测试账号。"),
        "rejected": ("关系已排除", "人工已确认它不是可复用的上下游关系。"),
    }
    return labels.get(status, ("等待机器预处理", "系统尚未生成可执行结论。"))


def preprocess_relation(relation: parameter_relation, *,
                        environment: Optional[ProjectEnvironment] = None,
                        source_profile: Optional[ProjectAuthProfile] = None,
                        consumer_profile: Optional[ProjectAuthProfile] = None,
                        persist: bool = True,
                        allow_direction_fix: bool = True,
                        update_readiness: bool = True) -> Dict[str, Any]:
    protected_mapping = bool(
        relation.stale_reason and (
            relation.verified
            or relation.manual_decision == "trusted"
            or relation.discovery_source == "manual_override"
        )
    )
    confirmed_mapping = None
    if protected_mapping:
        confirmed_mapping = {
            "req_pathid": relation.req_pathid,
            "res_pathid": relation.res_pathid,
            "source_parameter": relation.source_parameter,
            "target_parameter": relation.target_parameter,
            "source_position": relation.source_position,
            "target_position": relation.target_position,
            "source_locator": dict(relation.source_locator or {}),
            "target_locator": dict(relation.target_locator or {}),
            "location_status": relation.location_status,
            "location_note": relation.location_note,
        }
    binding = bind_relation_locations(
        relation,
        allow_direction_fix=bool(allow_direction_fix and not protected_mapping),
    )
    if confirmed_mapping:
        for field, value in confirmed_mapping.items():
            setattr(relation, field, value)
    source_endpoint = binding["source_endpoint"]
    consumer_endpoint = binding["consumer_endpoint"]
    if environment is None and relation.project_id:
        env_query = {"project_id": relation.project_id, "active": True}
        if relation.env_id:
            environment = ProjectEnvironment.objects(env_id=relation.env_id, **env_query).first()
        environment = environment or ProjectEnvironment.objects(**env_query).order_by("env_id").first()
    if environment:
        relation.env_id = environment.env_id
    if (source_profile is None or consumer_profile is None) and environment:
        default_source, default_consumer = _default_profiles(relation.project_id, environment.env_id)
        source_profile = source_profile or default_source
        consumer_profile = consumer_profile or default_consumer

    source_hosts = host_candidates(
        source_endpoint, environment, source_profile, relation.selected_source_host,
    )
    consumer_hosts = host_candidates(
        consumer_endpoint, environment, consumer_profile, relation.selected_consumer_host,
    )
    if source_hosts:
        relation.selected_source_host = source_hosts[0]["host"]
    if consumer_hosts:
        relation.selected_consumer_host = consumer_hosts[0]["host"]

    peer_relations = list(parameter_relation.objects(
        project_id=relation.project_id,
        res_pathid=relation.res_pathid,
        req_pathid=relation.req_pathid,
        manual_decision__nin=["rejected", "deleted"],
    )) if relation.project_id else [relation]
    relation_targets = _peer_relation_targets(
        peer_relations, current_relation=relation, current_binding=binding,
    )
    source_input = {}
    consumer_input = {}
    if environment and source_profile and source_endpoint:
        source_input = request_input_view(
            relation.res_pathid, relation.project_id, environment.env_id,
            source_profile.profile_id,
            account_id=source_profile.account_key,
        )
    if environment and consumer_profile and consumer_endpoint:
        consumer_input = request_input_view(
            relation.req_pathid, relation.project_id, environment.env_id,
            consumer_profile.profile_id, account_id=consumer_profile.account_key,
            relation_targets=relation_targets,
        )

    latest_result = _effective_validation(
        relation,
        source_profile,
        consumer_profile,
        environment,
        source_input,
        consumer_input,
    )
    latest = _validation_view(latest_result)
    source_method = _method(source_endpoint)
    consumer_method = _method(consumer_endpoint)
    mutation = consumer_method in MUTATION_METHODS
    estimate = relation_request_estimate(consumer_method)
    policy = environment_execution_policy(environment)
    codes = list(binding["reason_codes"])
    if len(peer_relations) > 1:
        codes.append("MULTI_PARAMETER_CASE")
    scheduled_verified = bool(
        relation.verified
        and _text(relation.feedback_note).startswith("scheduled parameter validation:")
    )
    if relation.verified and not latest and not scheduled_verified:
        codes.append("LEGACY_RUNTIME_OBSERVED")
    if source_hosts:
        codes.append("HOST_EXACT_MATCH" if source_hosts[0]["exact"] else "HOST_FALLBACK")

    if relation.manual_decision == "deleted":
        status = "deleted"
    elif relation.stale_reason:
        status = "stale"
        codes.append("EXPERIENCE_STALE")
    elif relation.manual_decision == "rejected":
        status = "rejected"
    elif relation.manual_decision == "trusted":
        status = "trusted"
        codes.append("MANUAL_RELATION_CONFIRMED")
    elif relation.manual_decision == "needs_data":
        status = "needs_data"
        codes.append("MANUAL_DATA_REQUIRED")
    elif relation.manual_decision == "stale":
        status = "needs_context"
        codes.append("EXPERIENCE_STALE")
    elif latest.get("status") in {"verified", "mutation_verified", "mutation_effect_after_error"} or scheduled_verified:
        status = "verified"
        codes.append("LATEST_VALIDATION_PASSED")
        if latest.get("status") == "mutation_effect_after_error":
            codes.append("MUTATION_EFFECT_AFTER_ERROR")
    elif latest.get("status") == "mutation_accepted":
        status = "accepted"
        codes.append("LATEST_VALIDATION_PASSED")
    elif not source_endpoint or not consumer_endpoint or relation.location_status != "resolved" or binding["ambiguous"]:
        status = "needs_correction"
    elif source_method not in READ_METHODS:
        status = "needs_correction"
        codes.append("SOURCE_NOT_READ_ONLY")
    elif not environment:
        status = "needs_context"
        codes.append("ENVIRONMENT_REQUIRED")
    elif not source_profile or not consumer_profile:
        status = "needs_context"
        codes.append("AUTH_PROFILE_REQUIRED")
    elif not source_hosts or not consumer_hosts:
        status = "needs_context"
        codes.append("HOST_REQUIRED")
    elif mutation and not mutation_execution_allowed(environment, source_profile, consumer_profile):
        status = "policy_blocked"
        codes.append("MUTATION_POLICY_BLOCKED")
    elif latest.get("status") in {
        "source_request_rejected", "consumer_request_rejected",
    }:
        status = "needs_data"
        codes.append("LATEST_REQUEST_DATA_REJECTED")
    elif latest.get("status") in {
        "source_auth_rejected", "consumer_auth_rejected",
    }:
        status = "needs_context"
        codes.append("LATEST_BUSINESS_AUTH_REJECTED")
    elif (source_input.get("gaps") or consumer_input.get("gaps")):
        status = "needs_data"
        codes.append("REQUEST_INPUT_GAPS")
    elif estimate > policy["auto_request_limit"]:
        status = "approval_required"
        codes.append("LARGE_RUN_APPROVAL_REQUIRED")
    elif latest.get("status") == "host_scope_approval_required":
        status = "approval_required"
        codes.append("HOST_SWEEP_APPROVAL_REQUIRED")
    elif latest and latest.get("status") not in {
            "verified", "mutation_verified", "mutation_accepted", "mutation_effect_after_error"}:
        status = "automatic_failed"
        codes.append("LATEST_VALIDATION_FAILED")
    else:
        status = "auto_ready"
        codes.append("AUTO_REQUEST_BUDGET_OK")
        codes.append("REQUEST_INPUT_READY")
        if mutation:
            codes.append("MUTATION_POLICY_ALLOWED")

    if status == "approval_required":
        relation.approval_status = "pending"
    elif status not in {"running"}:
        relation.approval_status = "not_required"
    relation.preprocess_version = PREPROCESS_VERSION
    relation.preprocess_status = status
    relation.preprocess_reason_codes = list(dict.fromkeys(codes))
    relation.machine_confidence = _confidence(relation, binding, latest)
    relation.estimated_requests = estimate
    relation.last_preprocessed_at = utcnow()
    title, detail = _status_conclusion(status, mutation=mutation, latest=latest)
    relation.preprocess_summary = {
        "title": title,
        "detail": detail,
        "source": endpoint_view(source_endpoint),
        "consumer": endpoint_view(consumer_endpoint),
        "mapping": {
            "source": _locator_label(binding["source_occurrence"], "response"),
            "consumer": _locator_label(binding["target_occurrence"], "request"),
            "source_parameter": _text(relation.source_parameter or relation.parameter),
            "target_parameter": _text(relation.target_parameter or relation.parameter),
        },
        "source_hosts": source_hosts[:5],
        "consumer_hosts": consumer_hosts[:5],
        "execution": {
            "mode": "test_mutation" if mutation else "read_only",
            "estimated_requests": estimate,
            "automatic_limit": policy["auto_request_limit"],
            "environment_type": policy["environment_type"],
            "mutation_allowed": bool(policy["allow_mutation"]),
        },
        "latest_validation": latest,
        "pair_relation_count": len(peer_relations),
        "pair_parameters": sorted({item.parameter for item in peer_relations if item.parameter}),
        "source_input": {
            "coverage": source_input.get("coverage") or {},
            "gaps": source_input.get("gaps") or [],
            "ready": source_input.get("ready", True),
        },
        "consumer_input": {
            "coverage": consumer_input.get("coverage") or {},
            "gaps": consumer_input.get("gaps") or [],
            "ready": consumer_input.get("ready", True),
        },
    }
    relation.mtime = utcnow()
    if persist:
        relation.save()
        if update_readiness:
            refresh_parameter_readiness(relation.project_id, relation.parameter)
    return relation_workbench_view(
        relation,
        environment=environment,
        source_profile=source_profile,
        consumer_profile=consumer_profile,
        binding=binding,
        latest=latest,
        source_input=source_input,
        consumer_input=consumer_input,
    )


def relation_workbench_view(relation: parameter_relation, *,
                            environment: Optional[ProjectEnvironment] = None,
                            source_profile: Optional[ProjectAuthProfile] = None,
                            consumer_profile: Optional[ProjectAuthProfile] = None,
                            binding: Optional[Dict[str, Any]] = None,
                            latest: Optional[Dict[str, Any]] = None,
                            source_input: Optional[Dict[str, Any]] = None,
                            consumer_input: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    binding = binding or bind_relation_locations(relation, allow_direction_fix=False)
    summary = dict(relation.preprocess_summary or {})
    latest = dict(
        latest if latest is not None
        else _validation_view(_latest_validation(relation))
    )
    status = _text(relation.preprocess_status) or "pending"
    if latest.get("status") == "host_scope_approval_required":
        approval_stage = latest.get("approval_stage")
        stage_endpoint = (
            binding.get("source_endpoint")
            if approval_stage == "source"
            else binding.get("consumer_endpoint")
        )
        stage_profile = (
            source_profile if approval_stage == "source" else consumer_profile
        )
        selected_host = (
            relation.selected_source_host
            if approval_stage == "source"
            else relation.selected_consumer_host
        )
        if stage_endpoint and environment and stage_profile:
            attempted_hosts = {
                _text(item.get("host"))
                for item in (
                    latest.get("source_attempts")
                    if approval_stage == "source"
                    else latest.get("consumer_attempts")
                ) or []
                if item.get("host")
            }
            full_hosts = {
                _text(item.get("host"))
                for item in host_candidates(
                    stage_endpoint, environment, stage_profile, selected_host,
                )
                if item.get("host")
            }
            latest["remaining_host_count"] = max(
                int(latest.get("remaining_host_count") or 0),
                len(full_hosts - attempted_hosts),
            )
    title, detail = _status_conclusion(
        status,
        mutation=_method(binding.get("consumer_endpoint")) in MUTATION_METHODS,
        latest=latest,
    )
    source_hosts = list(summary.get("source_hosts") or host_candidates(
        binding.get("source_endpoint"), environment, source_profile, relation.selected_source_host,
    ))
    consumer_hosts = list(summary.get("consumer_hosts") or host_candidates(
        binding.get("consumer_endpoint"), environment, consumer_profile, relation.selected_consumer_host,
    ))
    codes = list(relation.preprocess_reason_codes or [])
    historical = [code for code in (relation.reason_codes or []) if code not in codes]
    evidence_items = reason_views(codes)
    historical_items = reason_views(historical)
    peer_relations = list(parameter_relation.objects(
        project_id=relation.project_id,
        res_pathid=relation.res_pathid,
        req_pathid=relation.req_pathid,
        manual_decision__nin=["rejected", "deleted"],
    ).order_by("parameter", "id")) if relation.project_id else [relation]
    peer_relations = peer_relations or [relation]
    pair_mappings = []
    for peer in peer_relations:
        is_current = str(peer.id) == str(relation.id)
        if is_current:
            peer_binding = binding
        elif (
            peer.location_status == "resolved" and peer.source_locator
            and peer.target_locator and peer.source_parameter and peer.target_parameter
        ):
            peer_binding = {
                "source_occurrence": SimpleNamespace(
                    parameter=peer.source_parameter, position=peer.source_position or "body",
                    locator=dict(peer.source_locator or {}), display_path=peer.source_parameter,
                    schema_path=peer.source_parameter,
                ),
                "target_occurrence": SimpleNamespace(
                    parameter=peer.target_parameter, position=peer.target_position or "body",
                    locator=dict(peer.target_locator or {}), display_path=peer.target_parameter,
                    schema_path=peer.target_parameter,
                ),
                "complete": True, "ambiguous": False,
            }
        else:
            peer_binding = bind_relation_locations(peer, allow_direction_fix=False)
        peer_summary = dict(peer.preprocess_summary or {})
        peer_mapping = dict(peer_summary.get("mapping") or {})
        peer_status = status if is_current else (
            _text(peer.preprocess_status) or ("verified" if peer.verified else "pending")
        )
        pair_mappings.append({
            "relation_id": str(peer.id),
            "parameter": _text(peer.parameter),
            "source": _locator_label(peer_binding.get("source_occurrence"), "response")
            or peer_mapping.get("source") or _text(peer.source_parameter or peer.parameter),
            "consumer": _locator_label(peer_binding.get("target_occurrence"), "request")
            or peer_mapping.get("consumer") or _text(peer.target_parameter or peer.parameter),
            "source_position": _text(peer.source_position or "body"),
            "target_position": _text(peer.target_position or "body"),
            "source_parameter": _text(peer.source_parameter or peer.parameter),
            "target_parameter": _text(peer.target_parameter or peer.parameter),
            "status": peer_status,
            "status_label": STATUS_LABELS.get(peer_status, peer_status),
            "verified": bool(peer.verified),
            "resolved": bool(peer_binding.get("complete") and not peer_binding.get("ambiguous")),
            "manual_override": peer.discovery_source == "manual_override",
            "stale_reason": _text(peer.stale_reason),
        })
    relation_targets = _peer_relation_targets(
        peer_relations, current_relation=relation, current_binding=binding,
    )
    source_input_provided = source_input is not None
    consumer_input_provided = consumer_input is not None
    source_input = source_input if source_input_provided else dict(summary.get("source_input") or {})
    consumer_input = consumer_input if consumer_input_provided else dict(summary.get("consumer_input") or {})
    if not source_input_provided and environment and source_profile and binding.get("source_endpoint"):
        source_input = request_input_view(
            relation.res_pathid, relation.project_id, environment.env_id,
            source_profile.profile_id,
            account_id=source_profile.account_key,
        )
    if not consumer_input_provided and environment and consumer_profile and binding.get("consumer_endpoint"):
        consumer_input = request_input_view(
            relation.req_pathid, relation.project_id, environment.env_id,
            consumer_profile.profile_id, account_id=consumer_profile.account_key,
            relation_targets=relation_targets,
        )
    return {
        "doc": relation,
        "status": status,
        "status_label": STATUS_LABELS.get(status, status),
        "conclusion_title": (
            title
            if latest.get("status") == "host_scope_approval_required"
            else summary.get("title") or title
        ),
        "conclusion_detail": (
            detail
            if latest.get("status") == "host_scope_approval_required"
            else summary.get("detail") or detail
        ),
        "source": summary.get("source") or endpoint_view(binding.get("source_endpoint")),
        "consumer": summary.get("consumer") or endpoint_view(binding.get("consumer_endpoint")),
        "mapping": summary.get("mapping") or {
            "source": _locator_label(binding.get("source_occurrence"), "response"),
            "consumer": _locator_label(binding.get("target_occurrence"), "request"),
            "source_parameter": _text(relation.source_parameter or relation.parameter),
            "target_parameter": _text(relation.target_parameter or relation.parameter),
        },
        "source_hosts": source_hosts,
        "consumer_hosts": consumer_hosts,
        "latest_validation": latest,
        "evidence_items": evidence_items,
        "historical_evidence_items": historical_items,
        "raw_evidence": list(relation.evidence or []),
        "pair_relation_count": len(peer_relations),
        "pair_parameters": sorted({item.parameter for item in peer_relations if item.parameter}),
        "pair_mappings": pair_mappings,
        "source_input": source_input,
        "consumer_input": consumer_input,
        "can_auto_run": status == "auto_ready",
        "can_approve": status == "approval_required" or relation.approval_status == "pending",
        "needs_human_correction": status == "needs_correction",
        "protected": bool(
            relation.verified or relation.manual_decision == "trusted"
            or relation.discovery_source == "manual_override"
        ),
        "discovery_source": _text(relation.discovery_source),
        "evidence_sources": list(relation.evidence_sources or []),
        "stale_reason": _text(relation.stale_reason),
    }


def select_relation_hosts(relation: parameter_relation, environment: ProjectEnvironment,
                          source_profile: ProjectAuthProfile, consumer_profile: ProjectAuthProfile,
                          source_host: str, consumer_host: str) -> parameter_relation:
    source = normalize_host(source_host)
    consumer = normalize_host(consumer_host)
    source_allowed = {item["host"] for item in host_candidates(
        _endpoint(relation.res_pathid, relation.project_id), environment, source_profile,
    )}
    consumer_allowed = {item["host"] for item in host_candidates(
        _endpoint(relation.req_pathid, relation.project_id), environment, consumer_profile,
    )}
    if source not in source_allowed or consumer not in consumer_allowed:
        raise ValueError("所选 Host 不属于当前环境和认证方案")
    relation.selected_source_host = source
    relation.selected_consumer_host = consumer
    relation.preprocess_status = "pending"
    relation.mtime = utcnow()
    relation.save()
    return relation


def swap_relation_direction(relation: parameter_relation, operator: str = "") -> parameter_relation:
    relation.req_pathid, relation.res_pathid = relation.res_pathid, relation.req_pathid
    relation.source_parameter, relation.target_parameter = relation.target_parameter, relation.source_parameter
    relation.source_position, relation.target_position = relation.target_position, relation.source_position
    relation.source_locator, relation.target_locator = relation.target_locator, relation.source_locator
    relation.selected_source_host, relation.selected_consumer_host = (
        relation.selected_consumer_host, relation.selected_source_host,
    )
    relation.location_status = "pending"
    relation.location_note = "direction changed by {}".format(_text(operator) or "operator")
    relation.preprocess_status = "pending"
    relation.modificator = _text(operator) or relation.modificator
    relation.mtime = utcnow()
    relation.save()
    return relation


def sync_relation_experience(relation: parameter_relation, *, operator: str = "") -> Optional[parameter_experience]:
    """Project an edge-level conclusion into the reusable parameter policy."""
    if not relation.project_id or not relation.parameter:
        return None
    canonical_key = parameter_identity(relation.parameter)
    priority = parameter_priority_item.objects(
        project_id=relation.project_id, canonical_key=canonical_key,
    ).first() or parameter_priority_item.objects(
        project_id=relation.project_id, parameter=relation.parameter,
    ).first()
    group_key = priority.parameter if priority else relation.parameter
    experience = parameter_experience.objects(
        project_id=relation.project_id,
        parameter=relation.parameter,
        group_key=group_key,
    ).first() or parameter_experience(
        project_id=relation.project_id,
        parameter=relation.parameter,
        group_key=group_key,
        ctime=utcnow(),
    )
    if relation.manual_decision == "rejected":
        experience.process_status = "rejected"
        experience.reuse_policy = "do_not_reuse"
        experience.chain_policy = "do_not_use"
        experience.validation_policy = "ignored"
    elif relation.manual_decision == "trusted" or relation.preprocess_status == "verified":
        experience.process_status = "trusted"
        experience.reuse_policy = "reusable"
        experience.chain_policy = "can_build_chain"
        experience.validation_policy = "verified"
        experience.confidence = max(float(experience.confidence or 0), float(relation.machine_confidence or 0))
    elif relation.preprocess_status == "accepted":
        if experience.process_status not in {"trusted", "reusable"}:
            experience.process_status = "needs_verify"
        if experience.reuse_policy == "unknown":
            experience.reuse_policy = "conditional"
        if experience.chain_policy == "unknown":
            experience.chain_policy = "needs_verify"
        experience.validation_policy = "needs_verify"
        experience.confidence = max(float(experience.confidence or 0), float(relation.machine_confidence or 0))
    else:
        return experience if experience.id else None
    if operator:
        experience.reviewer = _text(operator)
    elif not experience.reviewer:
        experience.reviewer = "machine"
    experience.mtime = utcnow()
    experience.save()
    refresh_parameter_readiness(relation.project_id, relation.parameter)
    return experience


def refresh_parameter_readiness(project_id: str, parameter: str, *,
                                relations: Optional[Sequence[parameter_relation]] = None) -> Optional[parameter_priority_item]:
    canonical_key = parameter_identity(parameter)
    item = parameter_priority_item.objects(
        project_id=_text(project_id), parameter=_text(parameter),
    ).first() or parameter_priority_item.objects(
        project_id=_text(project_id), canonical_key=canonical_key,
    ).first()
    if not item:
        return None
    item_identity = item.canonical_key or canonical_key or parameter_identity(item.parameter)
    if relations is None:
        relations = [
            row for row in parameter_relation.objects(project_id=_text(project_id))
            if parameter_identity(row.parameter) == item_identity
        ]
    else:
        relations = list(relations)
    counts = Counter(_text(row.preprocess_status) or "pending" for row in relations)
    if counts.get("verified"):
        status, readiness = "verified", 100.0
    elif counts.get("trusted"):
        status, readiness = "trusted", 90.0
    elif counts.get("accepted"):
        status, readiness = "accepted", 78.0
    elif counts.get("auto_ready"):
        status, readiness = "auto_ready", 60.0
    elif counts.get("running"):
        status, readiness = "running", 50.0
    elif counts.get("stale"):
        status, readiness = "stale", 25.0
    elif counts.get("needs_data"):
        status, readiness = "needs_data", 35.0
    elif counts.get("needs_context"):
        status, readiness = "needs_context", 30.0
    elif counts.get("policy_blocked"):
        status, readiness = "policy_blocked", 20.0
    elif counts.get("needs_correction") or counts.get("automatic_failed"):
        status, readiness = "needs_correction", 10.0
    elif relations:
        status, readiness = "pending", 15.0
    else:
        status, readiness = "no_relation", 0.0
    item.readiness_status = status
    item.readiness_score = readiness
    item.readiness_reasons = [
        "{}={}".format(key, value) for key, value in sorted(counts.items()) if value
    ][:12]
    importance = float(item.rule_weight or 0)
    # Work priority answers "what should the machine/human unblock next"; it
    # deliberately differs from business importance and chain readiness.
    item.work_priority = round(importance * (1.0 - readiness / 100.0), 2)
    item.mtime = utcnow()
    item.save()
    return item


def preprocess_relations(project_id: str, *, env_id: str = "", pathids: Optional[Sequence[int]] = None,
                         limit: int = 0,
                         source_profile: Optional[ProjectAuthProfile] = None,
                         consumer_profile: Optional[ProjectAuthProfile] = None) -> Dict[str, Any]:
    project_id = _text(project_id)
    environment_query: Dict[str, Any] = {"project_id": project_id, "active": True}
    environment = None
    if env_id:
        environment = ProjectEnvironment.objects(env_id=_text(env_id), **environment_query).first()
    environment = environment or ProjectEnvironment.objects(**environment_query).order_by("env_id").first()
    if environment and (source_profile is None or consumer_profile is None):
        default_source, default_consumer = _default_profiles(project_id, environment.env_id)
        source_profile = source_profile or default_source
        consumer_profile = consumer_profile or default_consumer
    query: Dict[str, Any] = {"project_id": project_id}
    if pathids:
        selected = [int(item) for item in pathids]
        query = {"__raw__": {
            "project_id": project_id,
            "$or": [
                {"req_pathid": {"$in": selected}},
                {"res_pathid": {"$in": selected}},
            ],
        }}
    rows = parameter_relation.objects(**query).order_by("id")
    if limit and int(limit) > 0:
        rows = rows[:int(limit)]
    counts: Counter = Counter()
    processed = 0
    affected_parameters = set()
    for relation in rows:
        view = preprocess_relation(
            relation,
            environment=environment,
            source_profile=source_profile,
            consumer_profile=consumer_profile,
            persist=True,
            update_readiness=False,
        )
        counts[view["status"]] += 1
        affected_parameters.add(_text(relation.parameter))
        processed += 1
    for parameter in sorted(item for item in affected_parameters if item):
        refresh_parameter_readiness(project_id, parameter)
    return {
        "project_id": project_id,
        "env_id": environment.env_id if environment else _text(env_id),
        "processed": processed,
        "counts": dict(counts),
        "preprocess_version": PREPROCESS_VERSION,
    }
