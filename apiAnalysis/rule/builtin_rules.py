"""Built-in predicates and typed dry-run output adapters for rule.v1."""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, Iterable, Mapping, Sequence, Tuple

from apiAnalysis.rule.framework import (
    EndpointClassificationCandidate,
    EndpointFact,
    EvaluationReport,
    LocatorFact,
    OfflineRuleEngine,
    OutputAdapterDefinition,
    OutputAdapterRegistry,
    ParameterOccurrenceFact,
    ParameterRelationCandidate,
    PredicateDefinition,
    PredicateRegistry,
    PredicateResult,
    RuleProtocolError,
    RuleSpec,
    ScoreContribution,
    summarize_values,
)
from apiAnalysis.rule.legacy_scoring import classify_endpoint_detail, score_weak_relation


RULE_SPEC_DIR = Path(__file__).with_name("specs")
LEGACY_ACTION_MAP = {
    "Auth_Path": "endpoint.auth",
    "Download_Path": "endpoint.download",
    "Upload_Path": "endpoint.upload",
    "D_Path": "endpoint.delete",
    "M_Path": "endpoint.modify",
    "C_Path": "endpoint.create",
    "Q_Path": "endpoint.query",
}
PARAMETER_CATEGORIES = {
    "auth_session", "dynamic", "pagination_filter", "generic_enum", "resource", "unknown",
}
_AUTH_NAMES = {
    "authorization", "auth", "token", "access_token", "refresh_token", "cookie", "session",
    "session_id", "sid", "sign", "signature", "csrf", "csrf_token", "password", "passwd",
    "captcha", "seccode", "otp", "secret", "api_key", "apikey",
}
_DYNAMIC_NAMES = {
    "timestamp", "time", "ts", "nonce", "request_id", "requestid", "trace_id", "traceid",
    "correlation_id", "correlationid", "request_uuid",
}
_PAGINATION_NAMES = {
    "page", "page_no", "page_num", "page_size", "size", "limit", "offset", "sort", "order",
    "keyword", "filter", "cursor", "start", "count",
}
_GENERIC_ENUM_NAMES = {
    "status", "type", "code", "state", "enabled", "disabled", "active", "flag", "mode",
    "lang", "locale",
}


def normalize_parameter_name(value: Any) -> str:
    text = str(value or "").strip().split(".")[-1]
    text = re.sub(r"\[[^\]]*\]", "", text)
    text = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", text)
    text = re.sub(r"[^a-zA-Z0-9_]+", "_", text).strip("_").lower()
    return re.sub(r"_+", "_", text)


def classify_parameter_category(name: Any, values: Iterable[Any] = ()) -> str:
    """Classify context parameters before values are irreversibly digested."""
    normalized = normalize_parameter_name(name)
    compact = normalized.replace("_", "")
    if normalized in _AUTH_NAMES or any(token in compact for token in ("accesstoken", "refreshtoken", "csrf")):
        return "auth_session"
    if normalized in _DYNAMIC_NAMES or compact.endswith("requestid") or compact.endswith("traceid"):
        return "dynamic"
    if normalized in _PAGINATION_NAMES:
        return "pagination_filter"
    if normalized in _GENERIC_ENUM_NAMES:
        return "generic_enum"
    materialized = list(values or ())
    unique = set()
    low_cardinality = True
    for value in materialized:
        try:
            unique.add(json.dumps(value, ensure_ascii=False, sort_keys=True))
        except TypeError:
            unique.add(str(value))
        if not (value is None or isinstance(value, bool) or (isinstance(value, int) and abs(value) <= 10)):
            low_cardinality = False
    if materialized and len(unique) <= 10 and low_cardinality:
        return "generic_enum"
    if normalized == "id" or normalized.endswith("_id") or compact.endswith("id") or any(
        token in normalized for token in ("owner", "tenant", "resource", "account", "user", "device")
    ):
        return "resource"
    return "unknown"


def parameter_occurrence_from_values(*, fact_id: str, project_id: str, env_id: str,
                                     endpoint_ref: str, pathid: int, direction: str,
                                     canonical_name: str, parameter_type: str,
                                     required: bool, locator: Mapping[str, Any],
                                     values: Iterable[Any], source_kind: str = "synthetic",
                                     principal_id: str = "", profile_revision_id: str = "",
                                     scope_key: str = "") -> ParameterOccurrenceFact:
    materialized = tuple(values or ())
    normalized_name = normalize_parameter_name(canonical_name)
    observation = summarize_values(
        fact_id="{}:observation".format(fact_id),
        project_id=project_id,
        env_id=env_id,
        source_kind=source_kind,
        values=materialized,
    )
    return ParameterOccurrenceFact(
        fact_id=fact_id,
        project_id=project_id,
        env_id=env_id,
        endpoint_ref=endpoint_ref,
        pathid=int(pathid),
        direction=direction,
        canonical_name=normalized_name,
        parameter_type=str(parameter_type or "unknown").lower(),
        required=bool(required),
        locator=LocatorFact.from_mapping(locator),
        category=classify_parameter_category(normalized_name, materialized),
        observation=observation,
        principal_id=principal_id,
        profile_revision_id=profile_revision_id,
        scope_key=scope_key,
    )


def endpoint_fact_from_document(value: Any) -> EndpointFact:
    """Project one already-loaded raw_data-like document without querying storage."""
    pathid = int(getattr(value, "ptah_id", getattr(value, "pathid", 0)) or 0)
    action = str(getattr(value, "action", "") or "")
    rule = str(getattr(value, "rule", "") or "")
    source = "none"
    if action:
        source = "machine" if rule.startswith(("path_score", "abstract_rule:")) else "manual"
    raw_req = getattr(value, "raw_req", ()) or ()
    return EndpointFact(
        fact_id="endpoint:{}".format(pathid),
        project_id=str(getattr(value, "project_id", "") or ""),
        env_id=str(getattr(value, "env_id", "") or ""),
        pathid=pathid,
        method=str(getattr(value, "method", "") or ""),
        path_template=str(getattr(value, "path", "") or ""),
        action=action,
        classification_source=source,
        media_type=str(getattr(value, "content_type", "") or ""),
        has_request_body=bool(raw_req and any(item not in (None, b"", "") for item in raw_req)),
        response_status_codes=tuple(int(item) for item in (getattr(value, "response_status_code", ()) or ())),
    )


def parameter_occurrence_from_document(value: Any, *, source_kind: str = "domain_projection",
                                       principal_id: str = "", profile_revision_id: str = "",
                                       scope_key: str = "") -> ParameterOccurrenceFact:
    """Project one loaded req_data/res_data-like document into a bounded fact."""
    endpoint = getattr(value, "raw_data", None)
    if endpoint is None:
        raise ValueError("parameter occurrence requires an endpoint document")
    direction = str(getattr(value, "direction", "") or "")
    if direction not in {"request", "response"}:
        raise ValueError("parameter occurrence direction is invalid")
    pathid = int(getattr(endpoint, "ptah_id", getattr(endpoint, "pathid", 0)) or 0)
    canonical_name = str(
        getattr(value, "canonical_name", "") or getattr(value, "parameter", "") or ""
    )
    locator = dict(getattr(value, "locator", {}) or {})
    if not locator:
        raise ValueError("parameter occurrence requires a typed locator")
    document_id = str(getattr(value, "id", "") or "")
    fact_id = "parameter:{}:{}:{}".format(direction, pathid, document_id or normalize_parameter_name(canonical_name))
    return parameter_occurrence_from_values(
        fact_id=fact_id,
        project_id=str(getattr(endpoint, "project_id", "") or ""),
        env_id=str(getattr(endpoint, "env_id", "") or ""),
        endpoint_ref="endpoint:{}".format(pathid),
        pathid=pathid,
        direction=direction,
        canonical_name=canonical_name,
        parameter_type=str(getattr(value, "type", "") or "unknown"),
        required=bool(getattr(value, "required", False)),
        locator=locator,
        values=tuple(getattr(value, "value", ()) or ()),
        source_kind=source_kind,
        principal_id=principal_id,
        profile_revision_id=profile_revision_id,
        scope_key=scope_key,
    )
def _no_args(args: Mapping[str, Any]) -> None:
    if args:
        raise RuleProtocolError("predicate does not accept arguments")


def _intersection_args(args: Mapping[str, Any]) -> None:
    if set(args) != {"value"} or type(args.get("value")) is not int or not 1 <= args["value"] <= 100:
        raise RuleProtocolError("intersection threshold must be an integer between 1 and 100")


def _legacy_score_args(args: Mapping[str, Any]) -> None:
    if set(args) - {"name_fallback"} or type(args.get("name_fallback", False)) is not bool:
        raise RuleProtocolError("legacy score name_fallback must be boolean")


def _emit_no_args(args: Mapping[str, Any]) -> None:
    if args:
        raise RuleProtocolError("output adapter does not accept arguments")


def _relation_emit_args(args: Mapping[str, Any]) -> None:
    if set(args) != {"relation"} or args.get("relation") not in {
        "weak_candidate", "insufficient_evidence", "alias_candidate",
    }:
        raise RuleProtocolError("relation output is unsupported")


_PAIR_TYPES = {
    "response_parameter": ParameterOccurrenceFact,
    "request_parameter": ParameterOccurrenceFact,
}


def _pair(context: Mapping[str, Any]) -> Tuple[ParameterOccurrenceFact, ParameterOccurrenceFact]:
    return context["response_parameter"], context["request_parameter"]


def _canonical_equal(context: Mapping[str, Any], _: Mapping[str, Any]) -> PredicateResult:
    response, request = _pair(context)
    matched = response.canonical_name == request.canonical_name
    return PredicateResult(matched, 1.0 if matched else 0.0,
                           ("PARAMETER_CANONICAL_NAME_EQUAL" if matched else "PARAMETER_CANONICAL_NAME_DIFFERENT",))


def _canonical_different(context: Mapping[str, Any], _: Mapping[str, Any]) -> PredicateResult:
    response, request = _pair(context)
    matched = response.canonical_name != request.canonical_name
    return PredicateResult(matched, 1.0 if matched else 0.0,
                           ("PARAMETER_CANONICAL_NAME_DIFFERENT" if matched else "PARAMETER_CANONICAL_NAME_EQUAL",))


def _endpoint_different(context: Mapping[str, Any], _: Mapping[str, Any]) -> PredicateResult:
    response, request = _pair(context)
    matched = response.endpoint_ref != request.endpoint_ref
    return PredicateResult(matched, 1.0 if matched else 0.0,
                           ("ENDPOINT_DIFFERENT" if matched else "ENDPOINT_SAME",))


def _intersection(context: Mapping[str, Any]) -> set:
    response, request = _pair(context)
    return set(response.observation.value_digests).intersection(request.observation.value_digests)


def _intersection_gte(context: Mapping[str, Any], args: Mapping[str, Any]) -> PredicateResult:
    count = len(_intersection(context))
    matched = count >= int(args["value"])
    return PredicateResult(matched, min(1.0, count / float(max(1, int(args["value"])))),
                           ("VALUE_INTERSECTION_PRESENT" if matched else "VALUE_INTERSECTION_BELOW_MINIMUM",))


def _intersection_empty(context: Mapping[str, Any], _: Mapping[str, Any]) -> PredicateResult:
    response, request = _pair(context)
    has_observations = bool(response.observation.value_digests and request.observation.value_digests)
    matched = has_observations and not _intersection(context)
    reason = "VALUE_INTERSECTION_EMPTY" if matched else (
        "VALUE_OBSERVATIONS_MISSING" if not has_observations else "VALUE_INTERSECTION_PRESENT"
    )
    return PredicateResult(matched, 1.0 if matched else 0.0, (reason,))


def _resource_relation_allowed(context: Mapping[str, Any], _: Mapping[str, Any]) -> PredicateResult:
    response, request = _pair(context)
    blocked = {"auth_session", "dynamic", "pagination_filter", "generic_enum"}
    matched = response.category not in blocked and request.category not in blocked
    return PredicateResult(matched, 1.0 if matched else 0.0,
                           ("PARAMETER_RESOURCE_RELATION_ALLOWED" if matched else "PARAMETER_CONTEXT_ONLY",))


def _type_compatible(context: Mapping[str, Any], _: Mapping[str, Any]) -> PredicateResult:
    response, request = _pair(context)
    numeric = {"integer", "int", "number", "float", "double"}
    left, right = response.parameter_type, request.parameter_type
    matched = left == right or left in {"", "unknown"} or right in {"", "unknown"} or {left, right}.issubset(numeric)
    return PredicateResult(matched, 1.0 if matched else 0.0,
                           ("PARAMETER_TYPE_COMPATIBLE" if matched else "PARAMETER_TYPE_INCOMPATIBLE",))


def _locator_interpretable(context: Mapping[str, Any], _: Mapping[str, Any]) -> PredicateResult:
    response, request = _pair(context)
    valid_positions = {"path", "query", "header", "cookie", "body"}
    matched = all(
        item.locator.version >= 2 and item.locator.position in valid_positions and item.locator.canonical_name
        for item in (response, request)
    )
    return PredicateResult(matched, 1.0 if matched else 0.0,
                           ("PARAMETER_LOCATOR_INTERPRETABLE" if matched else "PARAMETER_LOCATOR_UNRESOLVED",))


def _legacy_weak_score(context: Mapping[str, Any], args: Mapping[str, Any]) -> PredicateResult:
    response, request = _pair(context)
    score, reasons = score_weak_relation(
        request.canonical_name,
        len(_intersection(context)),
        request.observation.unique_value_count,
        response.observation.unique_value_count,
        used_name_fallback=bool(args.get("name_fallback", False)),
    )
    return PredicateResult(True, float(score) / 100.0, tuple(str(item) for item in reasons))


def builtin_predicate_registry() -> PredicateRegistry:
    registry = PredicateRegistry()
    definitions = (
        PredicateDefinition("parameter.canonical_name_equal.v1", _PAIR_TYPES, _no_args, _canonical_equal),
        PredicateDefinition("parameter.canonical_name_different.v1", _PAIR_TYPES, _no_args, _canonical_different),
        PredicateDefinition("endpoint.different.v1", _PAIR_TYPES, _no_args, _endpoint_different),
        PredicateDefinition("value.intersection_count_gte.v1", _PAIR_TYPES, _intersection_args, _intersection_gte),
        PredicateDefinition("value.intersection_empty.v1", _PAIR_TYPES, _no_args, _intersection_empty),
        PredicateDefinition("parameter.resource_relation_allowed.v1", _PAIR_TYPES, _no_args, _resource_relation_allowed),
        PredicateDefinition("type.compatible.v1", _PAIR_TYPES, _no_args, _type_compatible),
        PredicateDefinition("locator.interpretable.v1", _PAIR_TYPES, _no_args, _locator_interpretable),
        PredicateDefinition("legacy.weak_relation_score.v1", _PAIR_TYPES, _legacy_score_args, _legacy_weak_score),
    )
    for definition in definitions:
        registry.register(definition)
    return registry


def _emit_endpoint(context: Mapping[str, Any], _: RuleSpec, __: float, ___: Tuple[str, ...],
                   ____: Tuple[ScoreContribution, ...]) -> EndpointClassificationCandidate:
    endpoint = context["endpoint"]
    detail = classify_endpoint_detail(endpoint)
    try:
        proposed = LEGACY_ACTION_MAP[detail.action]
    except KeyError as exc:
        raise RuleProtocolError("legacy classifier returned an unregistered action") from exc
    apply_allowed = endpoint.classification_source == "machine" or (
        endpoint.classification_source == "none" and not endpoint.action
    )
    reason_codes = list(detail.reason_codes)
    if not apply_allowed:
        reason_codes.append("EXISTING_CLASSIFICATION_PRESERVED")
    winning_contributions = tuple(
        (action, reason, float(points) / 100.0)
        for action, reason, points in detail.contributions if action == detail.action
    )
    return EndpointClassificationCandidate(
        endpoint_ref=endpoint.fact_id,
        proposed_action=proposed,
        legacy_action=detail.action,
        confidence=float(detail.confidence) / 100.0,
        reason_codes=tuple(reason_codes),
        score_contributions=winning_contributions,
        existing_action=endpoint.action,
        apply_allowed=apply_allowed,
    )


def _emit_relation(context: Mapping[str, Any], rule: RuleSpec, score: float,
                   reasons: Tuple[str, ...], _: Tuple[ScoreContribution, ...]) -> ParameterRelationCandidate:
    response, request = _pair(context)
    relation = str(rule.emit.args["relation"])
    relation_reason = {
        "weak_candidate": "WEAK_RELATION_CANDIDATE",
        "insufficient_evidence": "INSUFFICIENT_EVIDENCE",
        "alias_candidate": "PARAMETER_ALIAS_CANDIDATE",
    }[relation]
    confidence = 0.0 if relation == "insufficient_evidence" else score
    return ParameterRelationCandidate(
        producer_ref=response.fact_id,
        consumer_ref=request.fact_id,
        relation=relation,
        confidence=confidence,
        reason_codes=tuple(dict.fromkeys(reasons + (relation_reason,))),
    )


def builtin_output_registry() -> OutputAdapterRegistry:
    registry = OutputAdapterRegistry()
    registry.register(OutputAdapterDefinition(
        "endpoint_classification.v1", {"endpoint": EndpointFact}, _emit_no_args, _emit_endpoint,
    ))
    registry.register(OutputAdapterDefinition(
        "parameter_relation_candidate.v1", _PAIR_TYPES, _relation_emit_args, _emit_relation,
    ))
    return registry


def builtin_engine() -> OfflineRuleEngine:
    return OfflineRuleEngine(builtin_predicate_registry(), builtin_output_registry())


def load_builtin_rule_specs() -> Tuple[RuleSpec, ...]:
    specs = []
    for path in sorted(RULE_SPEC_DIR.glob("*.json"), key=lambda item: item.name):
        specs.append(RuleSpec.from_json(path.read_text(encoding="utf-8")))
    if not specs:
        raise RuleProtocolError("no built-in RuleSpec files were found")
    identities = {(item.rule_id, item.version) for item in specs}
    if len(identities) != len(specs):
        raise RuleProtocolError("duplicate built-in RuleSpec identity")
    return tuple(specs)


def run_builtin_p0(endpoints: Iterable[EndpointFact],
                   parameters: Iterable[ParameterOccurrenceFact]) -> Tuple[EvaluationReport, ...]:
    endpoint_values = tuple(endpoints or ())
    parameter_values = tuple(parameters or ())
    responses = tuple(item for item in parameter_values if item.direction == "response")
    requests = tuple(item for item in parameter_values if item.direction == "request")
    engine = builtin_engine()
    reports = []
    for rule in load_builtin_rule_specs():
        if rule.inputs == ("endpoint",):
            inputs = {"endpoint": endpoint_values}
        elif rule.inputs == ("response_parameter", "request_parameter"):
            inputs = {"response_parameter": responses, "request_parameter": requests}
        else:
            raise RuleProtocolError("built-in rule declares unsupported P0 inputs")
        reports.append(engine.evaluate(rule, inputs))
    return tuple(reports)


def legacy_relation_outcome(response: ParameterOccurrenceFact,
                            request: ParameterOccurrenceFact,
                            min_score: float = 0.60) -> Dict[str, Any]:
    """Pure comparator for the relevant branches of infer_weak_relations."""
    if response.canonical_name != request.canonical_name:
        return {"relation": "none", "score": 0.0, "reason_codes": []}
    overlap_count = len(set(response.observation.value_digests).intersection(request.observation.value_digests))
    if response.endpoint_ref != request.endpoint_ref and overlap_count:
        score, reasons = score_weak_relation(
            request.canonical_name,
            overlap_count,
            request.observation.unique_value_count,
            response.observation.unique_value_count,
        )
        normalized_score = score / 100.0
        return {
            "relation": "weak" if normalized_score >= float(min_score) else "none",
            "score": normalized_score,
            "reason_codes": list(reasons),
        }
    if response.endpoint_ref == request.endpoint_ref and not overlap_count:
        return {"relation": "not_equal", "score": 0.30, "reason_codes": ["NO_INTERSECTION_SAME_PATH"]}
    return {"relation": "none", "score": 0.0, "reason_codes": []}
