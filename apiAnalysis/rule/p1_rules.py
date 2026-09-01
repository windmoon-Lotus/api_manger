"""Pure P1 rule adapters for roles, resource chains, principals and CRUD pairs.

This module has no database or network imports.  Domain projection and safe
persistence live in ``apiAnalysis.tool.unified_rule_analysis``.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Sequence, Tuple

from apiAnalysis.rule.builtin_rules import (
    PARAMETER_CATEGORIES,
    builtin_output_registry,
    builtin_predicate_registry,
)
from apiAnalysis.rule.framework import (
    EndpointFact,
    Fact,
    OfflineRuleEngine,
    OutputAdapterDefinition,
    ParameterOccurrenceFact,
    PredicateDefinition,
    PredicateResult,
    RuleProtocolError,
    RuleSpec,
    ScoreContribution,
)


P1_RULE_SPEC_DIR = Path(__file__).resolve().parent / "specs_p1"
CRUD_OPERATIONS = {"list", "detail", "create", "update", "delete"}
MUTATION_OPERATIONS = {"create", "update", "delete"}


@dataclass(frozen=True)
class EndpointPairFact(Fact):
    left_ref: str
    right_ref: str
    left_pathid: int
    right_pathid: int
    left_operation: str
    right_operation: str
    resource_family: str
    compatibility: float


@dataclass(frozen=True)
class ResourceChainFact(Fact):
    parent_ref: str
    child_ref: str
    parent_pathid: int
    child_pathid: int
    parent_family: str
    child_family: str
    chain_kind: str
    confidence: float


@dataclass(frozen=True)
class PrincipalPairFact(Fact):
    source_principal_id: str
    target_principal_id: str
    source_profile_revision_id: str
    target_profile_revision_id: str
    source_scope_key: str
    target_scope_key: str
    source_privilege_rank: int
    target_privilege_rank: int
    relation_kind: str


@dataclass(frozen=True)
class ParameterRoleCandidate:
    occurrence_ref: str
    endpoint_ref: str
    pathid: int
    canonical_name: str
    position: str
    role: str
    confidence: float
    relation_eligible: bool
    reason_codes: Tuple[str, ...]
    verified: bool = False
    write_disposition: str = "machine_fields_only"
    dry_run: bool = True


@dataclass(frozen=True)
class CrudPairCandidate:
    left_ref: str
    right_ref: str
    left_pathid: int
    right_pathid: int
    left_operation: str
    right_operation: str
    resource_family: str
    confidence: float
    reason_codes: Tuple[str, ...]
    verified: bool = False
    dry_run: bool = True


@dataclass(frozen=True)
class ResourceChainCandidate:
    parent_ref: str
    child_ref: str
    parent_pathid: int
    child_pathid: int
    parent_family: str
    child_family: str
    chain_kind: str
    confidence: float
    reason_codes: Tuple[str, ...]
    verified: bool = False
    dry_run: bool = True


@dataclass(frozen=True)
class PrincipalScopeCandidate:
    source_principal_id: str
    target_principal_id: str
    source_profile_revision_id: str
    target_profile_revision_id: str
    source_scope_key: str
    target_scope_key: str
    relation_kind: str
    confidence: float
    reason_codes: Tuple[str, ...]
    verified: bool = False
    dry_run: bool = True


def _no_args(args: Mapping[str, Any]) -> None:
    if args:
        raise RuleProtocolError("predicate or output does not accept arguments")


def _parameter_supported(context: Mapping[str, Fact], _: Mapping[str, Any]) -> PredicateResult:
    value = context["parameter"]
    matched = value.category in PARAMETER_CATEGORIES
    return PredicateResult(
        matched, 1.0 if matched else 0.0,
        ("PARAMETER_CATEGORY_CLASSIFIED" if matched else "PARAMETER_CATEGORY_UNSUPPORTED",),
    )


def _parameter_confidence(context: Mapping[str, Fact], _: Mapping[str, Any]) -> PredicateResult:
    value = context["parameter"]
    confidence = {
        "auth_session": 0.98, "dynamic": 0.95, "pagination_filter": 0.95,
        "resource": 0.85, "generic_enum": 0.78, "unknown": 0.35,
    }[value.category]
    return PredicateResult(True, confidence, ("PARAMETER_ROLE_{}".format(value.category.upper()),))


def _crud_compatible(context: Mapping[str, Fact], _: Mapping[str, Any]) -> PredicateResult:
    value = context["endpoint_pair"]
    matched = (
        value.left_ref != value.right_ref
        and value.resource_family
        and value.left_operation in CRUD_OPERATIONS
        and value.right_operation in CRUD_OPERATIONS
        and value.left_operation != value.right_operation
        and bool({value.left_operation, value.right_operation} & MUTATION_OPERATIONS)
    )
    return PredicateResult(
        matched, value.compatibility if matched else 0.0,
        ("CRUD_RESOURCE_FAMILY_COMPATIBLE" if matched else "CRUD_PAIR_INCOMPATIBLE",),
    )


def _pair_confidence(context: Mapping[str, Fact], _: Mapping[str, Any]) -> PredicateResult:
    value = context["endpoint_pair"]
    return PredicateResult(True, max(0.0, min(1.0, value.compatibility)), ("CRUD_PAIR_SCORE",))


def _resource_chain_eligible(context: Mapping[str, Fact], _: Mapping[str, Any]) -> PredicateResult:
    value = context["resource_chain"]
    matched = (
        value.parent_ref != value.child_ref
        and value.chain_kind in {"endpoint_parent_child", "response_to_request"}
        and bool(value.parent_family and value.child_family)
    )
    return PredicateResult(
        matched, value.confidence if matched else 0.0,
        ("RESOURCE_PARENT_CHILD_STRUCTURE" if matched else "RESOURCE_CHAIN_INELIGIBLE",),
    )


def _resource_confidence(context: Mapping[str, Fact], _: Mapping[str, Any]) -> PredicateResult:
    value = context["resource_chain"]
    return PredicateResult(True, max(0.0, min(1.0, value.confidence)), ("RESOURCE_CHAIN_SCORE",))


def _principal_relation_known(context: Mapping[str, Fact], _: Mapping[str, Any]) -> PredicateResult:
    value = context["principal_pair"]
    matched = value.relation_kind in {
        "same_principal", "same_profile", "same_scope", "different_scope",
        "higher_privilege", "lower_privilege", "peer",
    }
    return PredicateResult(
        matched, 1.0 if matched else 0.0,
        ("PRINCIPAL_RELATION_{}".format(value.relation_kind.upper()) if matched
         else "PRINCIPAL_RELATION_UNKNOWN",),
    )


def _principal_confidence(context: Mapping[str, Fact], _: Mapping[str, Any]) -> PredicateResult:
    value = context["principal_pair"]
    confidence = 1.0 if value.relation_kind == "same_principal" else 0.95
    return PredicateResult(True, confidence, ("PRINCIPAL_PROFILE_SCOPE_EXPLICIT",))


def _emit_parameter_role(context: Mapping[str, Fact], _: RuleSpec, score: float,
                         reasons: Tuple[str, ...], __: Tuple[ScoreContribution, ...]
                         ) -> ParameterRoleCandidate:
    value = context["parameter"]
    blocked = {"auth_session", "dynamic", "pagination_filter", "generic_enum"}
    codes = list(reasons)
    codes.append(
        "PARAMETER_RELATION_FILTERED_CONTEXT_ONLY"
        if value.category in blocked else "PARAMETER_RELATION_ELIGIBLE"
    )
    return ParameterRoleCandidate(
        occurrence_ref=value.fact_id,
        endpoint_ref=value.endpoint_ref,
        pathid=value.pathid,
        canonical_name=value.canonical_name,
        position=value.locator.position,
        role=value.category,
        confidence=score,
        relation_eligible=value.category not in blocked,
        reason_codes=tuple(dict.fromkeys(codes)),
    )


def _emit_crud(context: Mapping[str, Fact], _: RuleSpec, score: float,
               reasons: Tuple[str, ...], __: Tuple[ScoreContribution, ...]) -> CrudPairCandidate:
    value = context["endpoint_pair"]
    return CrudPairCandidate(
        left_ref=value.left_ref, right_ref=value.right_ref,
        left_pathid=value.left_pathid, right_pathid=value.right_pathid,
        left_operation=value.left_operation, right_operation=value.right_operation,
        resource_family=value.resource_family, confidence=score,
        reason_codes=tuple(dict.fromkeys(reasons + ("CRUD_PAIR_CANDIDATE",))),
    )


def _emit_resource(context: Mapping[str, Fact], _: RuleSpec, score: float,
                   reasons: Tuple[str, ...], __: Tuple[ScoreContribution, ...]
                   ) -> ResourceChainCandidate:
    value = context["resource_chain"]
    return ResourceChainCandidate(
        parent_ref=value.parent_ref, child_ref=value.child_ref,
        parent_pathid=value.parent_pathid, child_pathid=value.child_pathid,
        parent_family=value.parent_family, child_family=value.child_family,
        chain_kind=value.chain_kind, confidence=score,
        reason_codes=tuple(dict.fromkeys(reasons + ("RESOURCE_CHAIN_CANDIDATE",))),
    )


def _emit_principal(context: Mapping[str, Fact], _: RuleSpec, score: float,
                    reasons: Tuple[str, ...], __: Tuple[ScoreContribution, ...]
                    ) -> PrincipalScopeCandidate:
    value = context["principal_pair"]
    return PrincipalScopeCandidate(
        source_principal_id=value.source_principal_id,
        target_principal_id=value.target_principal_id,
        source_profile_revision_id=value.source_profile_revision_id,
        target_profile_revision_id=value.target_profile_revision_id,
        source_scope_key=value.source_scope_key,
        target_scope_key=value.target_scope_key,
        relation_kind=value.relation_kind,
        confidence=score,
        reason_codes=tuple(dict.fromkeys(reasons + ("PRINCIPAL_SCOPE_CANDIDATE",))),
    )


def p1_engine() -> OfflineRuleEngine:
    predicates = builtin_predicate_registry()
    for definition in (
        PredicateDefinition("parameter.category_supported.v1", {"parameter": ParameterOccurrenceFact}, _no_args, _parameter_supported),
        PredicateDefinition("parameter.category_confidence.v1", {"parameter": ParameterOccurrenceFact}, _no_args, _parameter_confidence),
        PredicateDefinition("endpoint_pair.crud_compatible.v1", {"endpoint_pair": EndpointPairFact}, _no_args, _crud_compatible),
        PredicateDefinition("endpoint_pair.confidence.v1", {"endpoint_pair": EndpointPairFact}, _no_args, _pair_confidence),
        PredicateDefinition("resource_chain.eligible.v1", {"resource_chain": ResourceChainFact}, _no_args, _resource_chain_eligible),
        PredicateDefinition("resource_chain.confidence.v1", {"resource_chain": ResourceChainFact}, _no_args, _resource_confidence),
        PredicateDefinition("principal_pair.relation_known.v1", {"principal_pair": PrincipalPairFact}, _no_args, _principal_relation_known),
        PredicateDefinition("principal_pair.confidence.v1", {"principal_pair": PrincipalPairFact}, _no_args, _principal_confidence),
    ):
        predicates.register(definition)
    outputs = builtin_output_registry()
    for definition in (
        OutputAdapterDefinition("parameter_role_candidate.v1", {"parameter": ParameterOccurrenceFact}, _no_args, _emit_parameter_role),
        OutputAdapterDefinition("crud_pair_candidate.v1", {"endpoint_pair": EndpointPairFact}, _no_args, _emit_crud),
        OutputAdapterDefinition("resource_chain_candidate.v1", {"resource_chain": ResourceChainFact}, _no_args, _emit_resource),
        OutputAdapterDefinition("principal_scope_candidate.v1", {"principal_pair": PrincipalPairFact}, _no_args, _emit_principal),
    ):
        outputs.register(definition)
    return OfflineRuleEngine(predicates, outputs)


def load_p1_rule_specs() -> Tuple[RuleSpec, ...]:
    specs = tuple(
        RuleSpec.from_json(path.read_text(encoding="utf-8"))
        for path in sorted(P1_RULE_SPEC_DIR.glob("*.json"), key=lambda item: item.name)
    )
    if not specs:
        raise RuleProtocolError("no P1 RuleSpec files were found")
    if len({(item.rule_id, item.version) for item in specs}) != len(specs):
        raise RuleProtocolError("duplicate P1 RuleSpec identity")
    return specs


def run_p1_rules(parameters: Iterable[ParameterOccurrenceFact] = (),
                 endpoint_pairs: Iterable[EndpointPairFact] = (),
                 resource_chains: Iterable[ResourceChainFact] = (),
                 principal_pairs: Iterable[PrincipalPairFact] = ()) -> Tuple[Any, ...]:
    inputs = {
        ("parameter",): {"parameter": tuple(parameters)},
        ("endpoint_pair",): {"endpoint_pair": tuple(endpoint_pairs)},
        ("resource_chain",): {"resource_chain": tuple(resource_chains)},
        ("principal_pair",): {"principal_pair": tuple(principal_pairs)},
    }
    engine = p1_engine()
    return tuple(engine.evaluate(rule, inputs[rule.inputs]) for rule in load_p1_rule_specs())


def _operation(endpoint: EndpointFact) -> str:
    action = str(endpoint.action or "").lower()
    for name, aliases in {
        "list": ("endpoint.query", "q_path", "list"),
        "detail": ("detail", "read"),
        "create": ("endpoint.create", "c_path", "create"),
        "update": ("endpoint.modify", "m_path", "update", "modify"),
        "delete": ("endpoint.delete", "d_path", "delete"),
    }.items():
        if any(alias in action for alias in aliases):
            return name
    return {
        "GET": "detail" if (_segments(endpoint.path_template) or ("",))[-1] == "{}" else "list",
        "POST": "create", "PUT": "update", "PATCH": "update", "DELETE": "delete",
    }.get(str(endpoint.method or "").upper(), "unknown")


def _segments(path: str) -> Tuple[str, ...]:
    result = []
    for segment in str(path or "").split("?")[0].strip("/").split("/"):
        if not segment:
            continue
        if re.fullmatch(r"\{[^{}]+\}|:[A-Za-z_][A-Za-z0-9_-]*", segment):
            result.append("{}")
        else:
            result.append(segment.lower())
    return tuple(result)


def _family(endpoint: EndpointFact) -> str:
    segments = list(_segments(endpoint.path_template))
    if segments and segments[-1] == "{}":
        segments.pop()
    if segments and segments[-1] in {"create", "update", "delete", "detail", "list", "search"}:
        segments.pop()
    return "/" + "/".join(segments)


def endpoint_resource_family(endpoint: EndpointFact) -> str:
    return _family(endpoint)


def build_endpoint_pair_facts(endpoints: Sequence[EndpointFact], *, max_facts: int = 50000
                              ) -> Tuple[EndpointPairFact, ...]:
    grouped: Dict[Tuple[str, str, str], List[EndpointFact]] = {}
    for endpoint in endpoints:
        key = (endpoint.project_id, endpoint.env_id, _family(endpoint))
        if key[2] in {"", "/"}:
            continue
        grouped.setdefault(key, []).append(endpoint)
    result = []
    for (project_id, env_id, family), items in sorted(grouped.items()):
        ordered = sorted(items, key=lambda item: item.fact_id)
        for index, left in enumerate(ordered):
            for right in ordered[index + 1:]:
                left_operation, right_operation = _operation(left), _operation(right)
                if left_operation == right_operation or "unknown" in {left_operation, right_operation}:
                    continue
                if not ({left_operation, right_operation} & MUTATION_OPERATIONS):
                    continue
                confidence = 0.90 if _segments(left.path_template) == _segments(right.path_template) else 0.78
                identity = hashlib.sha256("{}|{}".format(left.fact_id, right.fact_id).encode()).hexdigest()
                result.append(EndpointPairFact(
                    fact_id="endpoint-pair:{}".format(identity), project_id=project_id,
                    env_id=env_id, left_ref=left.fact_id, right_ref=right.fact_id,
                    left_pathid=left.pathid, right_pathid=right.pathid,
                    left_operation=left_operation, right_operation=right_operation,
                    resource_family=family, compatibility=confidence,
                ))
                if len(result) > max_facts:
                    raise RuleProtocolError("endpoint pair fact budget exceeded")
    return tuple(result)


def build_resource_chain_facts(endpoints: Sequence[EndpointFact], *, max_facts: int = 50000
                               ) -> Tuple[ResourceChainFact, ...]:
    result = []
    ordered = sorted(endpoints, key=lambda item: (len(_segments(item.path_template)), item.fact_id))
    for parent in ordered:
        parent_segments = _segments(parent.path_template)
        for child in ordered:
            child_segments = _segments(child.path_template)
            if parent.fact_id == child.fact_id or len(child_segments) <= len(parent_segments):
                continue
            if child_segments[:len(parent_segments)] != parent_segments:
                continue
            if len(child_segments) - len(parent_segments) > 2:
                continue
            identity = hashlib.sha256("{}|{}".format(parent.fact_id, child.fact_id).encode()).hexdigest()
            result.append(ResourceChainFact(
                fact_id="resource-chain:{}".format(identity),
                project_id=parent.project_id, env_id=parent.env_id,
                parent_ref=parent.fact_id, child_ref=child.fact_id,
                parent_pathid=parent.pathid, child_pathid=child.pathid,
                parent_family=_family(parent), child_family=_family(child),
                chain_kind="endpoint_parent_child", confidence=0.82,
            ))
            if len(result) > max_facts:
                raise RuleProtocolError("resource chain fact budget exceeded")
    return tuple(result)


def principal_pair_relations(source: Mapping[str, Any], target: Mapping[str, Any]) -> Tuple[str, ...]:
    if source["principal_id"] == target["principal_id"]:
        return ("same_principal",)
    relations = []
    if source.get("profile_revision_id") and source.get("profile_revision_id") == target.get("profile_revision_id"):
        relations.append("same_profile")
    if source.get("scope_key") and source.get("scope_key") == target.get("scope_key"):
        relations.append("same_scope")
    elif source.get("scope_key") != target.get("scope_key"):
        relations.append("different_scope")
    if int(source.get("privilege_rank") or 0) > int(target.get("privilege_rank") or 0):
        relations.append("higher_privilege")
    elif int(source.get("privilege_rank") or 0) < int(target.get("privilege_rank") or 0):
        relations.append("lower_privilege")
    else:
        relations.append("peer")
    return tuple(dict.fromkeys(relations))


def principal_pair_relation(source: Mapping[str, Any], target: Mapping[str, Any]) -> str:
    return principal_pair_relations(source, target)[0]


def build_principal_pair_facts(principals: Sequence[Mapping[str, Any]], *, max_facts: int = 10000
                               ) -> Tuple[PrincipalPairFact, ...]:
    result = []
    for source in sorted(principals, key=lambda item: item["principal_id"]):
        for target in sorted(principals, key=lambda item: item["principal_id"]):
            if source.get("project_id") != target.get("project_id") or source.get("env_id") != target.get("env_id"):
                continue
            for relation in principal_pair_relations(source, target):
                identity = hashlib.sha256(
                    "{}|{}|{}".format(
                        source["principal_id"], target["principal_id"], relation,
                    ).encode()
                ).hexdigest()
                result.append(PrincipalPairFact(
                    fact_id="principal-pair:{}".format(identity),
                    project_id=str(source.get("project_id") or ""),
                    env_id=str(source.get("env_id") or ""),
                    source_principal_id=str(source["principal_id"]),
                    target_principal_id=str(target["principal_id"]),
                    source_profile_revision_id=str(source.get("profile_revision_id") or ""),
                    target_profile_revision_id=str(target.get("profile_revision_id") or ""),
                    source_scope_key=str(source.get("scope_key") or ""),
                    target_scope_key=str(target.get("scope_key") or ""),
                    source_privilege_rank=int(source.get("privilege_rank") or 0),
                    target_privilege_rank=int(target.get("privilege_rank") or 0),
                    relation_kind=relation,
                ))
                if len(result) > max_facts:
                    raise RuleProtocolError("principal pair fact budget exceeded")
    return tuple(result)


def p1_rule_bundle_sha256() -> str:
    payload = [(item.rule_id, item.version, item.canonical_sha256()) for item in load_p1_rule_specs()]
    return hashlib.sha256(json.dumps(payload, separators=(",", ":")).encode()).hexdigest()
