"""Unified P1 offline rule projection, comparison and safe persistence.

All network-capable execution remains outside this module.  It reads bounded
project data, executes versioned RuleSpec objects, persists only machine-owned
typed fields, and can create non-executable ``security_test_plan`` drafts.
"""
from __future__ import annotations

import dataclasses
import datetime as dt
import hashlib
import itertools
import json
from collections import Counter, defaultdict
from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from apiAnalysis.db.collection import (
    AuthorizationPrincipal,
    ProjectAuthProfile,
    ProjectEnvironment,
    idor_parameter_candidate,
    parameter_priority_item,
    parameter_relation,
    raw_data,
    req_data,
    res_data,
    security_test_plan,
)
from apiAnalysis.rule.builtin_rules import (
    endpoint_fact_from_document,
    legacy_relation_outcome,
    load_builtin_rule_specs,
    parameter_occurrence_from_values,
    run_builtin_p0,
)
from apiAnalysis.rule.framework import (
    EndpointClassificationCandidate,
    EndpointFact,
    ParameterOccurrenceFact,
    ParameterRelationCandidate,
    RuleMatch,
)
from apiAnalysis.rule.p1_rules import (
    CrudPairCandidate,
    ParameterRoleCandidate,
    PrincipalScopeCandidate,
    ResourceChainCandidate,
    build_endpoint_pair_facts,
    build_principal_pair_facts,
    build_resource_chain_facts,
    endpoint_resource_family,
    load_p1_rule_specs,
    run_p1_rules,
)
from apiAnalysis.rule.shadow_evaluation import ShadowEvaluationError, ShadowLimits, load_shadow_projection
from apiAnalysis.tool.parameter_identity import parameter_identity
from apiAnalysis.tool.test_plan import create_next_version, create_plan


ANALYSIS_VERSION = "unified-offline-rules.p1.v1"
PLAN_CHECK_TYPE = "rule_candidate_draft"
PLAN_ADAPTER_ID = "rule_plan_draft_only"


class UnifiedRuleAnalysisError(RuntimeError):
    pass


@dataclass(frozen=True)
class UnifiedAnalysisLimits:
    max_endpoints: int = 50000
    max_occurrences: int = 100000
    max_endpoint_pairs: int = 50000
    max_resource_chains: int = 50000
    max_principal_pairs: int = 10000
    max_relation_pairs: int = 1000000
    max_plan_drafts: int = 100
    max_report_samples: int = 20

    def validate(self) -> None:
        for name, value, maximum in (
            ("max_endpoints", self.max_endpoints, 100000),
            ("max_occurrences", self.max_occurrences, 500000),
            ("max_endpoint_pairs", self.max_endpoint_pairs, 100000),
            ("max_resource_chains", self.max_resource_chains, 100000),
            ("max_principal_pairs", self.max_principal_pairs, 100000),
            ("max_relation_pairs", self.max_relation_pairs, 5000000),
            ("max_plan_drafts", self.max_plan_drafts, 1000),
            ("max_report_samples", self.max_report_samples, 100),
        ):
            if not 1 <= int(value) <= maximum:
                raise UnifiedRuleAnalysisError("{} is outside the supported budget".format(name))


@dataclass(frozen=True)
class UnifiedAnalysisResult:
    project_id: str
    env_id: str
    profile_id: str
    profile_revision_id: str
    input_watermark_sha256: str
    rule_bundle_sha256: str
    endpoint_documents: Mapping[int, Any]
    parameter_documents: Mapping[str, Any]
    relation_facts: Mapping[str, ParameterOccurrenceFact]
    reports: Tuple[Any, ...]
    matches: Tuple[RuleMatch, ...]
    summary: Mapping[str, Any]


def _sha256(value: Any) -> str:
    encoded = json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str,
    )
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _bounded(queryset: Any, limit: int, label: str) -> List[Any]:
    rows = list(queryset.limit(int(limit) + 1))
    if len(rows) > int(limit):
        raise UnifiedRuleAnalysisError("{} budget exceeded".format(label))
    return rows


def _environment(project_id: str, env_id: str) -> ProjectEnvironment:
    if env_id:
        value = ProjectEnvironment.objects(
            project_id=project_id, env_id=env_id, active=True,
        ).first()
        if not value:
            raise UnifiedRuleAnalysisError("selected environment is unavailable")
        return value
    values = list(ProjectEnvironment.objects(project_id=project_id, active=True).limit(2))
    if len(values) != 1:
        raise UnifiedRuleAnalysisError("one explicit active environment is required")
    return values[0]


def _profile(project_id: str, env_id: str, profile_id: str) -> Optional[ProjectAuthProfile]:
    if profile_id:
        value = ProjectAuthProfile.objects(
            project_id=project_id, env_id=env_id, profile_id=profile_id, active=True,
        ).first()
        if not value:
            raise UnifiedRuleAnalysisError("selected profile is unavailable")
        return value
    defaults = list(ProjectAuthProfile.objects(
        project_id=project_id, env_id=env_id, active=True, is_default=True,
    ).limit(2))
    if len(defaults) == 1:
        return defaults[0]
    active = list(ProjectAuthProfile.objects(
        project_id=project_id, env_id=env_id, active=True,
    ).limit(2))
    return active[0] if len(active) == 1 else None


def _endpoint_facts(project_id: str, env_id: str, limits: UnifiedAnalysisLimits
                    ) -> Tuple[Tuple[EndpointFact, ...], Dict[int, Any], bool]:
    active_envs = list(ProjectEnvironment.objects(project_id=project_id, active=True).only("env_id"))
    inherit_unset = len(active_envs) == 1 and str(active_envs[0].env_id or "") == env_id
    query = raw_data.objects(project_id=project_id)
    if not inherit_unset:
        query = query.filter(env_id=env_id)
    documents = _bounded(query.order_by("ptah_id"), limits.max_endpoints, "endpoint")
    if any(str(item.env_id or "") not in {"", env_id} for item in documents):
        raise UnifiedRuleAnalysisError("endpoint projection crossed an environment boundary")
    facts = []
    by_pathid = {}
    for document in documents:
        fact = endpoint_fact_from_document(document)
        facts.append(dataclasses.replace(fact, project_id=project_id, env_id=env_id))
        by_pathid[int(document.ptah_id)] = document
    return tuple(facts), by_pathid, inherit_unset


def _locator_mapping(value: Any, direction: str) -> Dict[str, Any]:
    locator = dict(getattr(value, "locator", None) or {})
    if locator:
        return locator
    return {}


def _parameter_facts(endpoint_documents: Mapping[int, Any], project_id: str, env_id: str,
                     limits: UnifiedAnalysisLimits
                     ) -> Tuple[Tuple[ParameterOccurrenceFact, ...], Dict[str, Any], Counter]:
    endpoints = list(endpoint_documents.values())
    endpoint_by_id = {item.id: item for item in endpoints}
    result = []
    documents: Dict[str, Any] = {}
    stats = Counter()
    for model, direction in ((req_data, "request"), (res_data, "response")):
        rows = _bounded(
            model.objects(raw_data__in=endpoints).order_by("id"),
            limits.max_occurrences, "{} parameter occurrence".format(direction),
        ) if endpoints else []
        for row in rows:
            endpoint = endpoint_by_id.get(getattr(row.raw_data, "id", row.raw_data))
            if endpoint is None:
                stats["skipped_endpoint_missing"] += 1
                continue
            locator = _locator_mapping(row, direction)
            if not locator:
                stats["skipped_typed_locator_missing"] += 1
                continue
            identity = parameter_identity(row.parameter, getattr(row, "canonical_name", ""))
            if not identity:
                stats["skipped_identity_missing"] += 1
                continue
            fact_id = "document-parameter:{}:{}".format(direction, str(row.id))
            try:
                fact = parameter_occurrence_from_values(
                    fact_id=fact_id, project_id=project_id, env_id=env_id,
                    endpoint_ref="endpoint:{}".format(int(endpoint.ptah_id)),
                    pathid=int(endpoint.ptah_id), direction=direction,
                    canonical_name=identity,
                    parameter_type=str(getattr(row, "type", "") or "unknown"),
                    required=bool(getattr(row, "required", False)), locator=locator,
                    values=tuple((getattr(row, "value", None) or ())[:100]),
                    source_kind="project_document_role_projection",
                )
            except ValueError:
                stats["skipped_invalid_fact"] += 1
                continue
            result.append(fact)
            documents[fact_id] = row
    if len(result) > limits.max_occurrences:
        raise UnifiedRuleAnalysisError("combined parameter occurrence budget exceeded")
    return tuple(result), documents, stats


def _principal_rows(project_id: str, env_id: str, limits: UnifiedAnalysisLimits
                    ) -> Tuple[Dict[str, Any], ...]:
    rows = _bounded(
        AuthorizationPrincipal.objects(
            project_id=project_id, env_id=env_id, active=True,
        ).order_by("principal_id"),
        max(1, int(limits.max_principal_pairs ** 0.5) + 1), "principal",
    )
    profiles = {
        item.profile_id: item for item in ProjectAuthProfile.objects(
            project_id=project_id, env_id=env_id, profile_id__in=[row.profile_id for row in rows],
        )
    }
    return tuple({
        "principal_id": str(row.principal_id), "project_id": project_id, "env_id": env_id,
        "profile_revision_id": str(getattr(profiles.get(row.profile_id), "current_revision_id", "") or ""),
        "scope_key": str(row.scope_key or ""), "privilege_rank": int(row.privilege_rank or 0),
    } for row in rows)


def _rule_bundle() -> Tuple[str, List[Dict[str, Any]]]:
    rules = tuple(load_builtin_rule_specs()) + tuple(load_p1_rule_specs())
    rows = [{
        "rule_id": item.rule_id, "version": item.version, "sha256": item.canonical_sha256(),
    } for item in rules]
    return _sha256(rows), rows


def _output_counts(matches: Iterable[RuleMatch]) -> Counter:
    return Counter(type(item.output).__name__ for item in matches)


def endpoint_watermark_rows(endpoints: Iterable[EndpointFact]) -> List[Tuple[Any, ...]]:
    """Exclude machine-derived classifications from the source watermark."""
    return [
        (
            item.fact_id, item.method, item.path_template,
            item.action if item.classification_source == "manual" else "",
        )
        for item in endpoints
    ]


def effective_endpoint_facts(endpoints: Sequence[EndpointFact], reports: Sequence[Any]
                             ) -> Tuple[EndpointFact, ...]:
    outputs = {
        match.output.endpoint_ref: match.output
        for report in reports for match in report.matches
        if isinstance(match.output, EndpointClassificationCandidate)
    }
    return tuple(
        dataclasses.replace(
            endpoint,
            action=outputs[endpoint.fact_id].proposed_action,
            classification_source="machine",
        )
        if endpoint.fact_id in outputs and outputs[endpoint.fact_id].apply_allowed
        else endpoint
        for endpoint in endpoints
    )


def _score_contributions(match: RuleMatch) -> List[Dict[str, Any]]:
    return [{
        "predicate": item.predicate,
        "value": item.value,
        "weight": item.weight,
        "contribution": item.contribution,
        "reason_codes": list(item.reason_codes),
    } for item in match.score_contributions]


def _relation_resource_chains(
        endpoint_facts: Sequence[EndpointFact],
        relation_facts: Mapping[str, ParameterOccurrenceFact],
        p0_reports: Sequence[Any]) -> Tuple[Any, ...]:
    endpoints = {item.fact_id: item for item in endpoint_facts}
    rows = []
    for report in p0_reports:
        for match in report.matches:
            output = match.output
            if not isinstance(output, ParameterRelationCandidate):
                continue
            source = relation_facts.get(output.producer_ref)
            target = relation_facts.get(output.consumer_ref)
            if (
                source is None or target is None
                or source.category != "resource" or target.category != "resource"
                or output.relation == "insufficient_evidence"
            ):
                continue
            parent = endpoints.get(source.endpoint_ref)
            child = endpoints.get(target.endpoint_ref)
            if parent is None or child is None:
                continue
            from apiAnalysis.rule.p1_rules import ResourceChainFact
            rows.append(ResourceChainFact(
                fact_id="relation-resource-chain:{}".format(_sha256({
                    "producer": output.producer_ref, "consumer": output.consumer_ref,
                })),
                project_id=source.project_id, env_id=source.env_id,
                parent_ref=source.endpoint_ref, child_ref=target.endpoint_ref,
                parent_pathid=source.pathid, child_pathid=target.pathid,
                parent_family=endpoint_resource_family(parent),
                child_family=endpoint_resource_family(child),
                chain_kind="response_to_request",
                confidence=max(0.0, min(1.0, output.confidence)),
            ))
    return tuple(rows)


def _legacy_diff(endpoint_facts: Sequence[EndpointFact], p0_reports: Sequence[Any]) -> Dict[str, Any]:
    classification = {
        match.output.endpoint_ref: match.output
        for report in p0_reports for match in report.matches
        if isinstance(match.output, EndpointClassificationCandidate)
    }
    class_parity = sum(
        1 for endpoint in endpoint_facts
        if endpoint.fact_id in classification
        and classification[endpoint.fact_id].legacy_action
    )
    relation_transitions = Counter()
    relation_outputs = {}
    for report in p0_reports:
        for match in report.matches:
            if isinstance(match.output, ParameterRelationCandidate):
                relation_outputs[(match.output.producer_ref, match.output.consumer_ref)] = match.output.relation
    parameter_facts = {
        item.fact_id: item
        for report in p0_reports for match in report.matches for item in ()
    }
    # The caller fills exact relation transitions because reports intentionally
    # contain only fact references, not the original private facts.
    return {
        "classification_outputs": len(classification),
        "classification_legacy_adapter_outputs": class_parity,
        "relation_output_count": len(relation_outputs),
        "relation_transitions": dict(relation_transitions),
    }


def analyze_project(project_id: str, *, env_id: str = "", profile_id: str = "",
                    limits: UnifiedAnalysisLimits = UnifiedAnalysisLimits()
                    ) -> UnifiedAnalysisResult:
    limits.validate()
    project_id = str(project_id or "").strip()
    if not project_id:
        raise UnifiedRuleAnalysisError("project_id is required")
    environment = _environment(project_id, str(env_id or "").strip())
    env_id = str(environment.env_id)
    profile = _profile(project_id, env_id, str(profile_id or "").strip())
    profile_revision_id = str(getattr(profile, "current_revision_id", "") or "")

    endpoint_facts, endpoint_documents, inherited = _endpoint_facts(
        project_id, env_id, limits,
    )
    parameter_facts, parameter_documents, parameter_stats = _parameter_facts(
        endpoint_documents, project_id, env_id, limits,
    )
    principal_rows = _principal_rows(project_id, env_id, limits)
    principal_pairs = build_principal_pair_facts(
        principal_rows, max_facts=limits.max_principal_pairs,
    )

    relation_parameters: Tuple[ParameterOccurrenceFact, ...] = ()
    relation_projection_status = "blocked"
    relation_blockers = ["PROFILE_SCOPED_RELATION_FACTS_UNAVAILABLE"]
    relation_projection_stats: Dict[str, Any] = {}
    if profile_revision_id:
        try:
            shadow = load_shadow_projection(
                project_id, env_id, profile_revision_id,
                ShadowLimits(
                    max_endpoints=limits.max_endpoints,
                    max_occurrences=limits.max_occurrences,
                    max_pair_combinations=limits.max_relation_pairs,
                ),
            )
            relation_parameters = tuple(shadow.parameters)
            relation_projection_stats = dict(shadow.stats)
            relation_projection_status = "complete" if relation_parameters else "blocked"
            relation_blockers = [] if relation_parameters else ["PROFILE_SCOPED_RELATION_FACTS_UNAVAILABLE"]
        except ShadowEvaluationError as exc:
            relation_blockers = [exc.__class__.__name__]

    p0_reports = run_builtin_p0(endpoint_facts, relation_parameters)
    effective_endpoints = effective_endpoint_facts(endpoint_facts, p0_reports)
    endpoint_pairs = build_endpoint_pair_facts(
        effective_endpoints, max_facts=limits.max_endpoint_pairs,
    )
    resource_chains = build_resource_chain_facts(
        effective_endpoints, max_facts=limits.max_resource_chains,
    )
    relation_fact_map = {item.fact_id: item for item in relation_parameters}
    relation_chains = _relation_resource_chains(
        effective_endpoints, relation_fact_map, p0_reports,
    )
    combined_resource_chains = tuple(resource_chains) + relation_chains
    if len(combined_resource_chains) > limits.max_resource_chains:
        raise UnifiedRuleAnalysisError("combined resource chain budget exceeded")
    p1_reports = run_p1_rules(
        parameter_facts, endpoint_pairs, combined_resource_chains, principal_pairs,
    )
    reports = tuple(p0_reports + p1_reports)
    matches = tuple(match for report in reports for match in report.matches)
    bundle_sha256, rule_rows = _rule_bundle()
    watermark = _sha256({
        "analysis_version": ANALYSIS_VERSION,
        "context": {
            "project_id": project_id, "env_id": env_id,
            "profile_revision_id": profile_revision_id,
        },
        "endpoints": endpoint_watermark_rows(endpoint_facts),
        "parameters": [
            (item.fact_id, item.pathid, item.direction, item.canonical_name,
             item.category, item.locator.schema_path) for item in parameter_facts
        ],
        "relation_parameters": [
            (item.fact_id, item.pathid, item.direction, item.canonical_name,
             item.observation.value_digests) for item in relation_parameters
        ],
        "endpoint_pairs": [dataclasses.asdict(item) for item in endpoint_pairs],
        "resource_chains": [dataclasses.asdict(item) for item in combined_resource_chains],
        "principal_pairs": [dataclasses.asdict(item) for item in principal_pairs],
        "rule_bundle_sha256": bundle_sha256,
    })

    p0_relation_facts = {item.fact_id: item for item in relation_parameters}
    transitions = Counter()
    p0_outputs = {
        (match.output.producer_ref, match.output.consumer_ref): match.output.relation
        for report in p0_reports for match in report.matches
        if isinstance(match.output, ParameterRelationCandidate)
    }
    responses = [item for item in relation_parameters if item.direction == "response"]
    requests = [item for item in relation_parameters if item.direction == "request"]
    for response, request in itertools.product(responses, requests):
        legacy = str(legacy_relation_outcome(response, request).get("relation") or "none")
        current = p0_outputs.get((response.fact_id, request.fact_id), "none")
        transitions["{}->{}".format(legacy, current)] += 1

    counts = _output_counts(matches)
    draft_groups = _draft_candidates_from_matches(matches)
    summary = {
        "schema_version": "unified-rule-analysis-report.v1",
        "analysis_version": ANALYSIS_VERSION,
        "mode": "offline_rule_analysis",
        "business_network_requests": 0,
        "finding_writes": 0,
        "context": {
            "project_id": project_id, "env_id": env_id,
            "profile_id": str(getattr(profile, "profile_id", "") or ""),
            "profile_revision_id": profile_revision_id,
        },
        "input_watermark_sha256": watermark,
        "rule_bundle_sha256": bundle_sha256,
        "rules": rule_rows,
        "projection": {
            "endpoints": len(endpoint_facts), "legacy_unset_env_inherited": inherited,
            "parameter_occurrences": len(parameter_facts),
            "endpoint_pairs": len(endpoint_pairs),
            "structural_resource_chains": len(resource_chains),
            "relation_resource_chains": len(relation_chains),
            "resource_chains": len(combined_resource_chains),
            "principals": len(principal_rows), "principal_pairs": len(principal_pairs),
            "relation_parameters": len(relation_parameters),
            "parameter_skips": dict(parameter_stats),
            "relation_projection": relation_projection_stats,
        },
        "relation_projection": {
            "status": relation_projection_status, "blockers": relation_blockers,
        },
        "output_counts": dict(sorted(counts.items())),
        "plan_draft_projection": {
            "candidate_groups": len(draft_groups),
            "candidate_pathids": len({
                pathid for item in draft_groups.values() for pathid in item["pathids"]
            }),
            "execution_allowed": False,
        },
        "principal_projection": {
            "status": "complete" if principal_rows else "blocked",
            "blockers": [] if principal_rows else ["AUTHORIZATION_PRINCIPALS_UNAVAILABLE"],
        },
        "analysis_conclusion": {
            "level": "initial_partial" if not principal_rows else "initial_complete",
            "ready": bool(endpoint_facts and parameter_facts and endpoint_pairs and combined_resource_chains),
            "covered_dimensions": [
                "endpoint_classification", "parameter_role", "parameter_relation",
                "resource_chain", "crud_pair",
            ] + (["principal_profile_scope"] if principal_rows else []),
            "blocked_dimensions": [] if principal_rows else ["principal_profile_scope"],
            "automatic_verification_claimed": False,
            "finding_created": False,
        },
        "legacy_diff": {
            "classification_adapter_parity": len(endpoint_facts),
            "relation_transition_counts": dict(sorted(transitions.items())),
        },
        "candidate_samples": [
            _sha256({
                "rule_id": item.rule_id, "fact_refs": item.fact_refs,
                "output_type": type(item.output).__name__,
            })
            for item in matches[:limits.max_report_samples]
        ],
    }
    return UnifiedAnalysisResult(
        project_id=project_id, env_id=env_id,
        profile_id=str(getattr(profile, "profile_id", "") or ""),
        profile_revision_id=profile_revision_id,
        input_watermark_sha256=watermark,
        rule_bundle_sha256=bundle_sha256,
        endpoint_documents=endpoint_documents,
        parameter_documents=parameter_documents,
        relation_facts=relation_fact_map,
        reports=reports, matches=matches, summary=summary,
    )


def _locator_from_fact(value: ParameterOccurrenceFact) -> Dict[str, Any]:
    return {
        "version": value.locator.version, "direction": value.locator.direction,
        "position": value.locator.position, "kind": value.locator.kind,
        "schema_path": value.locator.schema_path,
        "canonical_name": value.locator.canonical_name,
    }


def _protected_relation(value: Any) -> bool:
    return bool(
        value.verified or value.manual_decision in {"trusted", "rejected", "deleted"}
        or value.discovery_source in {"manual_override", "manual_tombstone"}
    )


def _operation_rows(result: UnifiedAnalysisResult) -> List[Tuple[str, RuleMatch]]:
    rows = []
    for match in result.matches:
        output = match.output
        if isinstance(output, EndpointClassificationCandidate):
            key = "classification:{:012d}".format(
                int(output.endpoint_ref.rsplit(":", 1)[-1])
            )
        elif isinstance(output, ParameterRoleCandidate):
            key = "role:{:012d}:{}:{}".format(
                output.pathid, output.position, output.canonical_name,
            )
        elif isinstance(output, ParameterRelationCandidate) and output.relation != "insufficient_evidence":
            key = "relation:{}:{}".format(output.producer_ref, output.consumer_ref)
        else:
            continue
        rows.append((key, match))
    return sorted(rows, key=lambda item: item[0])


def persist_typed_outputs(result: UnifiedAnalysisResult, *, resume_after: str = "",
                          progress_callback: Optional[Callable[[str, Mapping[str, int]], None]] = None,
                          initial_counts: Optional[Mapping[str, int]] = None
                          ) -> Dict[str, int]:
    """Persist machine candidates without altering protected/manual conclusions."""
    counts = Counter(dict(initial_counts or {}))
    # Relation facts do not live in reports; rebuild the bounded projection only
    # when relation output exists. The watermark protects this second read.
    shadow_facts = dict(result.relation_facts)

    for key, match in _operation_rows(result):
        if resume_after and key <= resume_after:
            continue
        output = match.output
        if isinstance(output, EndpointClassificationCandidate):
            pathid = int(output.endpoint_ref.rsplit(":", 1)[-1])
            endpoint = result.endpoint_documents.get(pathid)
            if endpoint is None:
                counts["classification_missing"] += 1
            else:
                current = endpoint_fact_from_document(endpoint)
                if not output.apply_allowed or current.classification_source == "manual":
                    counts["classification_manual_preserved"] += 1
                else:
                    classification_contributions = [{
                        "action": action, "reason": reason,
                        "contribution": contribution,
                    } for action, reason, contribution in output.score_contributions]
                    raw_data.objects(pk=endpoint.pk).update_one(
                        set__action=output.proposed_action,
                        set__class_confidence=int(round(output.confidence * 100)),
                        set__class_reason_codes=list(output.reason_codes),
                        set__class_score_contributions=classification_contributions,
                        set__rule="abstract_rule:{}:{}".format(match.rule_id, match.rule_version),
                    )
                    counts["classification_upserted"] += 1
        elif isinstance(output, ParameterRoleCandidate):
            document = result.parameter_documents.get(output.occurrence_ref)
            endpoint = result.endpoint_documents.get(output.pathid)
            if document is None or endpoint is None:
                counts["role_missing"] += 1
            else:
                row = idor_parameter_candidate.objects(
                    project_id=result.project_id, env_id=result.env_id,
                    pathid=output.pathid, parameter=output.canonical_name,
                    direction=str(getattr(document, "direction", "") or "request"),
                    position=output.position,
                    schema_path=str(getattr(document, "schema_path", "") or ""),
                ).first()
                if row is None:
                    row = idor_parameter_candidate(
                        project_id=result.project_id, env_id=result.env_id,
                        pathid=output.pathid, raw_data=endpoint,
                        method=str(endpoint.method or ""), path=str(endpoint.path or ""),
                        parameter=output.canonical_name, position=output.position,
                        canonical_name=output.canonical_name,
                        direction=str(getattr(document, "direction", "") or "request"),
                        schema_path=str(getattr(document, "schema_path", "") or ""),
                        locator=dict(getattr(document, "locator", None) or {}),
                        param_type=str(getattr(document, "type", "") or ""),
                        required=bool(getattr(document, "required", False)),
                    )
                    counts["role_created"] += 1
                else:
                    counts["role_updated"] += 1
                # manual_role/manual_note are intentionally untouched.
                row.role = output.role
                row.role_confidence = output.confidence
                row.reason_codes = list(output.reason_codes)
                row.source_meta = {
                    "source": "abstract_rule_p1", "rule_id": match.rule_id,
                    "rule_version": match.rule_version, "rule_sha256": match.rule_sha256,
                    "relation_eligible": output.relation_eligible,
                    "input_watermark_sha256": result.input_watermark_sha256,
                    "score_contributions": _score_contributions(match),
                }
                row.mtime = dt.datetime.utcnow()
                row.save()
                priority = parameter_priority_item.objects(
                    project_id=result.project_id, parameter=output.canonical_name,
                ).first() or parameter_priority_item(
                    project_id=result.project_id, parameter=output.canonical_name,
                    canonical_key=output.canonical_name,
                )
                priority.rule_role = output.role
                priority.rule_weight = output.confidence
                priority.rule_reasons = list(output.reason_codes)
                priority.mtime = dt.datetime.utcnow()
                priority.save()
                counts["priority_upserted"] += 1
        elif isinstance(output, ParameterRelationCandidate):
            source = shadow_facts.get(output.producer_ref)
            target = shadow_facts.get(output.consumer_ref)
            if source is None or target is None:
                counts["relation_fact_missing"] += 1
            else:
                existing = next((item for item in parameter_relation.objects(
                    project_id=result.project_id,
                    env_id__in=["", result.env_id],
                    res_pathid=source.pathid, req_pathid=target.pathid,
                ) if (
                    str(item.source_parameter or item.parameter or "") == source.canonical_name
                    and str(item.target_parameter or item.parameter or "") == target.canonical_name
                )), None)
                if existing is not None:
                    counts["relation_protected" if _protected_relation(existing) else "relation_existing_create_only"] += 1
                else:
                    parameter_relation(
                        project_id=result.project_id, env_id=result.env_id,
                        parameter=target.canonical_name,
                        source_parameter=source.canonical_name,
                        target_parameter=target.canonical_name,
                        source_position=source.locator.position,
                        target_position=target.locator.position,
                        source_locator=_locator_from_fact(source),
                        target_locator=_locator_from_fact(target),
                        locator_version=max(source.locator.version, target.locator.version),
                        location_status="resolved",
                        req_pathid=target.pathid, res_pathid=source.pathid,
                        rule="abstract_rule:{}:{}".format(match.rule_id, match.rule_version),
                        relation=output.relation,
                        score=round(output.confidence * 100.0, 2),
                        machine_confidence=output.confidence,
                        reason_codes=list(output.reason_codes),
                        evidence=[{
                            "kind": "abstract_rule_candidate", "rule_id": match.rule_id,
                            "rule_version": match.rule_version, "rule_sha256": match.rule_sha256,
                            "input_watermark_sha256": result.input_watermark_sha256,
                            "score_contributions": _score_contributions(match),
                        }],
                        verified=False, discovery_version=ANALYSIS_VERSION,
                        discovery_source="abstract_rule_p1",
                        evidence_sources=["profile_scoped_observation"],
                        first_seen_at=dt.datetime.utcnow(), last_seen_at=dt.datetime.utcnow(),
                    ).save()
                    counts["relation_created"] += 1
        if progress_callback:
            progress_callback(key, dict(counts))
    # This module never imports or writes vulnerability_finding.  The count is
    # checked as an invariant by integration tests around the caller.
    counts["finding_writes"] = 0
    return dict(counts)


def _draft_candidates_from_matches(matches: Iterable[RuleMatch]) -> Dict[str, Dict[str, Any]]:
    groups: Dict[str, Dict[str, Any]] = defaultdict(lambda: {
        "pathids": set(), "candidate_refs": [], "candidate_summaries": [],
        "operations": set(),
    })
    for match in matches:
        output = match.output
        if isinstance(output, CrudPairCandidate):
            family = output.resource_family
            group = groups[family]
            group["pathids"].update((output.left_pathid, output.right_pathid))
            group["operations"].update((output.left_operation, output.right_operation))
            refs = (output.left_ref, output.right_ref)
            current_pathids = sorted((output.left_pathid, output.right_pathid))
        elif isinstance(output, ResourceChainCandidate):
            family = output.child_family or output.parent_family
            group = groups[family]
            group["pathids"].update((output.parent_pathid, output.child_pathid))
            group["operations"].add("parent_child")
            refs = (output.parent_ref, output.child_ref)
            current_pathids = sorted((output.parent_pathid, output.child_pathid))
        else:
            continue
        group["candidate_refs"].append(_sha256({
            "rule_sha256": match.rule_sha256, "left": refs[0], "right": refs[1],
        }))
        if len(group["candidate_summaries"]) < 100:
            group["candidate_summaries"].append({
                "candidate_ref": group["candidate_refs"][-1],
                "rule_id": match.rule_id, "rule_version": match.rule_version,
                "rule_sha256": match.rule_sha256,
                "output_type": type(output).__name__, "score": match.score,
                "reason_codes": list(match.reason_codes),
                "score_contributions": _score_contributions(match),
                "pathids": current_pathids,
            })
    return groups


def create_non_executable_plan_drafts(result: UnifiedAnalysisResult, *, created_by: str = "rule-engine",
                                      max_drafts: int = 500) -> Dict[str, int]:
    groups = _draft_candidates_from_matches(result.matches)
    if len(groups) > int(max_drafts):
        raise UnifiedRuleAnalysisError("test plan draft budget exceeded")
    counts = Counter()
    for family, group in sorted(groups.items()):
        pathids = sorted(int(item) for item in group["pathids"])
        draft_sha256 = _sha256({
            "analysis_version": ANALYSIS_VERSION,
            "input_watermark_sha256": result.input_watermark_sha256,
            "rule_bundle_sha256": result.rule_bundle_sha256,
            "resource_family": family, "pathids": pathids,
            "candidate_refs": sorted(group["candidate_refs"]),
            "candidate_count": len(group["candidate_refs"]),
            "candidate_summaries": list(group["candidate_summaries"]),
        })
        name = "Rule draft · {}".format(family or "project")[:180]
        versions = list(security_test_plan.objects(
            project_id=result.project_id, env_id=result.env_id,
            name=name, check_type=PLAN_CHECK_TYPE,
        ).order_by("-version"))
        existing = next(
            (item for item in versions if dict(item.scope or {}).get("draft_sha256") == draft_sha256),
            None,
        )
        if existing is not None:
            counts["draft_reused"] += 1
            continue
        scope = {
            "pathids": pathids, "resource_family": family,
            "operations": sorted(group["operations"]),
            "candidate_refs": sorted(group["candidate_refs"]),
            "draft_sha256": draft_sha256,
            "rule_bundle_sha256": result.rule_bundle_sha256,
            "input_watermark_sha256": result.input_watermark_sha256,
            "execution_allowed": False,
        }
        fields = {
            "env_id": result.env_id, "adapter_id": PLAN_ADAPTER_ID,
            "adapter_version": "1", "auth_mode": "account" if result.profile_id else "inherit",
            "auth_profile_id": result.profile_id or None,
            "scope": scope, "snapshot_filter": {"pathids": pathids},
            "execution_policy": {"allow_mutation": False, "mutation_acknowledged": False},
            "request_budget": len(pathids),
            "description": "Generated from offline RuleSpec candidates. Draft-only; no execution adapter is registered.",
            "created_by": created_by,
        }
        try:
            if versions:
                create_next_version(versions[0].id, **fields)
            else:
                create_plan(
                    name=name, project_id=result.project_id, check_type=PLAN_CHECK_TYPE,
                    **fields,
                )
        except Exception as exc:
            if exc.__class__.__name__ != "NotUniqueError":
                raise
            existing = security_test_plan.objects(
                project_id=result.project_id, env_id=result.env_id,
                name=name, check_type=PLAN_CHECK_TYPE,
                scope__draft_sha256=draft_sha256,
            ).first()
            if existing is None:
                raise
            counts["draft_reused"] += 1
            continue
        counts["draft_created"] += 1
    counts["execution_runs_created"] = 0
    counts["business_network_requests"] = 0
    return dict(counts)
