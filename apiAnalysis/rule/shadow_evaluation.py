"""Read-only Mongo projection and old/new comparison for the P0 rule runtime.

This module contains fixed, project-scoped queries.  It never sends business
HTTP requests and never writes Mongo documents.  Profile-scoped relation facts
are built only from parameter_archive rows whose project, environment, account
reference, immutable Profile Revision and source provenance all match.  Legacy
import aggregates are deliberately excluded.
"""
from __future__ import annotations

import hashlib
import itertools
import json
from collections import Counter, defaultdict
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Mapping, Sequence, Tuple

from apiAnalysis.db.collection import (
    ProjectAccountBinding,
    ProjectAuthProfile,
    ProjectAuthProfileRevision,
    ProjectEnvironment,
    parameter_archive,
    parameter_relation,
    raw_data,
    req_data,
    res_data,
)
from apiAnalysis.rule.builtin_rules import (
    legacy_relation_outcome,
    load_builtin_rule_specs,
    parameter_occurrence_from_values,
    run_builtin_p0,
)
from apiAnalysis.rule.framework import EndpointFact, ParameterOccurrenceFact
from apiAnalysis.rule.legacy_scoring import classify_endpoint_with_score
from apiAnalysis.rule.profile_parameter_archive import PROFILE_ARCHIVE_SOURCE_KIND
from apiAnalysis.tool.parameter_identity import parameter_identity


SHADOW_REPORT_VERSION = "abstract-rule-shadow.v1"


class ShadowEvaluationError(RuntimeError):
    pass


@dataclass(frozen=True)
class ShadowLimits:
    max_endpoints: int = 5000
    max_occurrences: int = 20000
    max_pair_combinations: int = 100000
    max_values_per_occurrence: int = 1000
    sample_limit: int = 20

    def validate(self) -> None:
        bounds = {
            "max_endpoints": (self.max_endpoints, 1, 50000),
            "max_occurrences": (self.max_occurrences, 1, 100000),
            "max_pair_combinations": (self.max_pair_combinations, 1, 1000000),
            "max_values_per_occurrence": (self.max_values_per_occurrence, 1, 10000),
            "sample_limit": (self.sample_limit, 0, 100),
        }
        for name, (value, minimum, maximum) in bounds.items():
            if type(value) is not int or not minimum <= value <= maximum:
                raise ShadowEvaluationError("{} is outside the supported budget".format(name))


@dataclass(frozen=True)
class ShadowProjection:
    endpoints: Tuple[EndpointFact, ...]
    parameters: Tuple[ParameterOccurrenceFact, ...]
    context: Mapping[str, str]
    stats: Mapping[str, Any]
    historical_not_equal: Tuple[Mapping[str, Any], ...]


def _sha256(value: Any) -> str:
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _bounded_rows(queryset: Any, limit: int, label: str) -> List[Any]:
    count = int(queryset.count())
    if count > limit:
        raise ShadowEvaluationError("{} budget exceeded: {} > {}".format(label, count, limit))
    return list(queryset)


def _endpoint_fact(value: Any, *, project_id: str, env_id: str) -> EndpointFact:
    pathid = int(getattr(value, "ptah_id", 0) or 0)
    action = str(getattr(value, "action", "") or "")
    rule = str(getattr(value, "rule", "") or "")
    classification_source = "none"
    if action:
        classification_source = "machine" if rule.startswith("path_score") else "manual"
    raw_req = getattr(value, "raw_req", ()) or ()
    return EndpointFact(
        fact_id="endpoint:{}".format(pathid),
        project_id=project_id,
        env_id=env_id,
        pathid=pathid,
        method=str(getattr(value, "method", "") or ""),
        path_template=str(getattr(value, "path", "") or ""),
        action=action,
        classification_source=classification_source,
        has_request_body=bool(raw_req and any(item not in (None, b"", "") for item in raw_req)),
        response_status_codes=tuple(
            int(item) for item in (getattr(value, "response_status_code", ()) or ())
        ),
    )


def _profile_context(project_id: str, env_id: str, profile_revision_id: str) -> Tuple[Any, Any, Tuple[str, ...]]:
    revision = ProjectAuthProfileRevision.objects(
        profile_revision_id=profile_revision_id,
    ).first()
    if revision is None:
        raise ShadowEvaluationError("profile revision was not found")
    profile = ProjectAuthProfile.objects(
        profile_id=revision.profile_id,
        project_id=project_id,
        env_id=env_id,
    ).first()
    if profile is None:
        raise ShadowEvaluationError("profile revision does not belong to the selected project/environment")
    account_key = str(revision.project_account_key or "")
    if not account_key:
        raise ShadowEvaluationError("profile revision has no project account reference")
    account_refs = {account_key}
    binding = ProjectAccountBinding.objects(
        project_id=project_id,
        env_id=env_id,
        account_key=account_key,
        active=True,
    ).first()
    if binding is not None and str(binding.account_id or ""):
        account_refs.add(str(binding.account_id))
    return revision, profile, tuple(sorted(account_refs))


def _archive_value_index(rows: Iterable[Any], limits: ShadowLimits) -> Tuple[Dict[Tuple[str, int, str], List[Any]], int]:
    result: Dict[Tuple[str, int, str], List[Any]] = defaultdict(list)
    total_values = 0
    for row in rows:
        identity = parameter_identity(getattr(row, "parameter", ""))
        if not identity:
            continue
        for direction, pathids, values in (
            ("request", getattr(row, "req_pathid", ()) or (), getattr(row, "req_value", ()) or ()),
            ("response", getattr(row, "res_pathid", ()) or (), getattr(row, "res_value", ()) or ()),
        ):
            for pathid in pathids:
                key = (direction, int(pathid), identity)
                bucket = result[key]
                for value in values:
                    bucket.append(value)
                    total_values += 1
                    if len(bucket) > limits.max_values_per_occurrence:
                        raise ShadowEvaluationError(
                            "profile-scoped values exceed the per-occurrence budget"
                        )
    return result, total_values


def _project_occurrences(documents: Sequence[Any], direction: str,
                         archive_values: Mapping[Tuple[str, int, str], Sequence[Any]],
                         project_id: str, env_id: str, profile_revision_id: str,
                         stats: Counter) -> List[ParameterOccurrenceFact]:
    result = []
    for document in documents:
        endpoint = getattr(document, "raw_data", None)
        pathid = int(getattr(endpoint, "ptah_id", 0) or 0)
        identity = parameter_identity(
            getattr(document, "parameter", ""),
            getattr(document, "canonical_name", ""),
        )
        values = archive_values.get((direction, pathid, identity), ())
        if not values:
            stats["skipped_without_profile_scoped_values"] += 1
            continue
        locator = dict(getattr(document, "locator", {}) or {})
        if not locator:
            stats["skipped_without_typed_locator"] += 1
            continue
        locator_identity = _sha256({
            "direction": direction,
            "pathid": pathid,
            "locator": locator,
        })
        try:
            fact = parameter_occurrence_from_values(
                fact_id="parameter:{}".format(locator_identity),
                project_id=project_id,
                env_id=env_id,
                endpoint_ref="endpoint:{}".format(pathid),
                pathid=pathid,
                direction=direction,
                canonical_name=identity,
                parameter_type=str(getattr(document, "type", "") or "unknown"),
                required=bool(getattr(document, "required", False)),
                locator=locator,
                values=values,
                source_kind="parameter_archive_profile_scoped",
                profile_revision_id=profile_revision_id,
            )
        except ValueError:
            stats["skipped_invalid_fact"] += 1
            continue
        result.append(fact)
    return result


def load_shadow_projection(project_id: str, env_id: str, profile_revision_id: str,
                           limits: ShadowLimits = ShadowLimits()) -> ShadowProjection:
    """Run only bounded read queries and return value-free rule facts."""
    project_id = str(project_id or "").strip()
    env_id = str(env_id or "").strip()
    profile_revision_id = str(profile_revision_id or "").strip()
    if not project_id or not env_id or not profile_revision_id:
        raise ShadowEvaluationError("project_id, env_id and profile_revision_id are required")
    limits.validate()
    revision, _, account_refs = _profile_context(project_id, env_id, profile_revision_id)

    active_environments = list(ProjectEnvironment.objects(
        project_id=project_id, active=True,
    ).only("env_id"))
    inherit_unset_env = (
        len(active_environments) == 1
        and str(active_environments[0].env_id or "") == env_id
    )
    environment_query = {} if inherit_unset_env else {"env_id": env_id}

    endpoint_documents = _bounded_rows(
        raw_data.objects(project_id=project_id, **environment_query).order_by("ptah_id"),
        limits.max_endpoints,
        "endpoint",
    )
    if inherit_unset_env and any(
        str(getattr(item, "env_id", "") or "") not in {"", env_id}
        for item in endpoint_documents
    ):
        raise ShadowEvaluationError("project contains assets assigned to another explicit environment")
    endpoint_facts = tuple(
        _endpoint_fact(item, project_id=project_id, env_id=env_id)
        for item in endpoint_documents
    )
    endpoint_ids = [item.id for item in endpoint_documents]

    archive_candidates = _bounded_rows(
        parameter_archive.objects(
            project_id=project_id,
            account_id__in=list(account_refs),
            **environment_query,
        ),
        limits.max_occurrences,
        "profile-scoped archive",
    )
    if inherit_unset_env and any(
        str(getattr(item, "env_id", "") or "") not in {"", env_id}
        for item in archive_candidates
    ):
        raise ShadowEvaluationError("profile-scoped archive contains another explicit environment")
    archive_rows = [
        item for item in archive_candidates
        if str(getattr(item, "env_id", "") or "") == env_id
        and str(getattr(item, "profile_revision_id", "") or "") == profile_revision_id
        and str(getattr(item, "source_kind", "") or "") == PROFILE_ARCHIVE_SOURCE_KIND
    ]
    archive_values, observed_value_count = _archive_value_index(archive_rows, limits)

    request_documents = _bounded_rows(
        req_data.objects(raw_data__in=endpoint_ids),
        limits.max_occurrences,
        "request occurrence",
    ) if endpoint_ids else []
    response_documents = _bounded_rows(
        res_data.objects(raw_data__in=endpoint_ids),
        limits.max_occurrences,
        "response occurrence",
    ) if endpoint_ids else []
    if len(request_documents) + len(response_documents) > limits.max_occurrences:
        raise ShadowEvaluationError("combined parameter occurrence budget exceeded")

    stats = Counter()
    request_facts = _project_occurrences(
        request_documents, "request", archive_values,
        project_id, env_id, profile_revision_id, stats,
    )
    response_facts = _project_occurrences(
        response_documents, "response", archive_values,
        project_id, env_id, profile_revision_id, stats,
    )
    pair_combinations = len(request_facts) * len(response_facts)
    if pair_combinations > limits.max_pair_combinations:
        raise ShadowEvaluationError(
            "relation pair budget exceeded: {} > {}".format(
                pair_combinations, limits.max_pair_combinations,
            )
        )

    historical_rows = _bounded_rows(
        parameter_relation.objects(
            project_id=project_id,
            relation="not_equal",
            **environment_query,
        ),
        limits.max_occurrences,
        "historical not_equal",
    )
    if inherit_unset_env and any(
        str(getattr(item, "env_id", "") or "") not in {"", env_id}
        for item in historical_rows
    ):
        raise ShadowEvaluationError("historical relations contain another explicit environment")
    historical = tuple({
        "pair_ref_sha256": _sha256({
            "parameter": str(getattr(item, "parameter", "") or ""),
            "req_pathid": int(getattr(item, "req_pathid", 0) or 0),
            "res_pathid": int(getattr(item, "res_pathid", 0) or 0),
        }),
        "rule": str(getattr(item, "rule", "") or ""),
        "verified": bool(getattr(item, "verified", False)),
        "manual_decision_present": bool(str(getattr(item, "manual_decision", "") or "")),
    } for item in historical_rows)

    return ShadowProjection(
        endpoints=endpoint_facts,
        parameters=tuple(response_facts + request_facts),
        context={
            "project_id": project_id,
            "env_id": env_id,
            "profile_revision_id": profile_revision_id,
            "profile_config_sha256": str(getattr(revision, "config_sha256", "") or ""),
            "account_ref_sha256": _sha256(account_refs),
        },
        stats={
            "endpoint_documents": len(endpoint_documents),
            "legacy_unset_env_inherited": bool(inherit_unset_env),
            "legacy_unset_env_endpoint_documents": sum(
                1 for item in endpoint_documents if not str(getattr(item, "env_id", "") or "")
            ),
            "request_occurrence_documents": len(request_documents),
            "response_occurrence_documents": len(response_documents),
            "profile_archive_candidate_rows": len(archive_candidates),
            "profile_archive_untrusted_rows": len(archive_candidates) - len(archive_rows),
            "profile_scoped_archive_rows": len(archive_rows),
            "profile_scoped_observed_values": observed_value_count,
            "projected_request_facts": len(request_facts),
            "projected_response_facts": len(response_facts),
            "pair_combinations": pair_combinations,
            **dict(stats),
        },
        historical_not_equal=historical,
    )


def _pair_ref(response: ParameterOccurrenceFact, request: ParameterOccurrenceFact) -> str:
    return _sha256({"producer": response.fact_id, "consumer": request.fact_id})


def _input_watermark(projection: ShadowProjection) -> str:
    return _sha256({
        "context": dict(projection.context),
        "endpoints": [
            (item.fact_id, item.method, item.path_template, item.action, item.classification_source)
            for item in projection.endpoints
        ],
        "parameters": [
            (item.fact_id, item.direction, item.canonical_name, item.parameter_type,
             item.category, item.observation.value_digests)
            for item in projection.parameters
        ],
    })


def build_shadow_report(projection: ShadowProjection, limits: ShadowLimits = ShadowLimits()) -> Dict[str, Any]:
    """Compare P0 output with legacy behavior without persisting either result."""
    limits.validate()
    responses = tuple(item for item in projection.parameters if item.direction == "response")
    requests = tuple(item for item in projection.parameters if item.direction == "request")
    pair_combinations = len(responses) * len(requests)
    if pair_combinations > limits.max_pair_combinations:
        raise ShadowEvaluationError("relation pair budget exceeded before evaluation")

    reports = run_builtin_p0(projection.endpoints, projection.parameters)
    classification_outputs = {
        match.output.endpoint_ref: match.output
        for report in reports for match in report.matches
        if hasattr(match.output, "proposed_action")
    }
    class_transitions = Counter()
    class_parity = 0
    manual_preserved = 0
    for endpoint in projection.endpoints:
        legacy_action, _, _ = classify_endpoint_with_score(endpoint)
        output = classification_outputs.get(endpoint.fact_id)
        if output is None:
            continue
        if output.legacy_action == legacy_action:
            class_parity += 1
        class_transitions["{}->{}".format(endpoint.action or "unset", output.proposed_action)] += 1
        if endpoint.classification_source == "manual" and not output.apply_allowed:
            manual_preserved += 1

    legacy_by_pair: Dict[str, str] = {}
    for response, request in itertools.product(responses, requests):
        outcome = legacy_relation_outcome(response, request)
        legacy_by_pair[_pair_ref(response, request)] = str(outcome["relation"])
    p0_by_pair: Dict[str, str] = {}
    for report in reports:
        for match in report.matches:
            output = match.output
            if not hasattr(output, "producer_ref"):
                continue
            p0_by_pair[_sha256({
                "producer": output.producer_ref,
                "consumer": output.consumer_ref,
            })] = output.relation

    transitions = Counter()
    changed_samples = []
    for pair_ref in sorted(set(legacy_by_pair).union(p0_by_pair)):
        legacy = legacy_by_pair.get(pair_ref, "none")
        p0 = p0_by_pair.get(pair_ref, "none")
        transitions["{}->{}".format(legacy, p0)] += 1
        if legacy != p0 and len(changed_samples) < limits.sample_limit:
            changed_samples.append({
                "pair_ref_sha256": pair_ref,
                "legacy_relation": legacy,
                "p0_relation": p0,
            })

    historical = projection.historical_not_equal
    relation_status = "complete" if responses and requests else "blocked"
    blockers = [] if relation_status == "complete" else ["PROFILE_SCOPED_RELATION_FACTS_UNAVAILABLE"]
    return {
        "schema_version": SHADOW_REPORT_VERSION,
        "mode": "read_only_shadow",
        "status": "complete" if relation_status == "complete" else "partial",
        "business_network_requests": 0,
        "database_writes": 0,
        "context": dict(projection.context),
        "input_watermark_sha256": _input_watermark(projection),
        "projection": dict(projection.stats),
        "classification": {
            "status": "complete",
            "evaluated": len(projection.endpoints),
            "legacy_p0_parity": class_parity,
            "manual_preserved": manual_preserved,
            "persisted_to_proposed_counts": dict(sorted(class_transitions.items())),
        },
        "relations": {
            "status": relation_status,
            "blockers": blockers,
            "evaluated_pairs": pair_combinations,
            "legacy_to_p0_counts": dict(sorted(transitions.items())),
            "changed_pair_samples": changed_samples,
        },
        "historical_not_equal_audit": {
            "count": len(historical),
            "verified_count": sum(1 for item in historical if item["verified"]),
            "manual_decision_count": sum(1 for item in historical if item["manual_decision_present"]),
            "rule_counts": dict(sorted(Counter(item["rule"] or "unknown" for item in historical).items())),
            "sample_refs": [item["pair_ref_sha256"] for item in historical[:limits.sample_limit]],
            "mutation_performed": False,
        },
        "rules": [{
            "rule_id": item.rule_id,
            "version": item.version,
            "sha256": item.canonical_sha256(),
        } for item in load_builtin_rule_specs()],
    }


def evaluate_project_shadow(project_id: str, env_id: str, profile_revision_id: str,
                            limits: ShadowLimits = ShadowLimits()) -> Dict[str, Any]:
    projection = load_shadow_projection(project_id, env_id, profile_revision_id, limits)
    return build_shadow_report(projection, limits)
