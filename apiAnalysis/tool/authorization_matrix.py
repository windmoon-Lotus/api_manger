"""Execute bounded multi-principal authorization matrices.

Each case uses one principal to obtain a real resource identifier and another
principal to access the related resource.  Identifiers and response bodies stay
in memory; persisted evidence contains only policy identity, principal aliases,
transport metadata, digests and the construction trace.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
from typing import Any, Dict, Mapping, Sequence, Tuple

from bson import ObjectId

from apiAnalysis.db.collection import (
    AuthorizationMatrixCase,
    AuthorizationPolicy,
    AuthorizationPolicyRule,
    ProjectAuthProfile,
    ProjectEnvironment,
    idor_construction_trace,
    parameter_relation,
    raw_data,
    request_snapshot,
    security_execution_checkpoint,
    security_test_run,
)
from apiAnalysis.tool.authorization_policy import (
    authorization_relation_descriptor,
    expand_authorization_matrix,
)
from apiAnalysis.tool.execution_adapter import ExecutionAdapter
from apiAnalysis.tool.execution_contract import ExecutionContext
from apiAnalysis.tool.execution_scheduler import ExecutionPolicy, enqueue_snapshot_batch, utcnow
from apiAnalysis.tool.interface_knowledge import resource_family
from apiAnalysis.tool.parameter_validation import (
    create_validation_case_snapshot,
    replay_parameter_validation,
)
from apiAnalysis.tool.project_auth import profile_context_fields


ADAPTER_ID = "authorization_matrix"
ADAPTER_VERSION = "1"
CHECK_TYPE = "authorization_matrix"
BLOCKED_STATUSES = {401, 403, 404}


def _stable_hash(value: Any) -> str:
    encoded = json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), default=str,
    )
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _status_code(value: Any):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def observe_authorization_decision(evidence: Mapping[str, Any]) -> str:
    source_status = _status_code(evidence.get("source_status_code"))
    subject_status = _status_code(evidence.get("consumer_status_code"))
    if source_status is None or not 200 <= source_status < 300:
        return "unknown"
    if subject_status in BLOCKED_STATUSES:
        return "deny"
    if subject_status is None or subject_status == 429 or subject_status >= 500:
        return "unknown"
    if 200 <= subject_status < 300:
        matches = int(evidence.get("authorization_resource_match_count") or 0)
        fields = int(evidence.get("authorization_resource_field_count") or 0)
        if fields and matches == fields:
            return "allow"
        if matches:
            return "allow_partial"
        return "unknown"
    return "unknown"


def judge_authorization_matrix(evidence: Dict[str, Any], check_type: str, auth_mode: str):
    expected = str(evidence.get("authorization_expected_decision") or "review")
    observed = str(
        evidence.get("authorization_observed_decision")
        or observe_authorization_decision(evidence)
    )
    source_status = _status_code(evidence.get("source_status_code"))
    if source_status is None or not 200 <= source_status < 300:
        return "not_evaluable", ["authorization_owner_resource_unavailable"], 0.92
    if expected == "deny":
        if observed in {"allow", "allow_partial"}:
            reason = (
                "authorization_policy_denied_but_resource_disclosed"
                if observed == "allow" else
                "authorization_policy_denied_but_resource_partially_disclosed"
            )
            return "potential_vuln", [reason], 0.96 if observed == "allow" else 0.84
        if observed == "deny":
            return "no_vuln", ["authorization_policy_denial_enforced"], 0.97
        return "need_review", ["authorization_denial_response_inconclusive"], 0.62
    if expected == "allow":
        if observed == "allow":
            return "no_vuln", ["authorization_policy_allow_enforced"], 0.94
        if observed == "deny":
            return "need_review", ["authorization_expected_access_blocked"], 0.88
        if observed == "allow_partial":
            return "need_review", ["authorization_expected_access_partial"], 0.72
        return "need_review", ["authorization_allow_response_inconclusive"], 0.58
    return "need_review", ["authorization_policy_requires_human_decision"], 0.5


def _result_target(plan_snapshot: request_snapshot, evidence: Mapping[str, Any]) -> Dict[str, Any]:
    plan = dict((plan_snapshot.metadata or {}).get("validation_plan") or {})
    case = dict(plan.get("authorization_case") or {})
    return {
        "path": str(plan.get("resource_path") or plan_snapshot.path or ""),
        "resource_family": str(case.get("resource_family") or ""),
        "action": str(case.get("action") or ""),
        "authorization_policy_key": str(case.get("policy_key") or ""),
        "authorization_policy_version_id": str(case.get("policy_version_id") or ""),
        "authorization_policy_version": int(case.get("policy_version") or 0),
        "authorization_case_key": str(case.get("case_key") or ""),
        "resource_owner_principal_id": str(case.get("resource_owner_principal_id") or ""),
        "subject_principal_id": str(case.get("subject_principal_id") or ""),
        "expected_decision": str(case.get("expected_decision") or ""),
        "observed_decision": str(evidence.get("authorization_observed_decision") or "unknown"),
        "matched_rule_id": str(case.get("matched_rule_id") or ""),
        "relation_ids": [
            str(item.get("relation_id") or "")
            for item in (plan.get("relations") or [])
            if str(item.get("relation_id") or "")
        ],
    }


def record_authorization_matrix_case(
    run: Any,
    plan_snapshot: request_snapshot,
    evidence: Dict[str, Any],
    execution_result: Any,
    checkpoint: Any,
):
    plan = dict((plan_snapshot.metadata or {}).get("validation_plan") or {})
    case = dict(plan.get("authorization_case") or {})
    observation_key = "{}:{}".format(run.id, case.get("case_key") or plan_snapshot.id)
    row = AuthorizationMatrixCase.objects(observation_key=observation_key).first()
    if not row:
        row = AuthorizationMatrixCase(
            observation_key=observation_key,
            case_key=str(case.get("case_key") or ""),
            run_id=run.id,
            result_id=execution_result.id if execution_result else None,
            policy_key=str(case.get("policy_key") or ""),
            policy_version_id=str(case.get("policy_version_id") or ""),
            policy_version=int(case.get("policy_version") or 0),
            project_id=str(run.project_id or ""),
            env_id=str(run.env_id or ""),
            resource_owner_principal_id=str(case.get("resource_owner_principal_id") or ""),
            subject_principal_id=str(case.get("subject_principal_id") or ""),
            resource_family=str(case.get("resource_family") or ""),
            action=str(case.get("action") or ""),
            expected_decision=str(case.get("expected_decision") or "review"),
            observed_decision=str(evidence.get("authorization_observed_decision") or "unknown"),
            matched_rule_id=str(case.get("matched_rule_id") or ""),
            reason_codes=list(execution_result.reason_codes or []) if execution_result else [],
        )
        row.save()

    trace = idor_construction_trace.objects(result_id=execution_result.id).first()
    if not trace:
        mappings = list(plan.get("relations") or [])
        trace = idor_construction_trace(
            run_id=run.id,
            result_id=execution_result.id,
            pathid=plan_snapshot.pathid,
            case_name=execution_result.case_name,
            check_type=run.check_type,
            method=plan_snapshot.method,
            path=str(plan.get("resource_path") or plan_snapshot.path or ""),
            resource_owner_principal_id=str(case.get("resource_owner_principal_id") or ""),
            subject_principal_id=str(case.get("subject_principal_id") or ""),
            selected_parameters={
                str(item.get("canonical_name") or item.get("target_parameter") or "field"): {
                    "source_position": "response",
                    "target_position": str(item.get("target_position") or "body"),
                    "source_locator": dict(item.get("source_locator") or {}),
                    "target_locator": dict(item.get("target_locator") or {}),
                }
                for item in mappings
            },
            kept_parameters={"authentication": "resolved_transiently_per_principal"},
            mutations=[{
                "type": "resource_identity_substitution",
                "value_persisted": False,
                "resource_match_count": int(
                    evidence.get("authorization_resource_match_count") or 0
                ),
            }],
            value_sources={
                "source": "resource_owner_response_transient",
                "digest": str(evidence.get("value_digest") or ""),
            },
            request_before={"snapshot_id": str(plan.get("source_snapshot_id") or "")},
            request_after={"snapshot_id": str(plan.get("consumer_snapshot_id") or "")},
            strategy="resource_owner_to_subject_matrix_cell",
            strategy_reason="versioned policy and verified parameter relation",
            judge_inputs={
                "expected_decision": str(case.get("expected_decision") or ""),
                "observed_decision": str(
                    evidence.get("authorization_observed_decision") or "unknown"
                ),
                "resource_match_count": int(
                    evidence.get("authorization_resource_match_count") or 0
                ),
                "resource_field_count": int(
                    evidence.get("authorization_resource_field_count") or 0
                ),
            },
            verdict=execution_result.verdict,
            reason_codes=list(execution_result.reason_codes or []),
            evidence_ref=execution_result.evidence_ref or "",
        )
        trace.save()
    return row


def build_authorization_matrix_adapter(resolver: Any) -> ExecutionAdapter:
    def replay(snapshot, **kwargs):
        evidence = replay_parameter_validation(snapshot, resolver, **kwargs)
        evidence["authorization_matrix_case"] = True
        evidence["authorization_observed_decision"] = observe_authorization_decision(evidence)
        evidence["result_target"] = _result_target(snapshot, evidence)
        return evidence

    return ExecutionAdapter(
        adapter_id=ADAPTER_ID,
        adapter_version=ADAPTER_VERSION,
        replay=replay,
        judge=judge_authorization_matrix,
        auth_modes=frozenset({"matrix"}),
        requires_account_context=False,
        supports_mutation=False,
        record=record_authorization_matrix_case,
    )


def _load_relation_groups(policy: AuthorizationPolicy):
    if str(policy.action or "read") != "read":
        raise ValueError(
            "authorization policy action has no registered execution adapter: {}"
            .format(policy.action)
        )
    try:
        relation_ids = [ObjectId(str(item)) for item in (policy.relation_ids or [])]
    except Exception as exc:
        raise ValueError("authorization policy contains an invalid relation id") from exc
    relations = list(parameter_relation.objects(id__in=relation_ids))
    found = {str(item.id) for item in relations}
    missing = [str(item) for item in relation_ids if str(item) not in found]
    if missing:
        raise ValueError("authorization policy relations are unavailable: {}".format(", ".join(missing)))
    frozen_relations = {
        str(item.get("relation_id") or ""): dict(item)
        for item in (policy.relation_snapshots or [])
    }
    if set(frozen_relations) != found:
        raise ValueError("authorization policy has no complete frozen relation snapshot")
    grouped: Dict[Tuple[int, int], list] = {}
    for relation in relations:
        if str(relation.project_id or "") != str(policy.project_id):
            raise ValueError("authorization relation does not belong to the policy project")
        if str(relation.env_id or "") not in {"", str(policy.env_id or "")}:
            raise ValueError("authorization relation does not belong to the policy environment")
        current = authorization_relation_descriptor(relation)
        if current["relation_sha256"] != str(
            frozen_relations[str(relation.id)].get("relation_sha256") or ""
        ):
            raise ValueError(
                "authorization relation changed; clone and activate a new policy version"
            )
        grouped.setdefault((int(relation.res_pathid), int(relation.req_pathid)), []).append(relation)
    resources = []
    groups_by_key = {}
    for (source_pathid, consumer_pathid), group in sorted(grouped.items()):
        endpoint = raw_data.objects(
            ptah_id=consumer_pathid, project_id=policy.project_id,
        ).first()
        if not endpoint:
            raise ValueError("authorization consumer endpoint is unavailable")
        method = str(endpoint.method or "").upper()
        if method not in {"GET", "HEAD", "OPTIONS"}:
            raise ValueError(
                "authorization matrix currently requires read-only consumer endpoints; "
                "write actions need an explicit cleanup contract"
            )
        family = resource_family(endpoint.path or endpoint.url or "")
        if policy.resource_family and family != policy.resource_family:
            raise ValueError("authorization relation resource family does not match the policy")
        resource_key = "{}:{}".format(source_pathid, consumer_pathid)
        resources.append({
            "resource_key": resource_key,
            "relation_ids": [str(item.id) for item in group],
            "resource_family": family,
            "action": "read",
        })
        groups_by_key[resource_key] = group
    return resources, groups_by_key


def schedule_authorization_matrix(
    policy_version_id: str,
    *,
    operator: str = "",
    retention_days: int = 30,
) -> Tuple[Any, bool]:
    policy = AuthorizationPolicy.objects(
        policy_version_id=str(policy_version_id),
        lifecycle=AuthorizationPolicy.ACTIVE,
    ).first()
    if not policy:
        raise ValueError("active authorization policy version not found")
    environment = ProjectEnvironment.objects(
        project_id=policy.project_id, env_id=policy.env_id, active=True,
    ).first()
    if not environment:
        raise ValueError("authorization policy environment is unavailable")
    principal_snapshots = list(policy.principal_snapshots or [])
    if not principal_snapshots:
        raise ValueError("authorization policy has no frozen principal snapshot")
    profiles: Dict[str, Any] = {}
    for principal in principal_snapshots:
        principal_id = str(principal.get("principal_id") or "")
        profile = ProjectAuthProfile.objects(
            profile_id=str(principal.get("profile_id") or ""),
            project_id=policy.project_id,
            env_id=policy.env_id,
            active=True,
        ).first()
        if not profile or str(profile.account_key or "") != str(principal.get("account_key") or ""):
            raise ValueError("authorization principal authentication profile is unavailable")
        frozen_revision = str(principal.get("auth_profile_revision_id") or "")
        current_revision = str(profile_context_fields(profile).get("auth_profile_revision_id") or "")
        if frozen_revision != current_revision:
            raise ValueError(
                "authorization principal authentication revision changed; clone and activate "
                "a new policy version before execution"
            )
        profiles[principal_id] = profile
    rules = list(AuthorizationPolicyRule.objects(
        policy_version_id=policy.policy_version_id, active=True,
    ))
    resources, groups_by_key = _load_relation_groups(policy)
    cases = expand_authorization_matrix(policy, principal_snapshots, rules, resources)
    snapshots = []
    for case in cases:
        snapshots.append(create_validation_case_snapshot(
            groups_by_key[case.resource_key],
            profiles[str(case.owner.get("principal_id") or "")],
            profiles[str(case.subject.get("principal_id") or "")],
            environment,
            request_budget=int(policy.request_budget_per_case or 3),
            approved_large_run=int(policy.request_budget_per_case or 3) > 3,
            retention_days=retention_days,
            purpose="authorization",
            authorization_case=case.metadata(policy),
        ))
    plan_sha256 = _stable_hash({
        "policy_version_id": policy.policy_version_id,
        "snapshots": sorted(str(item.id) for item in snapshots),
    })
    context = ExecutionContext(
        project_id=policy.project_id,
        env_id=policy.env_id,
        auth_mode="matrix",
        adapter_id=ADAPTER_ID,
        adapter_version=ADAPTER_VERSION,
        plan_version="authorization-matrix-v1",
        plan_sha256=plan_sha256,
    )
    latest_terminal = security_test_run.objects(
        project_id=policy.project_id,
        env_id=policy.env_id,
        adapter_id=ADAPTER_ID,
        plan_sha256=plan_sha256,
        status__in=[security_test_run.DONE, security_test_run.FAILED],
    ).order_by("-finished_at").only("id").first()
    workers = max(1, min(8, len(snapshots)))
    run, created = enqueue_snapshot_batch(
        name="authorization matrix: {} / v{} / {} cases".format(
            policy.name, policy.version, len(snapshots),
        ),
        check_type=CHECK_TYPE,
        context=context,
        snapshot_ids=[item.id for item in snapshots],
        policy=ExecutionPolicy(
            max_workers=workers,
            per_host_workers=max(1, min(4, workers)),
            request_timeout_seconds=10,
            min_interval_ms=50,
        ),
        scope={
            "purpose": "authorization_matrix",
            "authorization_policy_key": policy.policy_key,
            "authorization_policy_version_id": policy.policy_version_id,
            "authorization_policy_version": int(policy.version or 0),
            "principal_ids": [
                str(item.get("principal_id") or "") for item in principal_snapshots
            ],
            "relation_ids": [str(item) for item in (policy.relation_ids or [])],
            "case_count": len(snapshots),
            "case_budget": int(policy.case_budget or 0),
            "request_budget_per_case": int(policy.request_budget_per_case or 0),
            "maximum_request_count": (
                len(snapshots) * int(policy.request_budget_per_case or 0)
            ),
        },
        operator=operator,
        idempotency_key="authorization-matrix:" + _stable_hash({
            "plan_sha256": plan_sha256,
            "previous_terminal_run": (
                str(latest_terminal.id) if latest_terminal else "none"
            ),
            "contract_version": 1,
        }),
    )
    expires_at = utcnow() + dt.timedelta(days=max(1, min(int(retention_days), 90)))
    security_test_run.objects(id=run.id).update_one(set__expires_at=expires_at)
    security_execution_checkpoint.objects(run_id=run.id).update(set__expires_at=expires_at)
    run.reload()
    return run, created
