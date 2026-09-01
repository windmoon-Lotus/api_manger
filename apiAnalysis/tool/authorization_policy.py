"""Versioned, selector-based authorization matrices.

The project model intentionally has no fixed ``owner``/``attacker`` pair and
does not assume that privilege is one-dimensional.  A policy selects any
number of principals and expands ordered subject x resource-owner cases.  Rule
selectors may use roles, ranks, scopes, labels and project-specific attributes.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import uuid
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Mapping, Sequence, Tuple

from bson import ObjectId

from apiAnalysis.db.collection import (
    AuthorizationPolicy,
    AuthorizationPolicyRule,
    AuthorizationPrincipal,
    ProjectAuthProfile,
    parameter_relation,
)


DECISIONS = {"allow", "deny", "review"}
SCOPE_RELATIONS = {"any", "same", "different"}
SELECTOR_FIELDS = {
    "principal_ids",
    "profile_ids",
    "account_keys",
    "role_keys",
    "scope_keys",
    "labels_all",
    "labels_any",
    "min_privilege_rank",
    "max_privilege_rank",
    "attributes",
}
MAX_CASE_BUDGET = 10_000
MAX_REQUESTS_PER_CASE = 10
SENSITIVE_ATTRIBUTE_KEYS = {
    "authorization", "cookie", "credential", "credentials", "password",
    "passwd", "secret", "token", "access_token", "refresh_token", "api_key",
    "private_key", "session", "sessionid",
}


class AuthorizationMatrixBudgetExceeded(ValueError):
    def __init__(self, required_cases: int, case_budget: int):
        self.required_cases = int(required_cases)
        self.case_budget = int(case_budget)
        super().__init__(
            "authorization matrix requires {} cases but policy budget is {}; "
            "narrow the principal/resource scope or create a new policy version"
            .format(self.required_cases, self.case_budget)
        )


def _get(value: Any, field: str, default: Any = None) -> Any:
    if isinstance(value, Mapping):
        return value.get(field, default)
    return getattr(value, field, default)


def _strings(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, (str, bytes)):
        values = [value]
    else:
        values = list(value)
    return [str(item) for item in values if str(item)]


def _stable_hash(value: Any) -> str:
    encoded = json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), default=str,
    )
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def authorization_relation_descriptor(relation: Any) -> Dict[str, Any]:
    value = {
        "relation_id": str(_get(relation, "id", "") or ""),
        "project_id": str(_get(relation, "project_id", "") or ""),
        "env_id": str(_get(relation, "env_id", "") or ""),
        "source_pathid": int(_get(relation, "res_pathid", 0) or 0),
        "consumer_pathid": int(_get(relation, "req_pathid", 0) or 0),
        "canonical_name": str(_get(relation, "parameter", "") or ""),
        "source_parameter": str(_get(relation, "source_parameter", "") or ""),
        "target_parameter": str(_get(relation, "target_parameter", "") or ""),
        "source_locator": dict(_get(relation, "source_locator", {}) or {}),
        "target_locator": dict(_get(relation, "target_locator", {}) or {}),
        "target_position": str(_get(relation, "target_position", "") or ""),
        "schema_fingerprint": str(_get(relation, "schema_fingerprint", "") or ""),
    }
    value["relation_sha256"] = _stable_hash(value)
    return value


def _validate_public_attributes(value: Mapping[str, Any], path: str = "attributes") -> Dict[str, Any]:
    result = dict(value or {})
    for key, item in result.items():
        normalized = str(key).strip().lower().replace("-", "_")
        location = "{}.{}".format(path, key)
        if normalized in SENSITIVE_ATTRIBUTE_KEYS:
            raise ValueError("authorization metadata cannot store sensitive field {}".format(location))
        if isinstance(item, Mapping):
            _validate_public_attributes(item, location)
        elif isinstance(item, (list, tuple)):
            for index, child in enumerate(item):
                if isinstance(child, Mapping):
                    _validate_public_attributes(child, "{}[{}]".format(location, index))
                elif isinstance(child, str) and child.strip().lower().startswith("bearer "):
                    raise ValueError("authorization metadata cannot store bearer material")
        elif isinstance(item, str):
            lowered = item.strip().lower()
            if lowered.startswith("bearer ") or "-----begin private key-----" in lowered:
                raise ValueError("authorization metadata cannot store authentication material")
    encoded = json.dumps(result, ensure_ascii=True, sort_keys=True, default=str)
    if len(encoded.encode("utf-8")) > 16_384:
        raise ValueError("authorization metadata is limited to 16 KiB")
    return result


def validate_selector(selector: Mapping[str, Any] | None) -> Dict[str, Any]:
    value = dict(selector or {})
    unknown = sorted(set(value) - SELECTOR_FIELDS)
    if unknown:
        raise ValueError("unsupported authorization selector fields: {}".format(", ".join(unknown)))
    attributes = value.get("attributes") or {}
    if not isinstance(attributes, Mapping):
        raise ValueError("authorization selector attributes must be a dictionary")
    for key in (
        "principal_ids", "profile_ids", "account_keys", "role_keys",
        "scope_keys", "labels_all", "labels_any",
    ):
        if key in value:
            value[key] = _strings(value[key])
    for key in ("min_privilege_rank", "max_privilege_rank"):
        if key in value:
            value[key] = int(value[key])
    if (
        "min_privilege_rank" in value and "max_privilege_rank" in value
        and value["min_privilege_rank"] > value["max_privilege_rank"]
    ):
        raise ValueError("authorization selector rank range is invalid")
    value["attributes"] = _validate_public_attributes(attributes, "selector.attributes")
    return value


def selector_matches(selector: Mapping[str, Any] | None, principal: Any) -> bool:
    """Match one principal without treating rank as the whole authorization model."""
    selector = validate_selector(selector)
    exact_sets = {
        "principal_ids": str(_get(principal, "principal_id", "") or ""),
        "profile_ids": str(_get(principal, "profile_id", "") or ""),
        "account_keys": str(_get(principal, "account_key", "") or ""),
        "role_keys": str(_get(principal, "role_key", "") or ""),
        "scope_keys": str(_get(principal, "scope_key", "") or ""),
    }
    for key, actual in exact_sets.items():
        expected = selector.get(key) or []
        if expected and actual not in expected:
            return False
    rank = int(_get(principal, "privilege_rank", 0) or 0)
    if "min_privilege_rank" in selector and rank < selector["min_privilege_rank"]:
        return False
    if "max_privilege_rank" in selector and rank > selector["max_privilege_rank"]:
        return False
    labels = {str(item) for item in (_get(principal, "labels", []) or [])}
    labels_all = set(selector.get("labels_all") or [])
    labels_any = set(selector.get("labels_any") or [])
    if labels_all and not labels_all.issubset(labels):
        return False
    if labels_any and labels.isdisjoint(labels_any):
        return False
    attributes = dict(_get(principal, "attributes", {}) or {})
    if any(attributes.get(key) != expected for key, expected in selector["attributes"].items()):
        return False
    return True


def _scope_relation_matches(rule: Any, owner: Any, subject: Any) -> bool:
    relation = str(_get(rule, "scope_relation", "any") or "any")
    if relation not in SCOPE_RELATIONS:
        return False
    owner_scope = str(_get(owner, "scope_key", "") or "")
    subject_scope = str(_get(subject, "scope_key", "") or "")
    if relation == "same":
        return bool(owner_scope and subject_scope and owner_scope == subject_scope)
    if relation == "different":
        return owner_scope != subject_scope
    return True


def resolve_authorization_expectation(
    policy: Any,
    rules: Sequence[Any],
    owner: Any,
    subject: Any,
    *,
    resource_family: str = "",
    action: str = "read",
) -> Dict[str, Any]:
    """Resolve a deterministic expectation for one ordered matrix cell."""
    ordered_rules = sorted(
        (item for item in rules if bool(_get(item, "active", True))),
        key=lambda item: (-int(_get(item, "priority", 0) or 0), str(_get(item, "rule_id", ""))),
    )
    for rule in ordered_rules:
        rule_family = str(_get(rule, "resource_family", "") or "")
        rule_action = str(_get(rule, "action", "") or "")
        if rule_family and rule_family != str(resource_family or ""):
            continue
        if rule_action and rule_action != str(action or ""):
            continue
        if not _scope_relation_matches(rule, owner, subject):
            continue
        if not selector_matches(_get(rule, "owner_selector", {}) or {}, owner):
            continue
        if not selector_matches(_get(rule, "subject_selector", {}) or {}, subject):
            continue
        expected = str(_get(rule, "expected_decision", "") or "")
        if expected not in DECISIONS:
            raise ValueError("authorization rule has an invalid expected decision")
        return {
            "expected_decision": expected,
            "matched_rule_id": str(_get(rule, "rule_id", "") or ""),
            "reason_codes": _strings(_get(rule, "reason_codes", []) or []),
        }
    same_principal = str(_get(owner, "principal_id", "")) == str(
        _get(subject, "principal_id", "")
    )
    expected = str(
        _get(policy, "same_principal_decision", "allow")
        if same_principal else _get(policy, "default_decision", "review")
    )
    if expected not in DECISIONS:
        raise ValueError("authorization policy has an invalid default decision")
    return {
        "expected_decision": expected,
        "matched_rule_id": "",
        "reason_codes": [
            "authorization_same_principal_default"
            if same_principal else "authorization_policy_default"
        ],
    }


@dataclass(frozen=True)
class AuthorizationCaseSpec:
    case_key: str
    resource_key: str
    relation_ids: Tuple[str, ...]
    resource_family: str
    action: str
    owner: Any
    subject: Any
    expected_decision: str
    matched_rule_id: str
    reason_codes: Tuple[str, ...]

    def metadata(self, policy: Any) -> Dict[str, Any]:
        return {
            "case_key": self.case_key,
            "policy_key": str(_get(policy, "policy_key", "") or ""),
            "policy_version_id": str(_get(policy, "policy_version_id", "") or ""),
            "policy_version": int(_get(policy, "version", 1) or 1),
            "resource_owner_principal_id": str(_get(self.owner, "principal_id", "") or ""),
            "subject_principal_id": str(_get(self.subject, "principal_id", "") or ""),
            "resource_family": self.resource_family,
            "action": self.action,
            "expected_decision": self.expected_decision,
            "matched_rule_id": self.matched_rule_id,
            "reason_codes": list(self.reason_codes),
        }


def expand_authorization_matrix(
    policy: Any,
    principals: Sequence[Any],
    rules: Sequence[Any],
    resources: Sequence[Mapping[str, Any]],
) -> List[AuthorizationCaseSpec]:
    """Expand the complete bounded matrix; never silently truncate cases."""
    selected_ids = _strings(_get(policy, "principal_ids", []) or [])
    by_id = {
        str(_get(item, "principal_id", "") or ""): item
        for item in principals
        if bool(_get(item, "active", True))
    }
    missing = [item for item in selected_ids if item not in by_id]
    if missing:
        raise ValueError("authorization policy principals are unavailable: {}".format(", ".join(missing)))
    selected = [by_id[item] for item in selected_ids]
    if not selected:
        raise ValueError("authorization policy requires at least one explicit principal")
    resources = [dict(item) for item in resources]
    if not resources:
        raise ValueError("authorization policy requires at least one resource relation group")
    include_self = bool(_get(policy, "include_self", True))
    pair_count = len(selected) * (len(selected) if include_self else max(0, len(selected) - 1))
    required_cases = pair_count * len(resources)
    case_budget = int(_get(policy, "case_budget", 0) or 0)
    if not 1 <= case_budget <= MAX_CASE_BUDGET:
        raise ValueError("authorization policy case budget must be between 1 and {}".format(MAX_CASE_BUDGET))
    if required_cases > case_budget:
        raise AuthorizationMatrixBudgetExceeded(required_cases, case_budget)
    request_budget = int(_get(policy, "request_budget_per_case", 0) or 0)
    if not 2 <= request_budget <= MAX_REQUESTS_PER_CASE:
        raise ValueError("authorization request budget per case must be between 2 and {}".format(MAX_REQUESTS_PER_CASE))

    result: List[AuthorizationCaseSpec] = []
    for resource in sorted(resources, key=lambda item: str(item.get("resource_key") or "")):
        relation_ids = tuple(sorted(_strings(resource.get("relation_ids") or [])))
        if not relation_ids:
            raise ValueError("authorization resource group requires relation ids")
        resource_key = str(resource.get("resource_key") or ":".join(relation_ids))
        family = str(resource.get("resource_family") or "")
        action = str(resource.get("action") or _get(policy, "action", "read") or "read")
        for owner in selected:
            for subject in selected:
                if not include_self and str(_get(owner, "principal_id", "")) == str(
                    _get(subject, "principal_id", "")
                ):
                    continue
                expectation = resolve_authorization_expectation(
                    policy, rules, owner, subject,
                    resource_family=family, action=action,
                )
                identity = {
                    "policy_key": str(_get(policy, "policy_key", "") or ""),
                    "policy_version_id": str(_get(policy, "policy_version_id", "") or ""),
                    "policy_version": int(_get(policy, "version", 1) or 1),
                    "resource_key": resource_key,
                    "relation_ids": relation_ids,
                    "resource_family": family,
                    "action": action,
                    "owner": str(_get(owner, "principal_id", "") or ""),
                    "subject": str(_get(subject, "principal_id", "") or ""),
                    "expected": expectation["expected_decision"],
                    "rule": expectation["matched_rule_id"],
                }
                result.append(AuthorizationCaseSpec(
                    case_key="authorization-case:" + _stable_hash(identity),
                    resource_key=resource_key,
                    relation_ids=relation_ids,
                    resource_family=family,
                    action=action,
                    owner=owner,
                    subject=subject,
                    expected_decision=expectation["expected_decision"],
                    matched_rule_id=expectation["matched_rule_id"],
                    reason_codes=tuple(expectation["reason_codes"]),
                ))
    return result


def create_authorization_principal(
    *, project_id: str, env_id: str, profile_id: str, name: str,
    role_key: str = "", privilege_rank: int = 0, scope_key: str = "",
    labels: Iterable[str] = (), attributes: Mapping[str, Any] | None = None,
) -> AuthorizationPrincipal:
    name = str(name or "").strip()
    role_key = str(role_key or "").strip()
    scope_key = str(scope_key or "").strip()
    normalized_labels = sorted(set(_strings(labels)))
    if not name:
        raise ValueError("authorization principal name is required")
    if any(len(value) > 120 for value in [name, role_key, scope_key] + normalized_labels):
        raise ValueError("authorization principal labels are limited to 120 characters")
    if len(normalized_labels) > 100:
        raise ValueError("authorization principal is limited to 100 labels")
    profile = ProjectAuthProfile.objects(
        profile_id=str(profile_id), project_id=str(project_id), env_id=str(env_id), active=True,
    ).first()
    if not profile:
        raise ValueError("active project authentication profile not found")
    principal = AuthorizationPrincipal(
        principal_id="principal-" + uuid.uuid4().hex,
        project_id=str(project_id),
        env_id=str(env_id),
        profile_id=str(profile.profile_id),
        account_key=str(profile.account_key),
        name=name,
        role_key=role_key,
        privilege_rank=int(privilege_rank or 0),
        scope_key=scope_key,
        labels=normalized_labels,
        attributes=_validate_public_attributes(attributes or {}),
        active=True,
    )
    principal.save()
    return principal


def create_authorization_policy_version(
    *, project_id: str, env_id: str, name: str, principal_ids: Sequence[str],
    relation_ids: Sequence[str], resource_family: str = "", action: str = "read",
    default_decision: str = "review", same_principal_decision: str = "allow",
    include_self: bool = True, case_budget: int = 100,
    request_budget_per_case: int = 3, created_by: str = "",
    policy_key: str = "", parent_policy_version_id: str = "",
) -> AuthorizationPolicy:
    name = str(name or "").strip()
    if not name:
        raise ValueError("authorization policy name is required")
    principal_ids = list(dict.fromkeys(_strings(principal_ids)))
    relation_ids = list(dict.fromkeys(_strings(relation_ids)))
    if not principal_ids or not relation_ids:
        raise ValueError("authorization policy requires explicit principals and relations")
    if default_decision not in DECISIONS or same_principal_decision not in DECISIONS:
        raise ValueError("authorization policy decisions are invalid")
    if not 1 <= int(case_budget) <= MAX_CASE_BUDGET:
        raise ValueError("authorization policy case budget is invalid")
    if not 2 <= int(request_budget_per_case) <= MAX_REQUESTS_PER_CASE:
        raise ValueError("authorization request budget per case is invalid")
    policy_key = str(policy_key or "policy-" + uuid.uuid4().hex)
    latest = AuthorizationPolicy.objects(policy_key=policy_key).order_by("-version").first()
    policy = AuthorizationPolicy(
        policy_key=policy_key,
        policy_version_id="policy-version-" + uuid.uuid4().hex,
        project_id=str(project_id),
        env_id=str(env_id),
        name=name,
        version=(int(latest.version) + 1 if latest else 1),
        lifecycle=AuthorizationPolicy.DRAFT,
        principal_ids=principal_ids,
        relation_ids=relation_ids,
        resource_family=str(resource_family or ""),
        action=str(action or "read"),
        default_decision=default_decision,
        same_principal_decision=same_principal_decision,
        include_self=bool(include_self),
        case_budget=int(case_budget),
        request_budget_per_case=int(request_budget_per_case),
        parent_policy_version_id=str(parent_policy_version_id or ""),
        created_by=str(created_by or ""),
    )
    policy.save()
    return policy


def add_authorization_policy_rule(
    policy_version_id: str, *, priority: int = 100,
    subject_selector: Mapping[str, Any] | None = None,
    owner_selector: Mapping[str, Any] | None = None,
    scope_relation: str = "any", resource_family: str = "", action: str = "read",
    expected_decision: str, reason_codes: Iterable[str] = (), description: str = "",
) -> AuthorizationPolicyRule:
    policy = AuthorizationPolicy.objects(policy_version_id=str(policy_version_id)).first()
    if not policy:
        raise ValueError("authorization policy not found")
    if policy.lifecycle != AuthorizationPolicy.DRAFT:
        raise ValueError("active authorization policy versions are immutable")
    if scope_relation not in SCOPE_RELATIONS:
        raise ValueError("authorization rule scope relation is invalid")
    if expected_decision not in DECISIONS:
        raise ValueError("authorization rule decision is invalid")
    rule = AuthorizationPolicyRule(
        rule_id="rule-" + uuid.uuid4().hex,
        policy_version_id=policy.policy_version_id,
        priority=int(priority),
        subject_selector=validate_selector(subject_selector),
        owner_selector=validate_selector(owner_selector),
        scope_relation=scope_relation,
        resource_family=str(resource_family or ""),
        action=str(action or "read"),
        expected_decision=expected_decision,
        reason_codes=_strings(reason_codes),
        description=str(description or "")[:1000],
        active=True,
    )
    rule.save()
    return rule


def activate_authorization_policy(policy_version_id: str) -> AuthorizationPolicy:
    policy = AuthorizationPolicy.objects(policy_version_id=str(policy_version_id)).first()
    if not policy:
        raise ValueError("authorization policy not found")
    if policy.lifecycle == AuthorizationPolicy.ARCHIVED:
        raise ValueError("archived authorization policy cannot be activated")
    principals = list(AuthorizationPrincipal.objects(
        principal_id__in=list(policy.principal_ids or []),
        project_id=policy.project_id, env_id=policy.env_id, active=True,
    ))
    found = {item.principal_id for item in principals}
    missing = [item for item in (policy.principal_ids or []) if item not in found]
    if missing:
        raise ValueError("authorization policy has unavailable principals: {}".format(", ".join(missing)))
    try:
        requested_relation_ids = [ObjectId(str(item)) for item in (policy.relation_ids or [])]
    except Exception as exc:
        raise ValueError("authorization policy contains an invalid relation id") from exc
    relations = list(parameter_relation.objects(id__in=requested_relation_ids))
    found_relation_ids = {str(item.id) for item in relations}
    missing_relations = [
        str(item) for item in requested_relation_ids if str(item) not in found_relation_ids
    ]
    if missing_relations:
        raise ValueError(
            "authorization policy has unavailable relations: {}".format(
                ", ".join(missing_relations)
            )
        )
    for relation in relations:
        if str(relation.project_id or "") != str(policy.project_id):
            raise ValueError("authorization policy relation belongs to another project")
        if str(relation.env_id or "") not in {"", str(policy.env_id or "")}:
            raise ValueError("authorization policy relation belongs to another environment")
        if not relation.source_locator or not relation.target_locator:
            raise ValueError("authorization policy requires located parameter relations")
        if not bool(relation.verified) and str(relation.manual_decision or "") != "trusted":
            raise ValueError("authorization policy requires verified or explicitly trusted relations")
    from apiAnalysis.tool.project_auth import profile_context_fields

    principal_snapshots = []
    for principal in sorted(principals, key=lambda item: item.principal_id):
        profile = ProjectAuthProfile.objects(
            profile_id=principal.profile_id,
            project_id=policy.project_id,
            env_id=policy.env_id,
            active=True,
        ).first()
        if not profile or profile.account_key != principal.account_key:
            raise ValueError(
                "authorization principal {} has no matching active authentication profile"
                .format(principal.principal_id)
            )
        auth_fields = profile_context_fields(profile)
        principal_snapshots.append({
            "principal_id": principal.principal_id,
            "profile_id": principal.profile_id,
            "account_key": principal.account_key,
            "name": principal.name,
            "role_key": principal.role_key or "",
            "privilege_rank": int(principal.privilege_rank or 0),
            "scope_key": principal.scope_key or "",
            "labels": sorted(str(item) for item in (principal.labels or [])),
            "attributes": dict(principal.attributes or {}),
            "auth_profile_revision_id": auth_fields.get("auth_profile_revision_id") or "",
        })
    relation_snapshots = [
        authorization_relation_descriptor(item)
        for item in sorted(relations, key=lambda relation: str(relation.id))
    ]
    now = dt.datetime.utcnow()
    AuthorizationPolicy.objects(
        policy_key=policy.policy_key,
        lifecycle=AuthorizationPolicy.ACTIVE,
        id__ne=policy.id,
    ).update(set__lifecycle=AuthorizationPolicy.ARCHIVED)
    AuthorizationPolicy.objects(id=policy.id, lifecycle=AuthorizationPolicy.DRAFT).update_one(
        set__lifecycle=AuthorizationPolicy.ACTIVE,
        set__principal_snapshots=principal_snapshots,
        set__relation_snapshots=relation_snapshots,
        set__activated_at=now,
    )
    return AuthorizationPolicy.objects(id=policy.id).first()


def clone_authorization_policy_version(policy_version_id: str, *, created_by: str = "") -> AuthorizationPolicy:
    source = AuthorizationPolicy.objects(policy_version_id=str(policy_version_id)).first()
    if not source:
        raise ValueError("authorization policy not found")
    clone = create_authorization_policy_version(
        project_id=source.project_id,
        env_id=source.env_id,
        name=source.name,
        principal_ids=list(source.principal_ids or []),
        relation_ids=list(source.relation_ids or []),
        resource_family=source.resource_family or "",
        action=source.action or "read",
        default_decision=source.default_decision or "review",
        same_principal_decision=source.same_principal_decision or "allow",
        include_self=bool(source.include_self),
        case_budget=int(source.case_budget or 100),
        request_budget_per_case=int(source.request_budget_per_case or 3),
        created_by=created_by,
        policy_key=source.policy_key,
        parent_policy_version_id=source.policy_version_id,
    )
    for rule in AuthorizationPolicyRule.objects(
        policy_version_id=source.policy_version_id,
    ).order_by("-priority"):
        add_authorization_policy_rule(
            clone.policy_version_id,
            priority=rule.priority,
            subject_selector=dict(rule.subject_selector or {}),
            owner_selector=dict(rule.owner_selector or {}),
            scope_relation=rule.scope_relation or "any",
            resource_family=rule.resource_family or "",
            action=rule.action or "read",
            expected_decision=rule.expected_decision,
            reason_codes=list(rule.reason_codes or []),
            description=rule.description or "",
        )
    return clone
