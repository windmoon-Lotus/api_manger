"""Lightweight scheduled validation for source -> consumer parameter relations."""
from __future__ import annotations

import copy
import datetime as dt
import hashlib
import json
import re
from types import SimpleNamespace
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple
from urllib.parse import urlsplit, urlunsplit

from mongoengine.errors import NotUniqueError

from apiAnalysis.db.collection import (
    ProjectAuthProfile,
    ProjectEnvironment,
    ProjectRequestFixture,
    parameter_relation,
    parameter_validation_result,
    raw_data,
    req_data,
    request_snapshot,
    res_data,
    security_execution_checkpoint,
    security_test_run,
)
from apiAnalysis.tool.account_context import AccountContext, AccountContextRef
from apiAnalysis.tool.compose_request import create_request_snapshot, render_request_url
from apiAnalysis.tool.execution_adapter import ExecutionAdapter
from apiAnalysis.tool.execution_contract import ExecutionContext
from apiAnalysis.tool.execution_scheduler import ExecutionPolicy, enqueue_snapshot_batch, utcnow
from apiAnalysis.tool.parameter_locator import (
    LOCATOR_VERSION,
    extract_values_at_locator,
    locator_from_path,
    set_value_at_locator,
)
from apiAnalysis.tool.parameter_relation_workbench import (
    MAX_APPROVED_REQUESTS,
    MAX_AUTOMATIC_REQUESTS,
    MUTATION_METHODS,
    READ_METHODS,
    bind_relation_locations as preprocess_relation_locations,
    environment_execution_policy,
    host_candidates,
    mutation_execution_allowed,
    preprocess_relation,
    relation_request_estimate,
    sync_relation_experience,
)
from apiAnalysis.tool.project_auth import (
    environment_host_names,
    normalize_host,
    profile_context_fields,
)
from apiAnalysis.tool.request_fixture import (
    apply_request_fixture,
    fixture_payload,
    get_request_fixture,
    request_input_view,
)
from apiAnalysis.tool.snapshot_runner import replay_snapshot, replay_snapshot_with_json


ADAPTER_ID = "parameter_relation_validation"
ADAPTER_VERSION = "1"
CHECK_TYPE = "parameter_relation_validation"
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
READ_HOST_RETRY_STATUS_CODES = {404, 405, 421}
PRE_RESPONSE_HOST_ERRORS = {
    "ConnectionError", "ConnectTimeout", "ProxyError", "SSLError",
    "InvalidURL", "InvalidSchema", "MissingSchema",
}
REQUEST_REJECTED_STATUS_CODES = {409, 422}
AUTH_REJECTED_STATUS_CODES = {401, 403}
GENERIC_HTTP_ERROR_CODES = {
    "400", "badrequest", "bad_request", "bad-request", "invalid",
    "invalid_request", "invalid-request", "request_error", "request-error",
    "error", "failed", "failure", "unknown",
}


class LargeValidationApprovalRequired(ValueError):
    """Raised before queueing when a batch exceeds the automatic request budget."""

    def __init__(self, estimated_requests: int, automatic_limit: int):
        self.estimated_requests = int(estimated_requests)
        self.automatic_limit = int(automatic_limit)
        super().__init__(
            "预计需要 {} 次请求，超过自动预算 {}；请确认批量执行范围".format(
                self.estimated_requests, self.automatic_limit,
            )
        )


def _stable_hash(value: Any) -> str:
    encoded = json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _safe_error_summary(response_json: Any,
                        evidence: Mapping[str, Any]) -> Dict[str, Any]:
    """Return bounded error metadata without retaining response values."""
    if response_json is None and evidence.get("response_json_type") == "object":
        text_sample = str(evidence.get("text_sample") or "")
        if text_sample:
            try:
                parsed = json.loads(text_sample)
            except (TypeError, ValueError):
                parsed = None
            if isinstance(parsed, dict):
                response_json = parsed
    top_level_keys = list(evidence.get("response_top_level_keys") or [])
    if isinstance(response_json, dict):
        top_level_keys = sorted(str(key)[:100] for key in response_json)[:60]
    error_code = ""
    error_code_source = ""
    error_fields: List[str] = []
    has_structured_errors = False

    def safe_code(value: Any, source: str) -> str:
        if not isinstance(value, (str, int)):
            return ""
        candidate = str(value).strip()
        if (
            not candidate
            or len(candidate) > 80
            or not re.fullmatch(r"[A-Za-z0-9_.:/-]+", candidate)
        ):
            return ""
        normalized = candidate.lower()
        if normalized in GENERIC_HTTP_ERROR_CODES:
            return ""
        if candidate.isdigit() and 400 <= int(candidate) <= 599:
            return ""
        if source in {"error", "message"} and not re.search(r"[./:]", candidate):
            return ""
        return candidate

    if isinstance(response_json, dict):
        code_containers = [response_json]
        nested_error = response_json.get("error")
        if isinstance(nested_error, dict):
            code_containers.append(nested_error)
        for container in code_containers:
            for key in ("error_code", "code", "errno"):
                error_code = safe_code(container.get(key), key)
                if error_code:
                    error_code_source = key
                    break
            if error_code:
                break
        if not error_code:
            error_code = safe_code(response_json.get("error"), "error")
            if error_code:
                error_code_source = "error"
        errors = response_json.get("errors")
        if isinstance(errors, dict):
            has_structured_errors = bool(errors)
            error_fields.extend(str(key)[:100] for key in errors)
        elif isinstance(errors, list):
            has_structured_errors = bool(errors)
        for key in ("field", "parameter", "param"):
            value = response_json.get(key)
            if isinstance(value, str):
                candidate = value.strip()
                if (
                    candidate
                    and len(candidate) <= 100
                    and re.fullmatch(r"[A-Za-z0-9_.\[\]-]+", candidate)
                ):
                    error_fields.append(candidate)
        if error_fields:
            has_structured_errors = True
        if not error_code:
            message = str(response_json.get("message") or "")
            match = re.search(
                r"\b[A-Za-z][A-Za-z0-9_.-]*/[A-Za-z][A-Za-z0-9_.-]*\b",
                message,
            )
            if match:
                error_code = safe_code(match.group(0), "message")
                if error_code:
                    error_code_source = "message"
    if not error_code:
        match = re.search(
            r"\b[A-Za-z][A-Za-z0-9_.-]*/[A-Za-z][A-Za-z0-9_.-]*\b",
            str(evidence.get("text_sample") or ""),
        )
        if match:
            error_code = safe_code(match.group(0), "message")
            if error_code:
                error_code_source = "message"
    explicit_business_rejection = bool(
        error_fields
        or has_structured_errors
        or error_code
    )
    return {
        "response_json_type": str(evidence.get("response_json_type") or ""),
        "response_top_level_keys": sorted(set(top_level_keys))[:60],
        "error_code": error_code,
        "error_code_source": error_code_source,
        "error_fields": sorted(set(error_fields))[:30],
        "has_structured_errors": has_structured_errors,
        "explicit_business_rejection": explicit_business_rejection,
    }


def _explicit_request_rejection(
    evidence: Mapping[str, Any],
    response_json: Any = None,
) -> bool:
    status_code = evidence.get("status_code")
    if status_code in REQUEST_REJECTED_STATUS_CODES:
        return True
    if status_code != 400:
        return False
    return bool(
        _safe_error_summary(
            response_json,
            evidence,
        ).get("explicit_business_rejection")
    )


def _value_summary(value: Any) -> Dict[str, Any]:
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
    return {
        "value_digest": hashlib.sha256(encoded.encode("utf-8")).hexdigest(),
        "value_type": type(value).__name__,
        "value_length": len(encoded),
    }


def _snapshot_view(snapshot: Any) -> SimpleNamespace:
    fields = (
        "id", "pathid", "raw_data", "source", "project_id", "import_run_id",
        "env_id", "account_id", "auth_mode", "auth_provider_id",
        "auth_context_ref", "auth_profile_revision_id", "auth_realm_revision_id",
        "auth_adapter_version_id", "method", "url", "path", "domain", "query",
        "headers", "cookies", "path_params", "body", "content_type",
        "expected_status_codes", "parameter_sources", "metadata",
    )
    return SimpleNamespace(**{
        field: copy.deepcopy(getattr(snapshot, field, None)) for field in fields
    })


def _replace_origin(url: str, base_url: str) -> str:
    if not base_url:
        return str(url or "")
    base = urlsplit(base_url if "://" in base_url else "https://" + base_url)
    original = urlsplit(str(url or ""))
    path = original.path or "/"
    base_path = (base.path or "").rstrip("/")
    if base_path and path != base_path and not path.startswith(base_path + "/"):
        path = base_path + "/" + path.lstrip("/")
    return urlunsplit((
        base.scheme or original.scheme or "https",
        base.netloc,
        path,
        original.query,
        original.fragment,
    ))


def _environment_base_url(environment: ProjectEnvironment, selected_host: str) -> str:
    selected = normalize_host(selected_host)
    for item in environment.hosts or []:
        if not isinstance(item, dict):
            continue
        candidate = normalize_host(item.get("host") or item.get("base_url") or "")
        if candidate == selected:
            return str(item.get("base_url") or item.get("host") or selected)
    return selected


def _profile_host(profile: ProjectAuthProfile, environment: ProjectEnvironment,
                  selected_host: str, fallback_host: str) -> Tuple[str, str]:
    environment_hosts = environment_host_names(environment)
    allowed = [normalize_host(item) for item in (profile.allowed_hosts or [])]
    allowed = [item for item in allowed if item] or environment_hosts
    host = normalize_host(selected_host or fallback_host or environment.default_host)
    if not host:
        raise ValueError("validation Host is required")
    if environment_hosts and host not in environment_hosts:
        raise ValueError("validation Host is outside the selected environment")
    if host not in allowed:
        raise ValueError("validation Host is outside the auth profile scope")
    return host, _environment_base_url(environment, host)


def _occurrence(model: Any, pathid: int, canonical_name: str,
                project_id: str = ""):
    normalized = str(canonical_name or "").lower().replace("-", "_")
    compact = "".join(char for char in normalized if char.isalnum())
    endpoint_query = {"ptah_id": pathid}
    if project_id:
        endpoint_query["project_id"] = str(project_id)
    endpoint = raw_data.objects(**endpoint_query).first()
    if not endpoint and project_id:
        endpoint = raw_data.objects(ptah_id=pathid).first()
    if not endpoint:
        return None
    occurrences = model.objects(raw_data=endpoint)
    item = occurrences.filter(canonical_name=normalized).first()
    if item:
        return item
    for candidate in occurrences:
        leaf = str(candidate.parameter or "").split(".")[-1].replace("[]", "")
        leaf_normalized = leaf.lower().replace("-", "_")
        if leaf_normalized == normalized or (
                compact and "".join(char for char in leaf_normalized if char.isalnum()) == compact):
            return candidate
    return None


def bind_relation_locations(relation: parameter_relation) -> parameter_relation:
    binding = preprocess_relation_locations(relation, allow_direction_fix=True)
    if not relation.source_locator or not relation.target_locator:
        relation.mtime = utcnow()
        relation.save()
        raise ValueError(relation.location_note or "relation location is unavailable")
    if binding.get("ambiguous"):
        relation.mtime = utcnow()
        relation.save()
        raise ValueError("relation parameter location is ambiguous")
    relation.locator_version = LOCATOR_VERSION
    relation.location_status = "resolved"
    relation.location_note = ""
    relation.mtime = utcnow()
    relation.save()
    return relation


def _request_template(pathid: int, profile: ProjectAuthProfile) -> request_snapshot:
    context = profile_context_fields(profile)
    key = "parameter-template:" + _stable_hash({
        "pathid": int(pathid),
        "project_id": context["project_id"],
        "env_id": context["env_id"],
        "account_id": context["account_id"],
        "provider_id": context["auth_provider_id"],
        "context_ref": context["auth_context_ref"],
        "profile_revision_id": context.get("auth_profile_revision_id") or "",
        "realm_revision_id": context.get("auth_realm_revision_id") or "",
        "adapter_version_id": context.get("auth_adapter_version_id") or "",
        "version": 2,
    })
    existing = request_snapshot.objects(template_key=key).first()
    if existing:
        return existing
    snapshot = create_request_snapshot(
        pathid,
        account_id=context["account_id"],
        env_id=context["env_id"],
        project_id=context["project_id"],
        auth_mode="account",
        source="parameter_validation_template",
        execution_metadata={
            "auth_provider_id": context["auth_provider_id"],
            "auth_context_ref": context["auth_context_ref"],
            "auth_profile_revision_id": context.get("auth_profile_revision_id") or "",
            "auth_realm_revision_id": context.get("auth_realm_revision_id") or "",
            "auth_adapter_version_id": context.get("auth_adapter_version_id") or "",
            "adapter_id": ADAPTER_ID,
            "adapter_version": ADAPTER_VERSION,
        },
    )
    if not snapshot:
        raise ValueError("request template could not be created")
    snapshot.template_key = key
    try:
        snapshot.save()
    except NotUniqueError:
        existing = request_snapshot.objects(template_key=key).first()
        if existing:
            return existing
        raise
    return snapshot


def create_validation_plan_snapshot(
    relation: parameter_relation,
    source_profile: ProjectAuthProfile,
    consumer_profile: ProjectAuthProfile,
    environment: ProjectEnvironment,
    *,
    source_host: str = "",
    consumer_host: str = "",
    manual_value: Any = None,
    manual_value_provided: bool = False,
    request_budget: int = MAX_AUTOMATIC_REQUESTS,
    approved_large_run: bool = False,
    retention_days: int = 7,
) -> request_snapshot:
    manual_values = {str(relation.id): manual_value} if manual_value_provided else {}
    return create_validation_case_snapshot(
        [relation], source_profile, consumer_profile, environment,
        source_host=source_host, consumer_host=consumer_host,
        manual_values=manual_values, request_budget=request_budget,
        approved_large_run=approved_large_run, retention_days=retention_days,
    )


def create_validation_case_snapshot(
    relations: Sequence[parameter_relation],
    source_profile: ProjectAuthProfile,
    consumer_profile: ProjectAuthProfile,
    environment: ProjectEnvironment,
    *,
    source_host: str = "",
    consumer_host: str = "",
    manual_values: Optional[Mapping[str, Any]] = None,
    request_budget: int = MAX_AUTOMATIC_REQUESTS,
    approved_large_run: bool = False,
    retention_days: int = 7,
    purpose: str = "relation",
    authorization_case: Optional[Mapping[str, Any]] = None,
) -> request_snapshot:
    relations = list(relations or [])
    manual_values = dict(manual_values or {})
    purpose = str(purpose or "relation").strip().lower()
    if purpose not in {"relation", "authorization"}:
        raise ValueError("unsupported validation purpose")
    if not relations:
        raise ValueError("at least one relation is required")
    if source_profile.project_id != consumer_profile.project_id:
        raise ValueError("source and consumer profiles must belong to one project")
    if source_profile.env_id != consumer_profile.env_id or source_profile.env_id != environment.env_id:
        raise ValueError("validation profiles must belong to the selected environment")
    authorization_case = dict(authorization_case or {})
    if purpose == "authorization":
        required_case_fields = {
            "case_key", "policy_key", "policy_version_id", "policy_version",
            "resource_owner_principal_id", "subject_principal_id",
            "expected_decision", "resource_family", "action",
        }
        missing_case_fields = sorted(
            key for key in required_case_fields if authorization_case.get(key) in {None, ""}
        )
        if missing_case_fields:
            raise ValueError(
                "authorization matrix case is missing: {}".format(
                    ", ".join(missing_case_fields)
                )
            )
        if authorization_case["expected_decision"] not in {"allow", "deny", "review"}:
            raise ValueError("authorization matrix expected decision is invalid")
    bound_relations = []
    pairs = set()
    for relation in relations:
        relation = bind_relation_locations(relation)
        if not relation.source_locator or not relation.target_locator:
            raise ValueError("relation source or target locator is unavailable")
        pairs.add((int(relation.res_pathid), int(relation.req_pathid)))
        bound_relations.append(relation)
    if len(pairs) != 1:
        raise ValueError("one validation case must use one source/consumer endpoint pair")
    source_pathid, consumer_pathid = next(iter(pairs))
    primary = bound_relations[0]
    source = _request_template(source_pathid, source_profile)
    consumer = _request_template(consumer_pathid, consumer_profile)
    if str(source.method or "").upper() not in SAFE_METHODS:
        raise ValueError("relation source must be a read-only request")
    consumer_method = str(consumer.method or "").upper()
    mutation = consumer_method in MUTATION_METHODS
    if consumer_method not in READ_METHODS | MUTATION_METHODS:
        raise ValueError("relation consumer method is unsupported")
    if purpose == "authorization" and mutation:
        raise ValueError(
            "authorization.v1 currently accepts read-only consumer endpoints; "
            "mutations require a dedicated readback and cleanup plan"
        )
    if mutation and not mutation_execution_allowed(
            environment, source_profile, consumer_profile):
        raise ValueError("写入验证只允许测试/预发环境中的测试账号")
    policy = environment_execution_policy(environment)
    maximum_budget = (
        policy["approved_request_limit"]
        if approved_large_run
        else policy["auto_request_limit"]
    )
    try:
        request_budget = max(1, min(int(request_budget), maximum_budget))
    except (TypeError, ValueError):
        request_budget = policy["auto_request_limit"]
    required_requests = relation_request_estimate(consumer_method)
    if required_requests > request_budget:
        raise LargeValidationApprovalRequired(required_requests, request_budget)
    source_selected, source_base = _profile_host(
        source_profile, environment,
        source_host or primary.selected_source_host, source.domain,
    )
    consumer_selected, consumer_base = _profile_host(
        consumer_profile, environment,
        consumer_host or primary.selected_consumer_host, consumer.domain,
    )
    source_endpoint = raw_data.objects(
        ptah_id=source_pathid, project_id=source_profile.project_id,
    ).first() or raw_data.objects(ptah_id=source_pathid).first()
    consumer_endpoint = raw_data.objects(
        ptah_id=consumer_pathid, project_id=consumer_profile.project_id,
    ).first() or raw_data.objects(ptah_id=consumer_pathid).first()
    source_options = host_candidates(
        source_endpoint, environment, source_profile, source_selected,
    )
    consumer_options = host_candidates(
        consumer_endpoint, environment, consumer_profile, consumer_selected,
    )
    source_options = source_options or [{
        "host": source_selected, "base_url": source_base, "reason": "selected", "score": 1,
    }]
    consumer_options = consumer_options or [{
        "host": consumer_selected, "base_url": consumer_base, "reason": "selected", "score": 1,
    }]
    available_source_host_count = len(source_options)
    available_consumer_host_count = len(consumer_options)
    source_auth = profile_context_fields(source_profile)
    consumer_auth = profile_context_fields(consumer_profile)
    source_fixture_doc = get_request_fixture(
        source_profile.project_id, environment.env_id, source_pathid, source_profile.profile_id,
    )
    consumer_fixture_doc = get_request_fixture(
        consumer_profile.project_id, environment.env_id, consumer_pathid, consumer_profile.profile_id,
    )
    source_fixture = fixture_payload(source_fixture_doc)
    consumer_fixture = fixture_payload(consumer_fixture_doc)
    mappings = []
    mapping_identity = []
    for relation in sorted(bound_relations, key=lambda item: str(item.id)):
        relation_key = str(relation.id)
        provided = relation_key in manual_values
        manual_value = manual_values.get(relation_key)
        manual_summary = _value_summary(manual_value) if provided else {}
        mapping = {
            "relation_id": relation_key,
            "canonical_name": relation.parameter,
            "source_parameter": relation.source_parameter or relation.parameter,
            "target_parameter": relation.target_parameter or relation.parameter,
            "source_locator": dict(relation.source_locator or {}),
            "target_locator": dict(relation.target_locator or {}),
            "target_position": relation.target_position or "body",
            "manual_value_provided": provided,
            "manual_value": manual_value if provided else None,
        }
        mappings.append(mapping)
        mapping_identity.append({
            key: value for key, value in mapping.items() if key != "manual_value"
        })
        mapping_identity[-1]["manual_value_digest"] = manual_summary.get("value_digest") or ""
    source_input = request_input_view(
        source_pathid, source_profile.project_id, environment.env_id,
        source_profile.profile_id, account_id=source_profile.account_key,
    )
    consumer_input = request_input_view(
        consumer_pathid, consumer_profile.project_id, environment.env_id,
        consumer_profile.profile_id, account_id=consumer_profile.account_key,
        relation_targets=[{
            "position": item["target_position"],
            "parameter": item["target_parameter"],
            "locator": item["target_locator"],
        } for item in mappings],
    )
    if source_input.get("gaps") or consumer_input.get("gaps"):
        gap_labels = []
        for role, input_view in (("来源", source_input), ("消费", consumer_input)):
            for gap in input_view.get("gaps") or []:
                gap_labels.append("{} {}·{}".format(
                    role, gap.get("position") or "body", gap.get("parameter") or "?",
                ))
        raise ValueError(
            "接口测试数据未就绪：{}。请先在参数关系页补充，保存后可复用。".format(
                "、".join(gap_labels[:8])
            )
        )
    plan_identity = {
        "purpose": purpose,
        "authorization_case": authorization_case if purpose == "authorization" else {},
        "relation_id": str(primary.id),
        "relation_ids": [item["relation_id"] for item in mappings],
        "relations": mapping_identity,
        "source_snapshot_id": str(source.id),
        "consumer_snapshot_id": str(consumer.id),
        "source_profile_id": source_profile.profile_id,
        "consumer_profile_id": consumer_profile.profile_id,
        "source_host": source_selected,
        "consumer_host": consumer_selected,
        "source_hosts": [
            {"host": item["host"], "base_url": item["base_url"]}
            for item in source_options[:request_budget]
        ],
        "consumer_hosts": [
            {"host": item["host"], "base_url": item["base_url"]}
            for item in consumer_options[:request_budget]
        ],
        "available_source_host_count": available_source_host_count,
        "available_consumer_host_count": available_consumer_host_count,
        "source_fixture_id": source_fixture_doc.fixture_id if source_fixture_doc else "",
        "source_fixture_revision": str(
            (source_fixture_doc.current_revision_id or source_fixture_doc.mtime)
            if source_fixture_doc else ""
        ),
        "consumer_fixture_id": consumer_fixture_doc.fixture_id if consumer_fixture_doc else "",
        "consumer_fixture_revision": str(
            (consumer_fixture_doc.current_revision_id or consumer_fixture_doc.mtime)
            if consumer_fixture_doc else ""
        ),
        "request_budget": request_budget,
        "environment_request_limit": policy["auto_request_limit"],
        "environment_approved_limit": policy["approved_request_limit"],
        "mutation": mutation,
        "approved_large_run": bool(approved_large_run),
        "version": 6,
    }
    template_key = (
        "authorization-matrix-plan:" if purpose == "authorization" else "parameter-plan:"
    ) + _stable_hash(plan_identity)
    existing = request_snapshot.objects(template_key=template_key).first()
    expires_at = utcnow() + dt.timedelta(days=max(1, min(int(retention_days), 90)))
    if existing:
        if not existing.expires_at or existing.expires_at < expires_at:
            existing.expires_at = expires_at
            existing.save()
        return existing
    plan = dict(plan_identity)
    plan.update({
        "authorization_matrix_case": purpose == "authorization",
        "resource_path": str(getattr(consumer_endpoint, "path", "") or consumer.path),
        "source_auth": source_auth,
        "consumer_auth": consumer_auth,
        "source_base_url": source_base,
        "consumer_base_url": consumer_base,
        "source_url_template": str(getattr(source_endpoint, "url", "") or source.url),
        "consumer_url_template": str(getattr(consumer_endpoint, "url", "") or consumer.url),
        "source_fixture": source_fixture,
        "consumer_fixture": consumer_fixture,
        "relations": mappings,
        # Legacy single-relation fields keep old workers/tests readable.
        "source_parameter": mappings[0]["source_parameter"],
        "target_parameter": mappings[0]["target_parameter"],
        "source_locator": mappings[0]["source_locator"],
        "target_locator": mappings[0]["target_locator"],
        "target_position": mappings[0]["target_position"],
        "canonical_name": mappings[0]["canonical_name"],
        "manual_value_provided": mappings[0]["manual_value_provided"],
        "manual_value": mappings[0]["manual_value"],
        "retention_days": max(1, min(int(retention_days), 90)),
        "consumer_method": consumer_method,
        "environment_type": policy["environment_type"],
        "mutation_authorized": bool(mutation and policy["allow_mutation"]),
    })
    snapshot = request_snapshot(
        pathid=consumer.pathid,
        raw_data=consumer.raw_data,
        source=(
            "authorization_matrix_plan"
            if purpose == "authorization" else "parameter_relation_plan"
        ),
        project_id=consumer_auth["project_id"],
        env_id=consumer_auth["env_id"],
        account_id="" if purpose == "authorization" else consumer_auth["account_id"],
        auth_mode="matrix" if purpose == "authorization" else "account",
        auth_provider_id="" if purpose == "authorization" else consumer_auth["auth_provider_id"],
        auth_context_ref="" if purpose == "authorization" else consumer_auth["auth_context_ref"],
        auth_profile_revision_id=(
            "" if purpose == "authorization"
            else consumer_auth.get("auth_profile_revision_id") or ""
        ),
        auth_realm_revision_id=(
            "" if purpose == "authorization"
            else consumer_auth.get("auth_realm_revision_id") or ""
        ),
        auth_adapter_version_id=(
            "" if purpose == "authorization"
            else consumer_auth.get("auth_adapter_version_id") or ""
        ),
        adapter_id=(
            "authorization_matrix"
            if purpose == "authorization" else ADAPTER_ID
        ),
        adapter_version=ADAPTER_VERSION,
        method=consumer.method,
        url=_replace_origin(consumer.url, consumer_base),
        path=consumer.path,
        domain=consumer_selected,
        query={}, headers={}, cookies={}, path_params={}, body=None,
        content_type=consumer.content_type,
        expected_status_codes=consumer.expected_status_codes or [],
        parameter_sources={},
        metadata={"validation_plan": plan},
        template_key=template_key,
        expires_at=expires_at,
    )
    try:
        snapshot.save(force_insert=True)
    except NotUniqueError:
        existing = request_snapshot.objects(template_key=template_key).first()
        if existing:
            return existing
        raise
    return snapshot


def _batch_source_blockers(
    project_id: str,
    environment: ProjectEnvironment,
    source_profile: ProjectAuthProfile,
    source_pathids: Sequence[int],
) -> Dict[int, str]:
    """Find shared source requests that need new fixture/auth context first."""
    pathids = sorted({int(value) for value in source_pathids})
    if not pathids:
        return {}
    latest_by_pathid: Dict[int, parameter_validation_result] = {}
    for result in parameter_validation_result.objects(
        project_id=project_id,
        env_id=environment.env_id,
        source_profile_id=source_profile.profile_id,
        res_pathid__in=pathids,
    ).only(
        "res_pathid", "status", "ctime", "source_result",
    ).order_by("-ctime"):
        if result.res_pathid is None:
            continue
        latest_by_pathid.setdefault(int(result.res_pathid), result)
        if len(latest_by_pathid) == len(pathids):
            break

    fixtures = {
        int(fixture.pathid): fixture
        for fixture in ProjectRequestFixture.objects(
            project_id=project_id,
            env_id=environment.env_id,
            profile_id=source_profile.profile_id,
            pathid__in=pathids,
            active=True,
            name="default",
        ).only("pathid", "mtime")
    }
    profile_times = [
        value for value in (
            getattr(source_profile, "mtime", None),
            getattr(source_profile, "last_refresh_at", None),
        ) if value
    ]
    blocked = {}
    for pathid, result in latest_by_pathid.items():
        status = str(result.status or "")
        if status == "source_request_rejected":
            source_result = dict(result.source_result or {})
            error_summary = dict(source_result.get("error_summary") or {})
            explicit = bool(
                source_result.get("status_code") in {409, 422}
                or error_summary.get("explicit_business_rejection")
                or error_summary.get("error_code")
                or error_summary.get("error_fields")
                or error_summary.get("has_structured_errors")
                or any(
                    item.get("explicit_business_rejection")
                    for item in list(source_result.get("attempts") or [])
                )
            )
            if not explicit:
                continue
            fixture = fixtures.get(pathid)
            if (
                fixture
                and fixture.mtime
                and result.ctime
                and fixture.mtime > result.ctime
            ):
                continue
            blocked[pathid] = status
        elif status == "source_auth_rejected":
            if (
                result.ctime
                and any(value > result.ctime for value in profile_times)
            ):
                continue
            blocked[pathid] = status
    return blocked


def select_ready_validation_batch(
    project_id: str,
    source_profile: ProjectAuthProfile,
    consumer_profile: ProjectAuthProfile,
    environment: ProjectEnvironment,
    *,
    total_request_budget: int,
    include_mutations: bool = False,
    approved_large_run: bool = False,
) -> Dict[str, Any]:
    """Select complete ready endpoint pairs under one hard total-request bound.

    Every selected pair receives the normal three-request safety envelope.  A
    read pair usually consumes two requests, but reserving three means Host
    retry can never make the batch exceed the number explicitly shown to the
    operator.
    """
    project_id = str(project_id or "").strip()
    if not project_id:
        raise ValueError("请选择需要验证的项目")
    if (
        source_profile.project_id != project_id
        or consumer_profile.project_id != project_id
    ):
        raise ValueError("批量验证认证方案不属于当前项目")
    if (
        source_profile.env_id != environment.env_id
        or consumer_profile.env_id != environment.env_id
    ):
        raise ValueError("批量验证认证方案不属于当前环境")

    policy = environment_execution_policy(environment)
    try:
        requested_total = int(total_request_budget)
    except (TypeError, ValueError) as exc:
        raise ValueError("总请求预算必须是整数") from exc
    if requested_total < 1:
        raise ValueError("总请求预算至少为 1")
    if requested_total > int(policy["approved_request_limit"]):
        raise ValueError(
            "总请求预算超过当前环境上限 {}".format(policy["approved_request_limit"])
        )
    if requested_total > int(policy["auto_request_limit"]) and not approved_large_run:
        raise LargeValidationApprovalRequired(
            requested_total, int(policy["auto_request_limit"]),
        )

    per_case_budget = min(
        MAX_AUTOMATIC_REQUESTS,
        int(policy["approved_request_limit"]),
    )
    if requested_total < per_case_budget:
        raise ValueError(
            "当前总预算不足以安全验证 1 个接口对；至少需要 {} 次请求".format(
                per_case_budget,
            )
        )

    # Approval-required pairs must not silently re-enter the same automatic
    # three-request envelope.  They are retried from their relation card (or
    # the latest-run recovery action) with an explicitly approved, larger
    # per-pair budget.
    rows = list(parameter_relation.objects(
        project_id=project_id,
        preprocess_status="auto_ready",
        manual_decision__nin=["rejected", "deleted"],
    ).order_by("-machine_confidence", "id"))
    grouped: Dict[Tuple[int, int], List[parameter_relation]] = {}
    for relation in rows:
        if not (
            relation.source_locator
            and relation.target_locator
            and relation.location_status == "resolved"
        ):
            continue
        grouped.setdefault(
            (int(relation.res_pathid), int(relation.req_pathid)),
            [],
        ).append(relation)

    endpoint_ids = sorted({
        pathid for pair in grouped for pathid in pair
    })
    endpoints = {
        int(endpoint.ptah_id): endpoint
        for endpoint in raw_data.objects(
            project_id=project_id,
            ptah_id__in=endpoint_ids,
        ).only("ptah_id", "method", "path", "domain", "url")
    }
    endpoint_methods = {
        pathid: str(endpoint.method or "").upper()
        for pathid, endpoint in endpoints.items()
    }
    ranked_pairs = sorted(
        grouped.items(),
        key=lambda item: (
            -max(float(row.machine_confidence or 0) for row in item[1]),
            item[0][0],
            item[0][1],
        ),
    )

    selected: List[parameter_relation] = []
    selected_pairs = []
    source_blockers = _batch_source_blockers(
        project_id,
        environment,
        source_profile,
        [pair[0] for pair in grouped],
    )
    skipped_source_blocked_pairs = 0
    skipped_mutation_pairs = 0
    skipped_unsupported_pairs = 0
    mutation_pairs = 0
    read_pairs = 0
    reserved_requests = 0
    mutation_allowed = mutation_execution_allowed(
        environment, source_profile, consumer_profile,
    )
    for (source_pathid, consumer_pathid), pair_relations in ranked_pairs:
        if source_pathid in source_blockers:
            skipped_source_blocked_pairs += 1
            continue
        method = endpoint_methods.get(consumer_pathid, "")
        source_endpoint = endpoints.get(source_pathid)
        consumer_endpoint = endpoints.get(consumer_pathid)
        primary_relation = pair_relations[0]
        mutation = method in MUTATION_METHODS
        if method not in READ_METHODS | MUTATION_METHODS:
            skipped_unsupported_pairs += 1
            continue
        if mutation and (not include_mutations or not mutation_allowed):
            skipped_mutation_pairs += 1
            continue
        if reserved_requests + per_case_budget > requested_total:
            continue
        selected.extend(pair_relations)
        selected_pairs.append({
            "pair_key": "{}:{}".format(source_pathid, consumer_pathid),
            "source_pathid": source_pathid,
            "consumer_pathid": consumer_pathid,
            "source_method": str(
                getattr(source_endpoint, "method", "") or ""
            ).upper(),
            "source_path": str(
                getattr(source_endpoint, "path", "") or ""
            ),
            "source_host": str(
                getattr(primary_relation, "selected_source_host", "") or
                getattr(source_endpoint, "domain", "") or ""
            ),
            "consumer_method": method,
            "consumer_path": str(
                getattr(consumer_endpoint, "path", "") or ""
            ),
            "consumer_host": str(
                getattr(primary_relation, "selected_consumer_host", "") or
                getattr(consumer_endpoint, "domain", "") or ""
            ),
            "field_count": len(pair_relations),
            "request_budget": per_case_budget,
            "mutation": mutation,
        })
        reserved_requests += per_case_budget
        if mutation:
            mutation_pairs += 1
        else:
            read_pairs += 1

    return {
        "relations": selected,
        "pairs": selected_pairs,
        "pair_count": len(selected_pairs),
        "field_count": len(selected),
        "read_pair_count": read_pairs,
        "mutation_pair_count": mutation_pairs,
        "available_pair_count": len(ranked_pairs),
        "skipped_source_blocked_pair_count": skipped_source_blocked_pairs,
        "skipped_mutation_pair_count": skipped_mutation_pairs,
        "skipped_unsupported_pair_count": skipped_unsupported_pairs,
        "total_request_budget": requested_total,
        "reserved_requests": reserved_requests,
        "per_case_request_budget": per_case_budget,
        "approved_large_run": bool(approved_large_run),
        "include_mutations": bool(include_mutations),
    }


def schedule_validation_batch(
    relations: Sequence[parameter_relation],
    source_profile: ProjectAuthProfile,
    consumer_profile: ProjectAuthProfile,
    environment: ProjectEnvironment,
    *,
    source_host: str = "",
    consumer_host: str = "",
    manual_values: Optional[Mapping[str, Any]] = None,
    operator: str = "",
    approved_large_run: bool = False,
    per_relation_request_budget: int = 0,
    retention_days: int = 7,
) -> Tuple[Any, bool]:
    relations = list(relations or [])
    manual_values = dict(manual_values or {})
    environment_policy = environment_execution_policy(environment)
    automatic_limit = environment_policy["auto_request_limit"]
    approved_limit = environment_policy["approved_request_limit"]
    estimated_requests = 0
    has_mutation = False
    try:
        requested_budget = int(per_relation_request_budget or 0)
    except (TypeError, ValueError):
        requested_budget = 0
    if requested_budget > automatic_limit and not approved_large_run:
        raise LargeValidationApprovalRequired(requested_budget, automatic_limit)
    maximum_budget = approved_limit if approved_large_run else automatic_limit
    relation_budget = (
        max(1, min(requested_budget, maximum_budget))
        if requested_budget else min(MAX_AUTOMATIC_REQUESTS, automatic_limit)
    )
    grouped_relations: Dict[Tuple[int, int], List[parameter_relation]] = {}
    for relation in relations:
        relation = bind_relation_locations(relation)
        grouped_relations.setdefault(
            (int(relation.res_pathid), int(relation.req_pathid)), [],
        ).append(relation)
    for (_source_pathid, consumer_pathid), group in grouped_relations.items():
        endpoint = raw_data.objects(ptah_id=consumer_pathid).only("method").first()
        method = str(endpoint.method or "").upper() if endpoint else ""
        base_estimate = relation_request_estimate(method)
        estimated_requests += max(base_estimate, relation_budget if requested_budget else base_estimate)
        has_mutation = bool(has_mutation or method in MUTATION_METHODS)
    if estimated_requests > automatic_limit and not approved_large_run:
        raise LargeValidationApprovalRequired(estimated_requests, automatic_limit)
    plans = []
    for _pair, group in sorted(grouped_relations.items()):
        plans.append(create_validation_case_snapshot(
            group,
            source_profile,
            consumer_profile,
            environment,
            source_host=source_host,
            consumer_host=consumer_host,
            manual_values=manual_values,
            request_budget=relation_budget,
            approved_large_run=approved_large_run,
            retention_days=retention_days,
        ))
    if not plans:
        raise ValueError("at least one relation is required")
    fields = profile_context_fields(consumer_profile)
    # Repeated clicks while one run is active reuse the same task.  Once that
    # run has produced relation results, their ids advance the revision and a
    # genuine re-validation can be queued without retaining duplicate clicks.
    latest_result_revisions = []
    for relation in relations:
        latest = parameter_validation_result.objects(relation=relation).order_by("-ctime").only("id").first()
        latest_result_revisions.append(str(latest.id) if latest else "none")
    context = ExecutionContext(
        project_id=fields["project_id"],
        env_id=fields["env_id"],
        account_id=fields["account_id"],
        auth_mode="account",
        auth_provider_id=fields["auth_provider_id"],
        auth_context_ref=fields["auth_context_ref"],
        auth_profile_revision_id=fields.get("auth_profile_revision_id") or "",
        auth_realm_revision_id=fields.get("auth_realm_revision_id") or "",
        auth_adapter_version_id=fields.get("auth_adapter_version_id") or "",
        adapter_id=ADAPTER_ID,
        adapter_version=ADAPTER_VERSION,
        plan_version="parameter-relation-v1",
    )
    policy = ExecutionPolicy(
        max_workers=min(4, len(plans)),
        per_host_workers=min(2, len(plans)),
        request_timeout_seconds=10,
        min_interval_ms=50,
        allow_mutation=has_mutation,
        mutation_acknowledged=has_mutation,
    )
    run, created = enqueue_snapshot_batch(
        name="参数关系验证 {} 条 / {} 个接口对".format(len(relations), len(plans)),
        check_type=CHECK_TYPE,
        context=context,
        snapshot_ids=[item.id for item in plans],
        policy=policy,
        scope={
            "relation_ids": [str(item.id) for item in relations],
            "case_count": len(plans),
            "source_profile_id": source_profile.profile_id,
            "consumer_profile_id": consumer_profile.profile_id,
            "retention_days": max(1, min(int(retention_days), 90)),
            "estimated_requests": estimated_requests,
            "approved_large_run": bool(approved_large_run),
            "per_relation_request_budget": relation_budget,
            "contains_mutation": has_mutation,
        },
        operator=operator,
        queue_name="snapshot",
        idempotency_key="parameter-validation:" + _stable_hash({
            "plans": sorted(str(item.id) for item in plans),
            "result_revisions": latest_result_revisions,
            "approved_large_run": bool(approved_large_run),
            "per_relation_request_budget": relation_budget,
            "version": 3,
        }),
    )
    expires_at = utcnow() + dt.timedelta(days=max(1, min(int(retention_days), 90)))
    security_test_run.objects(id=run.id).update_one(set__expires_at=expires_at)
    security_execution_checkpoint.objects(run_id=run.id).update(set__expires_at=expires_at)
    parameter_relation.objects(id__in=[item.id for item in relations]).update(
        set__preprocess_status="running",
        set__last_validation_run_id=run.id,
        set__mtime=utcnow(),
    )
    run.reload()
    return run, created


def _account_reference(values: Mapping[str, Any]) -> AccountContextRef:
    return AccountContextRef(
        project_id=str(values.get("project_id") or ""),
        env_id=str(values.get("env_id") or ""),
        account_id=str(values.get("account_id") or ""),
        provider_id=str(values.get("auth_provider_id") or ""),
        context_ref=str(values.get("auth_context_ref") or ""),
    )


def _same_context(context: Optional[AccountContext], reference: AccountContextRef) -> bool:
    if not context:
        return False
    return (
        context.provider_id, context.project_id, context.env_id,
        context.account_id, context.context_ref or context.account_id,
    ) == reference.cache_key()


def _context_with_cookie_overlay(context: AccountContext,
                                 cookies: Mapping[str, Any]) -> AccountContext:
    """Overlay a first-class request Cookie without persisting either value."""
    merged = dict(context.cookies or {})
    merged.update({str(key): str(value) for key, value in (cookies or {}).items()})
    return AccountContext(
        project_id=context.project_id,
        env_id=context.env_id,
        account_id=context.account_id,
        provider_id=context.provider_id,
        context_ref=context.context_ref,
        headers=context.headers,
        cookies=merged,
        auth_kind=context.auth_kind,
        expires_at=context.expires_at,
        issued_at=context.issued_at,
        allowed_hosts=context.allowed_hosts,
        metadata=context.metadata,
    )


def _fallback_values(value: Any, canonical_name: str, limit: int = 20) -> List[Any]:
    results: List[Any] = []
    target = str(canonical_name or "").lower().replace("-", "_")
    def walk(node: Any) -> None:
        if len(results) >= limit:
            return
        if isinstance(node, dict):
            for key, child in node.items():
                if str(key).lower().replace("-", "_") == target:
                    results.append(child)
                walk(child)
        elif isinstance(node, list):
            for child in node:
                walk(child)
    walk(value)
    return results[:limit]


def _response_contains_value(document: Any, expected: Any, limit: int = 10000) -> bool:
    """Compare transient response values without returning or persisting them."""
    expected_values = expected if isinstance(expected, list) else [expected]
    expected_hashes = {_stable_hash(item) for item in expected_values}
    pending = [document]
    visited = 0
    while pending and visited < limit:
        current = pending.pop()
        visited += 1
        if isinstance(current, dict):
            pending.extend(current.values())
        elif isinstance(current, list):
            pending.extend(current)
        elif _stable_hash(current) in expected_hashes:
            return True
    return False


def _apply_value(snapshot: SimpleNamespace, plan: Mapping[str, Any], value: Any) -> str:
    position = str(plan.get("target_position") or "body")
    parameter = str(plan.get("target_parameter") or plan.get("canonical_name") or "")
    if position == "query":
        snapshot.query = dict(snapshot.query or {})
        snapshot.query[parameter] = value
        snapshot.url = render_request_url({"url": snapshot.url, "query": snapshot.query})
    elif position == "header":
        snapshot.headers = dict(snapshot.headers or {})
        snapshot.headers[parameter] = value
    elif position == "cookie":
        snapshot.cookies = dict(snapshot.cookies or {})
        snapshot.cookies[parameter] = value
    elif position == "path":
        snapshot.path_params = dict(snapshot.path_params or {})
        snapshot.path_params[parameter] = value
        for name in {parameter, str(plan.get("canonical_name") or "")}:
            snapshot.url = snapshot.url.replace("{" + name + "}", str(value))
            snapshot.url = snapshot.url.replace(":" + name, str(value))
    else:
        locator = dict(plan.get("target_locator") or {}) or locator_from_path(
            parameter, direction="request", position="body",
        )
        snapshot.body = set_value_at_locator(copy.deepcopy(snapshot.body), locator, value)
    return position


def _mutation_host_retryable(evidence: Mapping[str, Any]) -> bool:
    """Return true only when the request clearly missed business execution.

    Mutations may cross Host on deterministic route/auth rejection or failures
    that happened before an HTTP response.  Read timeouts and 5xx are excluded
    because the first Host may already have changed state.
    """
    status_code = evidence.get("status_code")
    if status_code in {401, 403, 404, 405, 421}:
        return True
    return str(evidence.get("error_type") or "") in PRE_RESPONSE_HOST_ERRORS


def _read_host_retryable(
    evidence: Mapping[str, Any],
    response_json: Any = None,
) -> bool:
    """Retry when a read failure may still be Host/routing related."""
    status_code = evidence.get("status_code")
    if status_code in READ_HOST_RETRY_STATUS_CODES:
        return True
    if status_code == 400:
        return not _explicit_request_rejection(evidence, response_json)
    return str(evidence.get("error_type") or "") in PRE_RESPONSE_HOST_ERRORS


def _request_failure_status(role: str, evidence: Mapping[str, Any], *,
                            remaining_hosts: int = 0,
                            budget_exhausted: bool = False,
                            mutation: bool = False,
                            response_json: Any = None) -> str:
    status_code = evidence.get("status_code")
    if _explicit_request_rejection(evidence, response_json):
        return "{}_request_rejected".format(role)
    if status_code in AUTH_REJECTED_STATUS_CODES:
        return "{}_auth_rejected".format(role)
    if status_code == 429:
        return "{}_rate_limited".format(role)
    retryable = (
        _mutation_host_retryable(evidence)
        if mutation else _read_host_retryable(evidence, response_json)
    )
    if retryable and remaining_hosts and budget_exhausted:
        return "host_scope_approval_required"
    return "{}_failed".format(role)


def replay_parameter_validation(plan_snapshot: request_snapshot, resolver: Any, *,
                                auth_mode: str = "account", request_options=None,
                                account_context: Optional[AccountContext] = None,
                                progress_callback: Optional[Callable[[Mapping[str, Any]], None]] = None,
                                ) -> Dict[str, Any]:
    plan = dict((plan_snapshot.metadata or {}).get("validation_plan") or {})
    mappings = list(plan.get("relations") or [])
    if not mappings:
        mappings = [{
            "relation_id": str(plan.get("relation_id") or ""),
            "canonical_name": str(plan.get("canonical_name") or ""),
            "source_parameter": str(plan.get("source_parameter") or plan.get("canonical_name") or ""),
            "target_parameter": str(plan.get("target_parameter") or plan.get("canonical_name") or ""),
            "source_locator": dict(plan.get("source_locator") or {}),
            "target_locator": dict(plan.get("target_locator") or {}),
            "target_position": str(plan.get("target_position") or "body"),
            "manual_value_provided": bool(plan.get("manual_value_provided")),
            "manual_value": plan.get("manual_value"),
        }]
    source = request_snapshot.objects(id=plan.get("source_snapshot_id")).first()
    consumer = request_snapshot.objects(id=plan.get("consumer_snapshot_id")).first()
    if not source or not consumer:
        return {"ok": False, "validation_status": "snapshot_failed", "error_type": "SnapshotNotFound"}
    source_reference = _account_reference(plan.get("source_auth") or {})
    consumer_reference = _account_reference(plan.get("consumer_auth") or {})
    configured_maximum = (
        plan.get("environment_approved_limit")
        if plan.get("approved_large_run")
        else plan.get("environment_request_limit")
    )
    try:
        maximum_budget = max(1, min(int(configured_maximum), MAX_APPROVED_REQUESTS))
    except (TypeError, ValueError):
        maximum_budget = MAX_AUTOMATIC_REQUESTS
    try:
        request_budget = max(
            1,
            min(int(plan.get("request_budget") or MAX_AUTOMATIC_REQUESTS), maximum_budget),
        )
    except (TypeError, ValueError):
        request_budget = MAX_AUTOMATIC_REQUESTS

    def report_progress(phase: str, message: str, **details: Any) -> None:
        if not progress_callback:
            return
        payload = {
            "phase": phase,
            "message": message,
            "request_budget": request_budget,
        }
        payload.update(details)
        try:
            progress_callback(payload)
        except Exception:
            # Progress is advisory.  A stale page must never break validation.
            pass

    report_progress(
        "preparing",
        "已加载来源与消费接口快照，正在准备认证和请求数据。",
        request_count=0,
    )
    mutation = bool(plan.get("mutation")) or str(consumer.method or "").upper() in MUTATION_METHODS
    source_options = list(plan.get("source_hosts") or []) or [{
        "host": plan.get("source_host") or source.domain,
        "base_url": plan.get("source_base_url") or plan.get("source_host") or source.domain,
    }]
    consumer_options = list(plan.get("consumer_hosts") or []) or [{
        "host": plan.get("consumer_host") or consumer.domain,
        "base_url": plan.get("consumer_base_url") or plan.get("consumer_host") or consumer.domain,
    }]
    try:
        available_source_host_count = max(
            len(source_options),
            int(plan.get("available_source_host_count") or 0),
        )
    except (TypeError, ValueError):
        available_source_host_count = len(source_options)
    try:
        available_consumer_host_count = max(
            len(consumer_options),
            int(plan.get("available_consumer_host_count") or 0),
        )
    except (TypeError, ValueError):
        available_consumer_host_count = len(consumer_options)

    def view_for_host(snapshot, option, role):
        view = _snapshot_view(snapshot)
        host = normalize_host(option.get("host") or option.get("base_url") or view.domain)
        base_url = str(option.get("base_url") or host)
        template_url = str(plan.get(role + "_url_template") or view.url)
        view.url = _replace_origin(template_url, base_url)
        view.domain = host
        apply_request_fixture(
            view, plan.get(role + "_fixture") or {}, url_template=view.url,
        )
        return view

    def context_for(reference, view):
        if _same_context(account_context, reference):
            return account_context
        return resolver.resolve(reference, host=view.domain, min_validity_seconds=30)

    def attempt_summary(view, evidence, response_json=None):
        safe_error = _safe_error_summary(response_json, evidence)
        def safe_names(key, limit=100):
            return [
                str(value)[:100]
                for value in list(evidence.get(key) or [])
                if str(value)
            ][:limit]

        return {
            "host": view.domain,
            "status_code": evidence.get("status_code"),
            "ok": bool(evidence.get("ok")),
            "error_type": str(evidence.get("error_type") or ""),
            "elapsed_ms": int(evidence.get("elapsed_ms") or 0),
            "response_json_type": safe_error["response_json_type"],
            "response_top_level_keys": safe_error["response_top_level_keys"],
            "error_code": safe_error["error_code"],
            "error_fields": safe_error["error_fields"],
            "explicit_business_rejection": bool(
                safe_error["explicit_business_rejection"]
            ),
            # ``snapshot_runner`` builds these fields from the actual
            # PreparedRequest.  Only structure and names cross this boundary;
            # query/header/cookie/body values remain transient.
            "request_method": str(
                evidence.get("request_method") or view.method or ""
            ).upper()[:20],
            "request_origin": str(evidence.get("request_origin") or "")[:300],
            "request_path": str(
                evidence.get("request_path") or view.path or ""
            )[:500],
            "request_query_names": safe_names("request_query_names"),
            "request_header_names": safe_names("request_header_names"),
            "request_cookie_names": safe_names("request_cookie_names"),
            "request_auth_header_names": safe_names(
                "request_auth_header_names",
            ),
            "request_auth_cookie_names": safe_names(
                "request_auth_cookie_names",
            ),
            "request_body_bytes": max(
                0, min(int(evidence.get("request_body_bytes") or 0), 1_000_000_000),
            ),
            "request_content_type": str(
                evidence.get("request_content_type") or ""
            )[:120],
            "request_timeout_seconds": evidence.get("request_timeout_seconds"),
            "request_allow_redirects": bool(
                evidence.get("request_allow_redirects", False)
            ),
            "request_tls_verify": bool(
                evidence.get("request_tls_verify", True)
            ),
            "auth_request_count": max(
                0, min(int(evidence.get("auth_request_count") or 0), 100),
            ),
        }

    request_count = 0
    source_attempts: List[Dict[str, Any]] = []
    consumer_attempts: List[Dict[str, Any]] = []
    source_evidence: Dict[str, Any] = {}
    source_json: Any = None
    selected_source_view = None
    selected_source_context = None
    value_records: Dict[str, Dict[str, Any]] = {}
    relation_results: Dict[str, Dict[str, Any]] = {}
    for mapping in mappings:
        relation_key = str(mapping.get("relation_id") or "")
        if mapping.get("manual_value_provided"):
            manual_value = mapping.get("manual_value")
            value_records[relation_key] = {
                "value": manual_value,
                "value_source": "manual_override",
                "summary": _value_summary(manual_value),
                "mapping": mapping,
            }
    needs_source = any(not mapping.get("manual_value_provided") for mapping in mappings)
    if needs_source:
        # Reserve one request for the consumer.  This lets the machine try two
        # candidate source Hosts and still stay within the three-request rule.
        for option in source_options:
            if request_count >= max(1, request_budget - 1):
                break
            source_view = view_for_host(source, option, "source")
            report_progress(
                "source_request",
                "正在请求来源接口，获取可注入消费请求的真实字段值。",
                request_count=request_count,
                attempt=len(source_attempts) + 1,
            )
            source_context = context_for(source_reference, source_view)
            source_evidence, source_json = replay_snapshot_with_json(
                source_view,
                auth_mode="account",
                request_options=request_options,
                account_context=source_context,
            )
            request_count += 1
            source_attempts.append(
                attempt_summary(source_view, source_evidence, source_json)
            )
            report_progress(
                "source_response",
                "来源接口已响应，正在检查状态并定位字段。",
                request_count=request_count,
                attempt=len(source_attempts),
                status_code=source_evidence.get("status_code"),
            )
            if source_evidence.get("ok"):
                selected_source_view = source_view
                selected_source_context = source_context
                break
            if not _read_host_retryable(source_evidence, source_json):
                break
        if not source_evidence.get("ok"):
            remaining_source_hosts = max(
                0, available_source_host_count - len(source_attempts),
            )
            source_status = _request_failure_status(
                "source",
                source_evidence,
                remaining_hosts=remaining_source_hosts,
                budget_exhausted=(
                    request_count >= max(1, request_budget - 1)
                ),
                response_json=source_json,
            )
            source_needs_host_approval = (
                source_status == "host_scope_approval_required"
            )
            for mapping in mappings:
                relation_key = str(mapping.get("relation_id") or "")
                if relation_key not in value_records:
                    relation_results[relation_key] = {
                        "relation_id": relation_key,
                        "canonical_name": str(mapping.get("canonical_name") or ""),
                        "validation_status": source_status,
                        "value_source": "source_response",
                    }
            if not value_records:
                return {
                    "ok": False,
                    "validation_status": source_status,
                    "status_code": source_evidence.get("status_code"),
                    "source_status_code": source_evidence.get("status_code"),
                    "consumer_status_code": None,
                    "elapsed_ms": source_evidence.get("elapsed_ms") or 0,
                    "response_len": source_evidence.get("response_len") or 0,
                    "domain": (source_attempts[-1]["host"] if source_attempts else ""),
                    "error_type": source_evidence.get("error_type") or "",
                    "source_attempts": source_attempts,
                    "consumer_attempts": [],
                    "request_count": request_count,
                    "remaining_host_count": (
                        remaining_source_hosts if source_needs_host_approval else 0
                    ),
                    "source_untried_host_count": remaining_source_hosts,
                    "consumer_untried_host_count": 0,
                    "approval_stage": (
                        "source" if source_needs_host_approval else ""
                    ),
                    "source_error_summary": _safe_error_summary(
                        source_json, source_evidence,
                    ),
                    "relation_results": list(relation_results.values()),
                }
        else:
            report_progress(
                "field_extraction",
                "来源请求成功，正在按字段定位器提取值并保持原始类型。",
                request_count=request_count,
            )
            for mapping in mappings:
                if mapping.get("manual_value_provided"):
                    continue
                relation_key = str(mapping.get("relation_id") or "")
                values = extract_values_at_locator(
                    source_json, mapping.get("source_locator") or {},
                )
                if not values:
                    values = _fallback_values(
                        source_json, str(mapping.get("canonical_name") or ""),
                    )
                if not values:
                    relation_results[relation_key] = {
                        "relation_id": relation_key,
                        "canonical_name": str(mapping.get("canonical_name") or ""),
                        "validation_status": "value_not_found",
                        "value_source": "source_response",
                    }
                    continue
                value = (
                    values if str(mapping.get("canonical_name") or "").endswith("_ids")
                    else values[0]
                )
                value_records[relation_key] = {
                    "value": value,
                    "value_source": "source_response",
                    "summary": _value_summary(value),
                    "mapping": mapping,
                }
    if not value_records:
        if not relation_results:
            for mapping in mappings:
                relation_results[str(mapping.get("relation_id") or "")] = {
                    "relation_id": str(mapping.get("relation_id") or ""),
                    "canonical_name": str(mapping.get("canonical_name") or ""),
                    "validation_status": "value_not_found",
                    "value_source": "source_response",
                }
        return {
            "ok": False,
            "validation_status": "value_not_found",
            "status_code": source_evidence.get("status_code"),
            "source_status_code": source_evidence.get("status_code"),
            "consumer_status_code": None,
            "elapsed_ms": source_evidence.get("elapsed_ms") or 0,
            "response_len": source_evidence.get("response_len") or 0,
            "domain": selected_source_view.domain if selected_source_view else "",
            "error_type": "",
            "source_attempts": source_attempts,
            "consumer_attempts": [],
            "request_count": request_count,
            "source_error_summary": _safe_error_summary(
                source_json, source_evidence,
            ),
            "relation_results": list(relation_results.values()),
        }

    consumer_evidence: Dict[str, Any] = {}
    consumer_json: Any = None
    selected_consumer_view = None
    positions: Dict[str, str] = {}
    # Mutations may cross Host after a deterministic route/auth rejection.  A
    # success, timeout or 5xx stops immediately and moves to after-read so an
    # unexpected side effect is preserved as development-bug evidence.
    selected_consumer_options = consumer_options
    for option in selected_consumer_options:
        if request_count >= request_budget:
            break
        consumer_view = view_for_host(consumer, option, "consumer")
        for relation_key, record in value_records.items():
            positions[relation_key] = _apply_value(
                consumer_view, record["mapping"], record["value"],
            )
        consumer_context = context_for(consumer_reference, consumer_view)
        if any(position == "cookie" for position in positions.values()) and consumer_view.cookies:
            consumer_context = _context_with_cookie_overlay(
                consumer_context, consumer_view.cookies,
            )
        report_progress(
            "consumer_request",
            "字段已注入，正在请求消费接口并观察是否被业务接受。",
            request_count=request_count,
            attempt=len(consumer_attempts) + 1,
        )
        if plan.get("authorization_matrix_case"):
            consumer_evidence, consumer_json = replay_snapshot_with_json(
                consumer_view,
                auth_mode="account",
                request_options=request_options,
                account_context=consumer_context,
            )
        else:
            consumer_evidence = replay_snapshot(
                consumer_view,
                auth_mode="account",
                request_options=request_options,
                account_context=consumer_context,
            )
        request_count += 1
        consumer_attempts.append(attempt_summary(consumer_view, consumer_evidence))
        report_progress(
            "consumer_response",
            "消费接口已响应，正在判断关系是否成立。",
            request_count=request_count,
            attempt=len(consumer_attempts),
            status_code=consumer_evidence.get("status_code"),
        )
        selected_consumer_view = consumer_view
        if consumer_evidence.get("ok"):
            break
        if mutation and not _mutation_host_retryable(consumer_evidence):
            break
        if not mutation and not _read_host_retryable(consumer_evidence):
            break

    if not consumer_attempts:
        for relation_key, record in value_records.items():
            relation_results[relation_key] = {
                "relation_id": relation_key,
                "canonical_name": str(record["mapping"].get("canonical_name") or ""),
                "validation_status": "request_budget_exhausted",
                "value_source": record["value_source"],
                "target_position": positions.get(relation_key) or record["mapping"].get("target_position"),
                **record["summary"],
            }
        return {
            "ok": False,
            "validation_status": "request_budget_exhausted",
            "source_status_code": source_evidence.get("status_code"),
            "consumer_status_code": None,
            "error_type": "RequestBudgetExhausted",
            "source_attempts": source_attempts,
            "consumer_attempts": consumer_attempts,
            "request_count": request_count,
            "relation_results": list(relation_results.values()),
        }

    effect_status = "not_checked"
    after_source_status_code = None
    remaining_consumer_hosts = max(
        0, available_consumer_host_count - len(consumer_attempts),
    )
    consumer_failure_retryable = (
        _mutation_host_retryable(consumer_evidence)
        if mutation else _read_host_retryable(consumer_evidence)
    )
    host_scope_approval = bool(
        not consumer_evidence.get("ok")
        and remaining_consumer_hosts
        and request_count >= request_budget
        and consumer_failure_retryable
    )
    consumer_failure_status = _request_failure_status(
        "consumer",
        consumer_evidence,
        remaining_hosts=remaining_consumer_hosts,
        budget_exhausted=request_count >= request_budget,
        mutation=mutation,
    )
    stopped_after_possible_execution = bool(
        mutation
        and consumer_attempts
        and not consumer_evidence.get("ok")
        and not _mutation_host_retryable(consumer_evidence)
    )
    should_read_after = bool(
        mutation
        and request_count < request_budget
        and (consumer_evidence.get("ok") or stopped_after_possible_execution)
    )
    relation_effects: Dict[str, str] = {}
    if should_read_after:
        # A bounded after-read gives DELETE a real effect check and gives other
        # writes a reachable post-state signal.  It never persists the value.
        option = {
            "host": selected_source_view.domain if selected_source_view else plan.get("source_host"),
            "base_url": next((
                item.get("base_url") for item in source_options
                if normalize_host(item.get("host")) == normalize_host(
                    selected_source_view.domain if selected_source_view else plan.get("source_host")
                )
            ), plan.get("source_base_url") or plan.get("source_host")),
        }
        after_view = view_for_host(source, option, "source")
        after_context = selected_source_context or context_for(source_reference, after_view)
        report_progress(
            "effect_check",
            "写入或删除请求已执行，正在回读来源接口确认实际效果。",
            request_count=request_count,
        )
        after_evidence, after_json = replay_snapshot_with_json(
            after_view,
            auth_mode="account",
            request_options=request_options,
            account_context=after_context,
        )
        request_count += 1
        after_source_status_code = after_evidence.get("status_code")
        if str(consumer.method or "").upper() == "DELETE" and after_evidence.get("ok"):
            for relation_key, record in value_records.items():
                mapping = record["mapping"]
                after_values = extract_values_at_locator(
                    after_json, mapping.get("source_locator") or {},
                )
                if not after_values:
                    after_values = _fallback_values(
                        after_json, str(mapping.get("canonical_name") or ""),
                    )
                original_digest = _stable_hash(record["value"])
                after_digests = {_stable_hash(item) for item in after_values}
                relation_effects[relation_key] = (
                    "delete_observed" if original_digest not in after_digests
                    else "value_still_present"
                )
            observed_count = sum(
                1 for value in relation_effects.values() if value == "delete_observed"
            )
            if observed_count == len(value_records):
                effect_status = "delete_observed"
            elif observed_count:
                effect_status = "partial_delete_observed"
            else:
                effect_status = "value_still_present"
        elif after_evidence.get("ok"):
            effect_status = "post_read_reachable"
            relation_effects = {
                relation_key: effect_status for relation_key in value_records
            }
        else:
            effect_status = "post_read_failed"
            relation_effects = {
                relation_key: effect_status for relation_key in value_records
            }

    successful_relation_count = 0
    defect_relation_count = 0
    for relation_key, record in value_records.items():
        relation_effect = relation_effects.get(relation_key, effect_status)
        effect_after_error = bool(
            not consumer_evidence.get("ok") and relation_effect == "delete_observed"
        )
        if effect_after_error:
            relation_status = "mutation_effect_after_error"
            defect_relation_count += 1
        elif host_scope_approval:
            relation_status = "host_scope_approval_required"
        elif not consumer_evidence.get("ok"):
            relation_status = consumer_failure_status
        elif mutation and relation_effect == "delete_observed":
            relation_status = "mutation_verified"
        elif mutation:
            relation_status = "mutation_accepted"
        else:
            relation_status = "verified"
        if relation_status in {
                "verified", "mutation_verified", "mutation_accepted", "mutation_effect_after_error"}:
            successful_relation_count += 1
        relation_results[relation_key] = {
            "relation_id": relation_key,
            "canonical_name": str(record["mapping"].get("canonical_name") or ""),
            "validation_status": relation_status,
            "value_source": record["value_source"],
            "target_position": positions.get(relation_key) or record["mapping"].get("target_position"),
            "effect_status": relation_effect,
            **record["summary"],
        }
    unresolved_count = len(relation_results) - successful_relation_count
    if successful_relation_count and unresolved_count:
        status = "partially_verified"
    elif defect_relation_count:
        status = "mutation_effect_after_error"
    elif host_scope_approval:
        status = "host_scope_approval_required"
    elif not consumer_evidence.get("ok"):
        status = consumer_failure_status
    elif mutation and effect_status == "delete_observed":
        status = "mutation_verified"
    elif mutation:
        status = "mutation_accepted"
    else:
        status = "verified"
    aggregate_summary = {
        "value_digest": _stable_hash({
            key: record["summary"].get("value_digest") for key, record in value_records.items()
        }),
        "value_type": (
            next(iter(value_records.values()))["summary"].get("value_type", "")
            if len(value_records) == 1 else "mapping"
        ),
        "value_length": sum(
            int(record["summary"].get("value_length") or 0) for record in value_records.values()
        ),
    }
    authorization_resource_matches = sum(
        1 for record in value_records.values()
        if consumer_json is not None
        and _response_contains_value(consumer_json, record["value"])
    )
    effect_after_error = bool(defect_relation_count)
    report_progress(
        "writing_results",
        "请求执行完成，正在逐字段写回验证结论与证据。",
        request_count=request_count,
        status_code=consumer_evidence.get("status_code"),
    )
    return {
        # The relation itself is established when a DELETE effect is observed
        # even if the mutation returned a timeout/5xx.  Preserve the transport
        # problem separately so the UI can flag it as an API defect.
        "ok": bool(consumer_evidence.get("ok") or effect_after_error),
        "validation_status": status,
        "status_code": consumer_evidence.get("status_code"),
        "source_status_code": source_evidence.get("status_code"),
        "consumer_status_code": consumer_evidence.get("status_code"),
        "elapsed_ms": (source_evidence.get("elapsed_ms") or 0) + (consumer_evidence.get("elapsed_ms") or 0),
        "response_len": consumer_evidence.get("response_len") or 0,
        "response_sha256": consumer_evidence.get("response_sha256") or "",
        "response_content_type": consumer_evidence.get("response_content_type") or "",
        "response_json_type": consumer_evidence.get("response_json_type") or "",
        "domain": selected_consumer_view.domain if selected_consumer_view else "",
        "error_type": "" if effect_after_error else consumer_evidence.get("error_type") or "",
        "consumer_error_type": consumer_evidence.get("error_type") or "",
        "value_source": (
            next(iter(value_records.values()))["value_source"]
            if len({record["value_source"] for record in value_records.values()}) == 1
            else "mixed"
        ),
        "target_position": (
            next(iter(positions.values())) if len(set(positions.values())) == 1 else "multiple"
        ),
        "relation_id": str(plan.get("relation_id") or ""),
        "source_snapshot_id": str(source.id),
        "consumer_snapshot_id": str(consumer.id),
        "source_attempts": source_attempts,
        "consumer_attempts": consumer_attempts,
        "request_count": request_count,
        "effect_status": effect_status,
        "after_source_status_code": after_source_status_code,
        "consumer_method": str(consumer.method or "").upper(),
        "remaining_host_count": remaining_consumer_hosts if host_scope_approval else 0,
        "source_untried_host_count": 0,
        "consumer_untried_host_count": (
            remaining_consumer_hosts
            if not consumer_evidence.get("ok") and not effect_after_error
            else 0
        ),
        "approval_stage": "consumer" if host_scope_approval else "",
        "source_error_summary": _safe_error_summary(
            source_json, source_evidence,
        ),
        "consumer_error_summary": _safe_error_summary(
            None, consumer_evidence,
        ),
        "relation_results": list(relation_results.values()),
        "authorization_matrix_case": bool(plan.get("authorization_matrix_case")),
        "authorization_resource_match_count": authorization_resource_matches,
        "authorization_resource_field_count": len(value_records),
        "authorization_case_key": str(
            (plan.get("authorization_case") or {}).get("case_key") or ""
        ),
        "authorization_policy_key": str(
            (plan.get("authorization_case") or {}).get("policy_key") or ""
        ),
        "authorization_policy_version_id": str(
            (plan.get("authorization_case") or {}).get("policy_version_id") or ""
        ),
        "authorization_policy_version": int(
            (plan.get("authorization_case") or {}).get("policy_version") or 0
        ),
        "resource_owner_principal_id": str(
            (plan.get("authorization_case") or {}).get("resource_owner_principal_id") or ""
        ),
        "subject_principal_id": str(
            (plan.get("authorization_case") or {}).get("subject_principal_id") or ""
        ),
        "authorization_expected_decision": str(
            (plan.get("authorization_case") or {}).get("expected_decision") or ""
        ),
        "authorization_matched_rule_id": str(
            (plan.get("authorization_case") or {}).get("matched_rule_id") or ""
        ),
        "authorization_rule_reason_codes": list(
            (plan.get("authorization_case") or {}).get("reason_codes") or []
        ),
        "authorization_resource_family": str(
            (plan.get("authorization_case") or {}).get("resource_family") or ""
        ),
        "authorization_action": str(
            (plan.get("authorization_case") or {}).get("action") or ""
        ),
        "resource_path": str(plan.get("resource_path") or ""),
        **aggregate_summary,
    }


def judge_parameter_validation(evidence: Dict[str, Any], check_type: str,
                               auth_mode: str):
    status = str(evidence.get("validation_status") or "")
    if status == "verified":
        return "relation_verified", ["parameter_relation_verified"], 0.9
    if status == "mutation_verified":
        return "relation_verified", ["parameter_relation_mutation_verified"], 0.95
    if status == "mutation_effect_after_error":
        return (
            "relation_verified_with_api_defect",
            ["parameter_relation_mutation_verified", "mutation_effect_after_error"],
            0.95,
        )
    if status == "mutation_accepted":
        return "relation_accepted", ["parameter_relation_mutation_accepted"], 0.75
    if status == "partially_verified":
        return "relation_group_partial", ["parameter_relation_group_partially_verified"], 0.7
    if status == "host_scope_approval_required":
        return "approval_required", ["parameter_validation_host_scope_approval_required"], 0.5
    if status in {"source_request_rejected", "consumer_request_rejected"}:
        return (
            "test_data_required",
            ["parameter_validation_request_rejected", status],
            0.2,
        )
    if status in {"source_auth_rejected", "consumer_auth_rejected"}:
        return "auth_rejected", ["parameter_validation_auth_rejected", status], 0.1
    if status in {"source_rate_limited", "consumer_rate_limited"}:
        return "rate_limited", ["parameter_validation_rate_limited", status], 0.1
    if evidence.get("error_type"):
        return "error", ["parameter_validation_error"], 0.0
    return "not_evaluable", [status or "parameter_validation_incomplete"], 0.2


def record_parameter_validation(run: Any, plan_snapshot: request_snapshot,
                                evidence: Dict[str, Any], execution_result: Any,
                                checkpoint: Any) -> parameter_validation_result:
    plan = dict((plan_snapshot.metadata or {}).get("validation_plan") or {})
    source_attempts = list(evidence.get("source_attempts") or [])
    consumer_attempts = list(evidence.get("consumer_attempts") or [])
    attempt_limit = max(1, min(
        int(plan.get("request_budget") or MAX_AUTOMATIC_REQUESTS),
        MAX_APPROVED_REQUESTS,
    ))
    source_host = str(
        next((item.get("host") for item in reversed(source_attempts) if item.get("ok")), "")
        or plan.get("source_host") or ""
    )
    successful_consumer_host = str(
        next((item.get("host") for item in reversed(consumer_attempts) if item.get("ok")), "")
        or plan.get("consumer_host") or ""
    )
    approval_stage = str(evidence.get("approval_stage") or "")
    remaining_host_count = int(evidence.get("remaining_host_count") or 0)
    source_untried_host_count = int(
        evidence.get("source_untried_host_count")
        or (remaining_host_count if approval_stage == "source" else 0)
        or 0
    )
    consumer_untried_host_count = int(
        evidence.get("consumer_untried_host_count")
        or (remaining_host_count if approval_stage == "consumer" else 0)
        or 0
    )
    common_source_result = {
        "status_code": evidence.get("source_status_code"),
        "after_status_code": evidence.get("after_source_status_code"),
        "attempts": source_attempts[:attempt_limit],
        "request_count": int(evidence.get("request_count") or 0),
        "remaining_host_count": (
            remaining_host_count if approval_stage == "source" else 0
        ),
        "untried_host_count": source_untried_host_count,
        "approval_stage": "source" if approval_stage == "source" else "",
        "error_summary": dict(evidence.get("source_error_summary") or {}),
    }
    common_consumer_result = {
        "status_code": evidence.get("consumer_status_code"),
        "response_len": evidence.get("response_len") or 0,
        "response_sha256": evidence.get("response_sha256") or "",
        "attempts": consumer_attempts[:attempt_limit],
        "request_count": int(evidence.get("request_count") or 0),
        "method": str(evidence.get("consumer_method") or plan.get("consumer_method") or ""),
        "error_type": str(evidence.get("consumer_error_type") or evidence.get("error_type") or ""),
        "remaining_host_count": (
            remaining_host_count if approval_stage == "consumer" else 0
        ),
        "untried_host_count": consumer_untried_host_count,
        "approval_stage": "consumer" if approval_stage == "consumer" else "",
        "error_summary": dict(evidence.get("consumer_error_summary") or {}),
    }
    relation_evidence_rows = list(evidence.get("relation_results") or [])
    if not relation_evidence_rows:
        relation_evidence_rows = [{
            "relation_id": str(plan.get("relation_id") or ""),
            "canonical_name": str(plan.get("canonical_name") or ""),
            "validation_status": str(evidence.get("validation_status") or "error"),
            "value_source": str(evidence.get("value_source") or ""),
            "value_digest": str(evidence.get("value_digest") or ""),
            "value_type": str(evidence.get("value_type") or ""),
            "value_length": int(evidence.get("value_length") or 0),
            "target_position": str(evidence.get("target_position") or plan.get("target_position") or ""),
            "effect_status": str(evidence.get("effect_status") or ""),
        }]
    saved_rows = []
    for relation_evidence in relation_evidence_rows:
        relation_id = str(relation_evidence.get("relation_id") or "")
        relation = parameter_relation.objects(id=relation_id).first() if relation_id else None
        case_key = "{}:{}:{}".format(run.id, plan_snapshot.id, relation_id or "unknown")
        row = parameter_validation_result.objects(case_key=case_key).first()
        if not row:
            row = parameter_validation_result(
                parameter=str(
                    relation_evidence.get("canonical_name")
                    or (relation.parameter if relation else "unknown")
                ),
                case_key=case_key,
                relation=relation,
                ctime=utcnow(),
            )
        row.group_key = row.parameter
        row.project_id = run.project_id or ""
        row.env_id = run.env_id or ""
        row.run_id = run.id
        row.execution_result_id = execution_result.id if execution_result else None
        row.req_pathid = relation.req_pathid if relation else plan_snapshot.pathid
        row.res_pathid = relation.res_pathid if relation else None
        row.status = str(relation_evidence.get("validation_status") or "error")
        row.value_source = str(relation_evidence.get("value_source") or "")
        row.value_digest = str(relation_evidence.get("value_digest") or "")
        row.value_type = str(relation_evidence.get("value_type") or "")
        row.value_length = int(relation_evidence.get("value_length") or 0)
        row.target_position = str(relation_evidence.get("target_position") or "")
        row.source_profile_id = str(plan.get("source_profile_id") or "")
        row.consumer_profile_id = str(plan.get("consumer_profile_id") or "")
        row.source_host = source_host
        row.consumer_host = str(
            (consumer_attempts[-1].get("host") if row.status == "mutation_effect_after_error" and consumer_attempts else "")
            or successful_consumer_host
        )
        row.source_snapshot_id = str(plan.get("source_snapshot_id") or "")
        row.consumer_snapshot_id = str(plan.get("consumer_snapshot_id") or "")
        row.source_result = dict(common_source_result)
        row.consumer_result = dict(
            common_consumer_result,
            effect_status=str(relation_evidence.get("effect_status") or evidence.get("effect_status") or ""),
        )
        row.note = "scheduled grouped parameter validation ({} relations)".format(
            len(relation_evidence_rows)
        )
        row.manual_by = run.operator or ""
        row.expires_at = run.expires_at
        row.save()
        saved_rows.append(row)
        if relation:
            successful = row.status in {
                "verified", "mutation_verified", "mutation_accepted", "mutation_effect_after_error",
            }
            relation.feedback_status = "consistent" if successful else "inconclusive"
            relation.feedback_note = "scheduled parameter validation: {}".format(row.status)
            relation.verified = bool(relation.verified or row.status in {
                "verified", "mutation_verified", "mutation_effect_after_error",
            })
            if successful:
                relation.confirmed_schema_fingerprint = relation.schema_fingerprint
                relation.stale_reason = ""
                if (
                    relation.discovery_source == "manual_override"
                    and relation.manual_decision == "stale"
                ):
                    relation.manual_decision = "trusted"
            if row.source_host:
                relation.selected_source_host = row.source_host
            if row.consumer_host and successful:
                relation.selected_consumer_host = row.consumer_host
            relation.preprocess_status = (
                "verified" if row.status in {"verified", "mutation_verified", "mutation_effect_after_error"}
                else "accepted" if row.status == "mutation_accepted"
                else "needs_data" if row.status in {
                    "source_request_rejected", "consumer_request_rejected",
                }
                else "needs_context" if row.status in {
                    "source_auth_rejected", "consumer_auth_rejected",
                }
                else "automatic_failed"
            )
            relation.mtime = utcnow()
            relation.save()
            preprocess_relation(relation, persist=True)
            relation.reload()
            sync_relation_experience(relation)
    return saved_rows[0] if saved_rows else None


def build_parameter_validation_adapter(resolver: Any) -> ExecutionAdapter:
    def replay(snapshot, **kwargs):
        return replay_parameter_validation(snapshot, resolver, **kwargs)

    return ExecutionAdapter(
        adapter_id=ADAPTER_ID,
        adapter_version=ADAPTER_VERSION,
        replay=replay,
        judge=judge_parameter_validation,
        auth_modes=frozenset({"account"}),
        requires_account_context=True,
        supports_mutation=True,
        record=record_parameter_validation,
    )
