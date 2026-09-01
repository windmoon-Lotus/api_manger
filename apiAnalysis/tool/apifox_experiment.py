"""Plan and execute concurrency-controlled Apifox test-environment experiments."""
from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple
from urllib.parse import urlsplit

from mongoengine.errors import NotUniqueError
from requests.exceptions import InvalidHeader
from requests.utils import check_header_validity

from apiAnalysis.db.collection import (
    ProjectAuthProfile,
    ProjectAuthProfileRevision,
    ProjectEnvironment,
    raw_data,
    request_snapshot,
)
from apiAnalysis.tool.compose_request import build_request_payload, payload_to_snapshot_data
from apiAnalysis.tool.execution_adapter import ExecutionAdapter
from apiAnalysis.tool.execution_contract import ExecutionContext
from apiAnalysis.tool.execution_scheduler import ExecutionPolicy, enqueue_snapshot_batch
from apiAnalysis.tool.project_auth import environment_host_names, profile_context_fields
from apiAnalysis.tool.request_sample_store import save_request_sample
from apiAnalysis.tool.snapshot_runner import replay_snapshot_with_json


APIFOX_EXPERIMENT_SCHEMA_VERSION = "apifox-test-experiment.v1"
APIFOX_EXPERIMENT_ADAPTER_ID = "apifox_test_experiment"
APIFOX_EXPERIMENT_ADAPTER_VERSION = "1"
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
TEST_ENVIRONMENT_TYPES = {"test", "testing", "preprod", "preproduction", "staging", "development", "dev"}
_UNRESOLVED_PATH = re.compile(r"\{[^{}]+\}|(?:^|/):[A-Za-z_][A-Za-z0-9_-]*")
_AUTH_HEADER_NAMES = {
    "authorization", "cookie", "proxy-authorization", "x-api-key", "api-key",
    "x-auth-token", "x-access-token", "access-token", "token", "jwt",
    "session", "sessionid", "x-csrf-token", "x-xsrf-token",
}


class ApifoxExperimentError(RuntimeError):
    pass


@dataclass(frozen=True)
class ApifoxExperimentLimits:
    max_endpoints: int = 50000
    report_sample_limit: int = 20

    def validate(self) -> None:
        if type(self.max_endpoints) is not int or not 1 <= self.max_endpoints <= 100000:
            raise ApifoxExperimentError("max_endpoints is outside the supported budget")
        if type(self.report_sample_limit) is not int or not 0 <= self.report_sample_limit <= 100:
            raise ApifoxExperimentError("report_sample_limit is outside the supported budget")


@dataclass(frozen=True)
class ExperimentCandidate:
    asset_id: str
    pathid: int
    method: str
    host: str
    mutation: bool
    payload_sha256: str
    source_updated_at: str
    payload: Mapping[str, Any]


@dataclass(frozen=True)
class ApifoxExperimentPlan:
    project_id: str
    env_id: str
    profile_revision_id: str
    import_run_id: str
    context: ExecutionContext
    candidates: Tuple[ExperimentCandidate, ...]
    skipped: Mapping[str, int]
    input_watermark_sha256: str
    plan_sha256: str
    limits: ApifoxExperimentLimits


def _sha256(value: Any) -> str:
    encoded = json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
        default=lambda item: {"type": type(item).__name__, "value": str(item)},
    )
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _bounded_rows(queryset: Any, limit: int, label: str) -> List[Any]:
    count = int(queryset.count())
    if count > limit:
        raise ApifoxExperimentError("{} budget exceeded: {} > {}".format(label, count, limit))
    return list(queryset)


def _headers_are_valid(headers: Mapping[str, Any]) -> bool:
    for name, value in dict(headers or {}).items():
        try:
            check_header_validity((str(name), value))
        except (InvalidHeader, TypeError):
            return False
    return True


def _profile_execution_context(project_id: str, env_id: str,
                               profile_revision_id: str) -> Tuple[Any, Any, ExecutionContext]:
    revision = ProjectAuthProfileRevision.objects(
        profile_revision_id=profile_revision_id,
    ).first()
    if revision is None:
        raise ApifoxExperimentError("profile revision was not found")
    profile = ProjectAuthProfile.objects(
        profile_id=revision.profile_id,
        project_id=project_id,
        env_id=env_id,
        active=True,
    ).first()
    if profile is None:
        raise ApifoxExperimentError("profile revision does not belong to the selected project/environment")
    fields = profile_context_fields(profile)
    if fields.get("auth_profile_revision_id") != profile_revision_id:
        raise ApifoxExperimentError("selected profile revision is not the active Profile revision")
    context = ExecutionContext(
        **fields,
        adapter_id=APIFOX_EXPERIMENT_ADAPTER_ID,
        adapter_version=APIFOX_EXPERIMENT_ADAPTER_VERSION,
        plan_version=APIFOX_EXPERIMENT_SCHEMA_VERSION,
    )
    return revision, profile, context


def _environment(project_id: str, env_id: str) -> Any:
    environment = ProjectEnvironment.objects(
        project_id=project_id, env_id=env_id, active=True,
    ).first()
    if environment is None:
        raise ApifoxExperimentError("selected project environment is not active")
    environment_type = str(environment.environment_type or "").strip().lower()
    if environment_type not in TEST_ENVIRONMENT_TYPES:
        raise ApifoxExperimentError("Apifox experiments require an explicit test environment type")
    return environment


def _asset_query(project_id: str, import_run_id: str,
                 pathids: Sequence[int]) -> Dict[str, Any]:
    query: Dict[str, Any] = {"source": "apifox", "project_id": project_id}
    if import_run_id:
        query["import_run_id"] = import_run_id
    if pathids:
        query["ptah_id__in"] = sorted({int(value) for value in pathids})
    return query


def build_apifox_experiment_plan(
        project_id: str, env_id: str, profile_revision_id: str, *,
        import_run_id: str = "", pathids: Sequence[int] = (),
        limits: ApifoxExperimentLimits = ApifoxExperimentLimits(),
) -> ApifoxExperimentPlan:
    """Build a no-write plan for all constructable Apifox methods."""
    project_id = str(project_id or "").strip()
    env_id = str(env_id or "").strip()
    profile_revision_id = str(profile_revision_id or "").strip()
    import_run_id = str(import_run_id or "").strip()
    if not project_id or not env_id or not profile_revision_id:
        raise ApifoxExperimentError("project_id, env_id and profile_revision_id are required")
    limits.validate()
    environment = _environment(project_id, env_id)
    revision, _profile, base_context = _profile_execution_context(
        project_id, env_id, profile_revision_id,
    )
    allowed_hosts = set(environment_host_names(environment))
    if not allowed_hosts:
        raise ApifoxExperimentError("test environment has no allowed Hosts")
    assets = _bounded_rows(
        raw_data.objects(**_asset_query(project_id, import_run_id, pathids)).order_by("ptah_id"),
        limits.max_endpoints,
        "Apifox endpoint",
    )
    skipped = Counter()
    candidates = []
    mutation_count = 0
    for asset in assets:
        asset_env = str(getattr(asset, "env_id", "") or "")
        if asset_env not in {"", env_id}:
            skipped["environment_mismatch"] += 1
            continue
        payload = build_request_payload(
            int(asset.ptah_id),
            account_id=base_context.account_id,
            env_id=env_id,
            project_id=project_id,
            auth_mode="account",
            source="apifox_test_experiment",
        )
        if not payload:
            skipped["request_payload_unavailable"] += 1
            continue
        if not _headers_are_valid(payload.get("headers") or {}):
            skipped["invalid_request_header"] += 1
            continue
        rendered_url = str(payload.get("rendered_url") or payload.get("url") or "")
        parsed = urlsplit(rendered_url)
        host = str(parsed.hostname or "").lower()
        if parsed.scheme not in {"http", "https"} or not host:
            skipped["absolute_url_unavailable"] += 1
            continue
        if host not in allowed_hosts:
            skipped["host_outside_environment"] += 1
            continue
        if _UNRESOLVED_PATH.search(parsed.path or ""):
            skipped["unresolved_path_parameter"] += 1
            continue
        unresolved_required_path = any(
            str(meta.get("position") or "") == "path"
            and bool(meta.get("required"))
            and str(meta.get("source") or "") in {"empty_default", "unresolved"}
            for meta in (payload.get("parameter_sources") or {}).values()
            if isinstance(meta, Mapping)
        )
        if unresolved_required_path:
            skipped["unresolved_path_parameter"] += 1
            continue
        method = str(payload.get("method") or asset.method or "GET").upper()
        mutation = method not in SAFE_METHODS
        mutation_count += int(mutation)
        source_meta = dict(getattr(asset, "source_meta", {}) or {})
        payload_digest = _sha256({
            "method": method,
            "url": rendered_url,
            "query": payload.get("query"),
            "headers": payload.get("headers"),
            "cookies": payload.get("cookies"),
            "body": payload.get("body"),
            "parameter_sources": payload.get("parameter_sources"),
        })
        candidates.append(ExperimentCandidate(
            asset_id=str(asset.id),
            pathid=int(asset.ptah_id),
            method=method,
            host=host,
            mutation=mutation,
            payload_sha256=payload_digest,
            source_updated_at=str(source_meta.get("updated_at") or ""),
            payload=payload,
        ))
    if mutation_count and not bool(environment.allow_mutation):
        raise ApifoxExperimentError("test environment does not allow mutation experiments")
    if not candidates:
        raise ApifoxExperimentError("no constructable Apifox experiment candidates")
    input_watermark = _sha256({
        "project_id": project_id,
        "env_id": env_id,
        "profile_revision_id": profile_revision_id,
        "profile_config_sha256": str(getattr(revision, "config_sha256", "") or ""),
        "import_run_id": import_run_id,
        "candidates": [{
            "asset_id": item.asset_id,
            "pathid": item.pathid,
            "method": item.method,
            "host": item.host,
            "payload_sha256": item.payload_sha256,
            "source_updated_at": item.source_updated_at,
        } for item in candidates],
    })
    plan_hash = _sha256({
        "schema_version": APIFOX_EXPERIMENT_SCHEMA_VERSION,
        "input_watermark_sha256": input_watermark,
        "candidate_pathids": [item.pathid for item in candidates],
        "skipped": dict(sorted(skipped.items())),
    })
    context = ExecutionContext(
        **{
            key: value for key, value in base_context.__dict__.items()
            if key not in {"plan_sha256"}
        },
        plan_sha256=plan_hash,
    )
    return ApifoxExperimentPlan(
        project_id=project_id,
        env_id=env_id,
        profile_revision_id=profile_revision_id,
        import_run_id=import_run_id,
        context=context,
        candidates=tuple(candidates),
        skipped=dict(skipped),
        input_watermark_sha256=input_watermark,
        plan_sha256=plan_hash,
        limits=limits,
    )


def apifox_experiment_report(plan: ApifoxExperimentPlan, *, mode: str,
                             run: Any = None, snapshots_created: int = 0,
                             run_created: bool = False) -> Dict[str, Any]:
    methods = Counter(item.method for item in plan.candidates)
    hosts = Counter(item.host for item in plan.candidates)
    samples = [{
        "candidate_ref_sha256": _sha256({
            "asset_id": item.asset_id,
            "pathid": item.pathid,
            "payload_sha256": item.payload_sha256,
        }),
        "method": item.method,
        "mutation": item.mutation,
    } for item in plan.candidates[:plan.limits.report_sample_limit]]
    database_records_created = int(snapshots_created)
    if run is not None and run_created:
        database_records_created += 1 + len(plan.candidates)
    report = {
        "schema_version": APIFOX_EXPERIMENT_SCHEMA_VERSION,
        "mode": mode,
        "status": "queued" if run is not None else "complete",
        "business_network_requests": 0,
        "database_writes": 0 if run is None else database_records_created,
        "database_records_created": database_records_created,
        "context": {
            "project_id": plan.project_id,
            "env_id": plan.env_id,
            "profile_revision_id": plan.profile_revision_id,
            "import_run_id": plan.import_run_id,
        },
        "input_watermark_sha256": plan.input_watermark_sha256,
        "plan_sha256": plan.plan_sha256,
        "candidates": {
            "count": len(plan.candidates),
            "mutation_count": sum(1 for item in plan.candidates if item.mutation),
            "method_counts": dict(sorted(methods.items())),
            "host_count": len(hosts),
            "host_candidate_counts": sorted(hosts.values(), reverse=True),
            "sample_refs": samples,
        },
        "skipped": dict(sorted(plan.skipped.items())),
    }
    if run is not None:
        report["run"] = {
            "run_id": str(run.id),
            "status": str(run.status or ""),
            "total_cases": int(run.total_cases or 0),
            "adapter_id": str(run.adapter_id or ""),
        }
    return report


def enqueue_apifox_experiment(
        plan: ApifoxExperimentPlan, expected_plan_sha256: str, *,
        max_workers: int = 8, per_host_workers: int = 4,
        min_interval_ms: int = 25, request_timeout_seconds: int = 10,
        lease_seconds: int = 60, max_dispatch_attempts: int = 3,
        operator: str = "",
) -> Dict[str, Any]:
    if str(expected_plan_sha256 or "").strip() != plan.plan_sha256:
        raise ApifoxExperimentError("expected plan hash does not match the current plan")
    snapshots = []
    created = 0
    for candidate in plan.candidates:
        template_key = "apifox-test-experiment:{}:{}".format(plan.plan_sha256, candidate.pathid)
        snapshot = request_snapshot.objects(template_key=template_key).first()
        if snapshot is None:
            snapshot_data = payload_to_snapshot_data(dict(candidate.payload), data=None)
            snapshot_data.update({
                "raw_data": raw_data.objects(pk=candidate.asset_id).first(),
                "source": "apifox_test_experiment",
                "project_id": plan.project_id,
                "import_run_id": plan.import_run_id,
                "env_id": plan.env_id,
                "account_id": plan.context.account_id,
                "auth_mode": "account",
                "auth_provider_id": plan.context.auth_provider_id,
                "auth_context_ref": plan.context.auth_context_ref,
                "auth_profile_revision_id": plan.profile_revision_id,
                "auth_realm_revision_id": plan.context.auth_realm_revision_id,
                "auth_adapter_version_id": plan.context.auth_adapter_version_id,
                "adapter_id": APIFOX_EXPERIMENT_ADAPTER_ID,
                "adapter_version": APIFOX_EXPERIMENT_ADAPTER_VERSION,
                "plan_version": APIFOX_EXPERIMENT_SCHEMA_VERSION,
                "plan_sha256": plan.plan_sha256,
                "template_key": template_key,
            })
            metadata = dict(snapshot_data.get("metadata") or {})
            metadata["apifox_experiment"] = {
                "schema_version": APIFOX_EXPERIMENT_SCHEMA_VERSION,
                "payload_sha256": candidate.payload_sha256,
                "mutation": candidate.mutation,
                "lifecycle_readback_available": False,
                "cleanup_available": False,
            }
            snapshot_data["metadata"] = metadata
            snapshot = request_snapshot(**snapshot_data)
            try:
                snapshot.save(force_insert=True)
                created += 1
            except NotUniqueError:
                snapshot = request_snapshot.objects(template_key=template_key).first()
                if snapshot is None:
                    raise
        snapshots.append(snapshot)
    contains_mutation = any(item.mutation for item in plan.candidates)
    policy = ExecutionPolicy(
        max_workers=max_workers,
        per_host_workers=per_host_workers,
        min_interval_ms=min_interval_ms,
        request_timeout_seconds=request_timeout_seconds,
        lease_seconds=lease_seconds,
        max_dispatch_attempts=max_dispatch_attempts,
        allow_mutation=contains_mutation,
        mutation_acknowledged=contains_mutation,
    )
    run, run_created = enqueue_snapshot_batch(
        name="Apifox test environment experiment",
        check_type="apifox_environment_observation",
        context=plan.context,
        snapshot_ids=[item.id for item in snapshots],
        policy=policy,
        scope={
            "source": "apifox",
            "import_run_id": plan.import_run_id,
            "candidate_count": len(plan.candidates),
            "mutation_count": sum(1 for item in plan.candidates if item.mutation),
            "lifecycle_evidence_required": True,
        },
        operator=operator,
        queue_name="snapshot",
    )
    return apifox_experiment_report(
        plan, mode="queued", run=run, snapshots_created=created,
        run_created=run_created,
    )


def _safe_sample_headers(headers: Mapping[str, Any]) -> Dict[str, Any]:
    return {
        key: value for key, value in dict(headers or {}).items()
        if str(key).strip().lower().replace("_", "-") not in _AUTH_HEADER_NAMES
        and not str(key).strip().lower().endswith("-token")
    }


def _bounded_response_json(value: Any, byte_limit: int = 1900) -> Optional[str]:
    """Return a valid representative JSON subtree, never a truncated document."""
    def shrink(node: Any, *, string_limit: int, dict_limit: int,
               list_limit: int, depth: int = 0) -> Any:
        if depth >= 8:
            return None
        if isinstance(node, dict):
            result = {}
            for key in list(node)[:dict_limit]:
                result[str(key)[:100]] = shrink(
                    node[key], string_limit=string_limit, dict_limit=dict_limit,
                    list_limit=list_limit, depth=depth + 1,
                )
            return result
        if isinstance(node, list):
            return [
                shrink(
                    item, string_limit=string_limit, dict_limit=dict_limit,
                    list_limit=list_limit, depth=depth + 1,
                )
                for item in node[:list_limit]
            ]
        if isinstance(node, str):
            return node[:string_limit]
        if node is None or isinstance(node, (bool, int, float)):
            return node
        return str(node)[:string_limit]

    for string_limit, dict_limit, list_limit in (
        (128, 60, 2), (64, 40, 1), (32, 25, 1), (16, 12, 1), (8, 6, 1),
    ):
        candidate = shrink(
            value, string_limit=string_limit, dict_limit=dict_limit,
            list_limit=list_limit,
        )
        encoded = json.dumps(candidate, ensure_ascii=False, separators=(",", ":"))
        if len(encoded.encode("utf-8")) <= byte_limit:
            return encoded
    return None


def _experiment_replay(snapshot: Any, **kwargs: Any) -> Dict[str, Any]:
    kwargs.setdefault("request_trace_phase", "apifox_experiment")
    evidence, captured_json = replay_snapshot_with_json(snapshot, **kwargs)
    method = str(getattr(snapshot, "method", "") or "").upper()
    mutation = method not in SAFE_METHODS
    evidence["apifox_experiment"] = True
    evidence["mutation_request"] = mutation
    evidence["before_readback_attempted"] = False
    evidence["after_readback_attempted"] = False
    evidence["cleanup_attempted"] = False
    evidence["lifecycle_gap"] = "readback_cleanup_adapter_unavailable" if mutation else ""
    evidence["_captured_json"] = captured_json
    return evidence


def _experiment_judge(evidence: Mapping[str, Any], _check_type: str,
                      _auth_mode: str) -> Tuple[str, List[str], float]:
    if evidence.get("error_type") or evidence.get("error"):
        return "error", ["transport_error"], 0.9
    status = evidence.get("status_code")
    if status is None:
        return "error", ["transport_error"], 0.9
    status = int(status)
    mutation = bool(evidence.get("mutation_request"))
    if status == 429:
        return "not_evaluable", ["rate_limited"], 0.95
    if 500 <= status < 600:
        return "not_evaluable", ["server_error"], 0.85
    if status in {401, 403}:
        return "not_evaluable", ["authenticated_request_rejected"], 0.9
    if status == 404:
        return "not_evaluable", ["test_environment_route_or_fixture_unavailable"], 0.8
    if status in {400, 409, 422}:
        return "not_evaluable", ["request_or_business_validation_observed"], 0.85
    if mutation and 200 <= status < 300:
        return "not_evaluable", ["mutation_response_requires_readback"], 0.95
    if 200 <= status < 400:
        return "not_evaluable", ["test_environment_response_observed"], 0.95
    return "not_evaluable", ["test_environment_response_observed"], 0.75


def _record_experiment_sample(run: Any, snapshot: Any, evidence: Mapping[str, Any],
                              _result: Any, _checkpoint: Any) -> None:
    endpoint = getattr(snapshot, "raw_data", None)
    if endpoint is None:
        return
    captured_json = evidence.get("_captured_json")
    response_body = _bounded_response_json(captured_json) if captured_json is not None else None
    sample = save_request_sample(
        endpoint,
        method=str(snapshot.method or "GET"),
        url=str(snapshot.url or ""),
        path=str(snapshot.path or ""),
        domain=str(snapshot.domain or ""),
        query=dict(snapshot.query or {}),
        headers=_safe_sample_headers(snapshot.headers or {}),
        body=snapshot.body,
        response_status_code=evidence.get("status_code"),
        response_body=response_body,
        project_id=str(run.project_id or ""),
        env_id=str(run.env_id or ""),
        account_id=str(run.account_id or ""),
        import_run_id=str(getattr(snapshot, "import_run_id", "") or ""),
        source="apifox_experiment",
    )
    if sample is not None and response_body is not None and sample.response_sample != response_body:
        sample.response_sample = response_body
        sample.save()
    status = evidence.get("status_code")
    if status is not None:
        raw_data.objects(pk=endpoint.id).update_one(
            add_to_set__response_status_code=int(status),
        )


def build_apifox_experiment_adapter() -> ExecutionAdapter:
    return ExecutionAdapter(
        adapter_id=APIFOX_EXPERIMENT_ADAPTER_ID,
        adapter_version=APIFOX_EXPERIMENT_ADAPTER_VERSION,
        replay=_experiment_replay,
        judge=_experiment_judge,
        auth_modes=frozenset({"account"}),
        requires_account_context=True,
        supports_mutation=True,
        record=_record_experiment_sample,
    )
