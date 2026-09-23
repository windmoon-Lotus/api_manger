"""Conservative readback and cleanup lifecycles for Apifox test mutations."""
from __future__ import annotations

import copy
import hashlib
import json
import re
from collections import Counter
from dataclasses import dataclass
from types import SimpleNamespace
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple
from urllib.parse import urlsplit, urlunsplit

from mongoengine.errors import NotUniqueError

from apiAnalysis.db.collection import parameter_archive, raw_data, request_sample, request_snapshot
from apiAnalysis.tool.apifox_experiment import (
    ApifoxExperimentError,
    _bounded_rows,
    _environment,
    _headers_are_valid,
    _profile_execution_context,
)
from apiAnalysis.tool.compose_request import build_request_payload, payload_to_snapshot_data
from apiAnalysis.tool.parameter_sources import MUTATION_BLOCKING_SOURCES
from apiAnalysis.tool.execution_adapter import ExecutionAdapter
from apiAnalysis.tool.execution_contract import ExecutionContext
from apiAnalysis.tool.execution_scheduler import ExecutionPolicy, enqueue_snapshot_batch
from apiAnalysis.tool.project_auth import environment_host_names
from apiAnalysis.tool.snapshot_runner import replay_snapshot_with_json


SCHEMA_VERSION = "apifox-mutation-lifecycle.v1"
ADAPTER_ID = "apifox_mutation_lifecycle"
ADAPTER_VERSION = "1"
UPDATE_METHODS = {"PUT", "PATCH"}
_PARAM = re.compile(r"\{([^{}]+)\}|:([A-Za-z_][A-Za-z0-9_-]*)")


class MutationLifecycleError(RuntimeError):
    pass


@dataclass(frozen=True)
class MutationLifecycleLimits:
    max_assets: int = 50000
    max_candidates: int = 1000
    report_sample_limit: int = 20

    def validate(self) -> None:
        if not 1 <= int(self.max_assets) <= 100000:
            raise MutationLifecycleError("max_assets is outside the supported budget")
        if not 1 <= int(self.max_candidates) <= 10000:
            raise MutationLifecycleError("max_candidates is outside the supported budget")
        if not 0 <= int(self.report_sample_limit) <= 100:
            raise MutationLifecycleError("report_sample_limit is outside the supported budget")


@dataclass(frozen=True)
class LifecycleCandidate:
    strategy: str
    mutation_asset_id: str
    mutation_pathid: int
    mutation_method: str
    readback_pathid: int
    cleanup_pathid: int
    host: str
    id_parameter: str
    mutation_payload: Mapping[str, Any]
    readback_payload: Mapping[str, Any]
    cleanup_payload: Mapping[str, Any]
    candidate_sha256: str


@dataclass(frozen=True)
class MutationLifecyclePlan:
    project_id: str
    env_id: str
    profile_revision_id: str
    context: ExecutionContext
    candidates: Tuple[LifecycleCandidate, ...]
    skipped: Mapping[str, int]
    input_watermark_sha256: str
    plan_sha256: str
    limits: MutationLifecycleLimits
    preflight_only: bool = False
    archive_value_index: int = 0


def _sha256(value: Any) -> str:
    encoded = json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
        default=lambda item: str(item),
    )
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _template_path(value: str) -> str:
    parsed = urlsplit(str(value or ""))
    path = parsed.path if parsed.scheme and parsed.netloc else str(value or "").split("?", 1)[0]
    path = "/" + path.lstrip("/")
    return re.sub(r"\{[^{}]+\}|:[A-Za-z_][A-Za-z0-9_-]*", "{}", path.rstrip("/") or "/")


def _raw_template_path(asset: Any) -> str:
    return _template_path(str(getattr(asset, "path", "") or getattr(asset, "url", "") or ""))


def _payload_ready(payload: Optional[Mapping[str, Any]], allowed_hosts: set) -> Tuple[bool, str]:
    if not payload:
        return False, "request_payload_unavailable"
    rendered = str(payload.get("rendered_url") or payload.get("url") or "")
    parsed = urlsplit(rendered)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return False, "absolute_url_unavailable"
    if str(parsed.hostname).lower() not in allowed_hosts:
        return False, "host_outside_environment"
    if _PARAM.search(parsed.path or ""):
        return False, "unresolved_path_parameter"
    if not _headers_are_valid(payload.get("headers") or {}):
        return False, "invalid_request_header"
    return True, ""


def _compose(pathid: int, project_id: str, env_id: str, account_id: str) -> Optional[Dict[str, Any]]:
    return build_request_payload(
        int(pathid), project_id=project_id, env_id=env_id,
        account_id=account_id, auth_mode="account",
        source="apifox_mutation_lifecycle",
    )


def _param_name(path: str) -> str:
    matches = list(_PARAM.finditer(str(path or "")))
    if len(matches) != 1:
        return ""
    return str(matches[0].group(1) or matches[0].group(2) or "")


def _scalars_for_key(value: Any, names: set) -> List[Any]:
    found = []
    if isinstance(value, dict):
        for key, item in value.items():
            if str(key).lower() in names and item is not None and not isinstance(item, (dict, list)):
                found.append(item)
            found.extend(_scalars_for_key(item, names))
    elif isinstance(value, list):
        for item in value:
            found.extend(_scalars_for_key(item, names))
    return found


def _extract_unique_id(value: Any, parameter: str) -> Optional[Any]:
    base = str(parameter or "").strip().lower()
    names = {base, base.replace("_", ""), "id"}
    if base.endswith("id"):
        names.add(base[:-2] + "_id")
    unique = []
    for item in _scalars_for_key(value, names):
        marker = (type(item).__name__, str(item))
        if marker not in {(type(value).__name__, str(value)) for value in unique}:
            unique.append(item)
    return unique[0] if len(unique) == 1 else None


def _historical_id_shape_ready(asset: Any, project_id: str, env_id: str,
                               account_id: str, parameter: str) -> bool:
    for sample in request_sample.objects(
        raw_data=asset, project_id=project_id, env_id=env_id, account_id=account_id,
        response_status_code__gte=200, response_status_code__lt=300,
    ).order_by("-last_seen"):
        try:
            value = json.loads(sample.response_sample)
        except (TypeError, ValueError):
            continue
        if _extract_unique_id(value, parameter) is not None:
            return True
    return False


def _private_payload(payload: Mapping[str, Any]) -> Dict[str, Any]:
    keys = (
        "pathid", "method", "rendered_url", "url", "path", "domain", "query",
        "headers", "cookies", "path_params", "body", "content_type",
        "expected_status_codes", "parameter_sources",
    )
    return {key: copy.deepcopy(payload.get(key)) for key in keys if key in payload}


def _dynamic_detail_payload(payload: Mapping[str, Any], asset: Any,
                            parameter: str) -> Dict[str, Any]:
    result = _private_payload(payload)
    current = urlsplit(str(result.get("rendered_url") or result.get("url") or ""))
    raw_value = str(getattr(asset, "path", "") or "")
    raw_parsed = urlsplit(raw_value)
    raw_path = raw_parsed.path if raw_parsed.scheme and raw_parsed.netloc else raw_value.split("?", 1)[0]
    if not current.scheme or not current.netloc or not _PARAM.search(raw_path):
        return {}
    template_url = urlunsplit((current.scheme, current.netloc, raw_path, "", ""))
    result["url"] = template_url
    result["rendered_url"] = template_url
    result["path"] = raw_path
    result["domain"] = str(current.hostname or "").lower()
    result["path_params"] = {parameter: "{" + parameter + "}"}
    return result


def _archive_parameter_values(parameter: str, pathids: Sequence[int], *,
                              project_id: str, env_id: str,
                              account_id: str) -> List[Any]:
    values: List[Any] = []
    pathid_set = {int(item) for item in pathids}
    for row in parameter_archive.objects(
        parameter=str(parameter or ""), project_id=project_id,
        env_id=env_id, account_id=account_id,
    ).order_by("id"):
        if not {int(item) for item in (row.req_pathid or [])} & pathid_set:
            continue
        for value in row.req_value or []:
            marker = (type(value).__name__, str(value))
            if marker not in {(type(item).__name__, str(item)) for item in values}:
                values.append(value)
    return values


def _override_path_parameter(payload: Mapping[str, Any], asset: Any,
                             parameter: str, value: Any) -> Dict[str, Any]:
    result = copy.deepcopy(dict(payload))
    current = urlsplit(str(result.get("rendered_url") or result.get("url") or ""))
    raw_path = str(getattr(asset, "path", "") or result.get("path") or "")
    raw_parsed = urlsplit(raw_path)
    if raw_parsed.scheme and raw_parsed.netloc:
        raw_path = raw_parsed.path
    template_url = urlunsplit((current.scheme, current.netloc, raw_path, "", ""))
    result["url"] = template_url
    result["rendered_url"] = template_url
    result["path"] = raw_path
    path_params = dict(result.get("path_params") or {})
    path_params[parameter] = value
    result["path_params"] = path_params
    return _render_resource_payload(result, parameter, value)


def _synthetic_required_parameters(payload: Mapping[str, Any]) -> List[str]:
    return sorted(
        str(name) for name, meta in dict(payload.get("parameter_sources") or {}).items()
        if isinstance(meta, Mapping)
        and bool(meta.get("required"))
        and str(meta.get("source") or "") in MUTATION_BLOCKING_SOURCES
    )


def _update_resource_identity_aligned(mutation_payload: Mapping[str, Any],
                                      read_payload: Mapping[str, Any]) -> bool:
    mutation_url = urlsplit(str(
        mutation_payload.get("rendered_url") or mutation_payload.get("url") or ""
    ))
    read_url = urlsplit(str(read_payload.get("rendered_url") or read_payload.get("url") or ""))
    if (
        mutation_url.scheme.lower(), mutation_url.netloc.lower(), mutation_url.path.rstrip("/") or "/"
    ) != (
        read_url.scheme.lower(), read_url.netloc.lower(), read_url.path.rstrip("/") or "/"
    ):
        return False
    mutation_path = dict(mutation_payload.get("path_params") or {})
    read_path = dict(read_payload.get("path_params") or {})
    for name in set(mutation_path) & set(read_path):
        if str(mutation_path[name]) != str(read_path[name]):
            return False
    mutation_query = dict(mutation_payload.get("query") or {})
    read_query = dict(read_payload.get("query") or {})
    resource_names = {
        name for name in set(mutation_query) & set(read_query)
        if str(name).lower() == "id" or str(name).lower().endswith(("_id", "id", "uuid"))
    }
    return all(str(mutation_query[name]) == str(read_query[name]) for name in resource_names)


def build_mutation_lifecycle_plan(
        project_id: str, env_id: str, profile_revision_id: str, *,
        pathids: Sequence[int] = (),
        preflight_only: bool = False,
        archive_value_index: int = 0,
        limits: MutationLifecycleLimits = MutationLifecycleLimits(),
) -> MutationLifecyclePlan:
    limits.validate()
    project_id = str(project_id or "").strip()
    env_id = str(env_id or "").strip()
    profile_revision_id = str(profile_revision_id or "").strip()
    if not project_id or not env_id or not profile_revision_id:
        raise MutationLifecycleError("project_id, env_id and profile_revision_id are required")
    archive_value_index = int(archive_value_index)
    if not 0 <= archive_value_index <= 100:
        raise MutationLifecycleError("archive_value_index is outside the supported budget")
    try:
        environment = _environment(project_id, env_id)
        revision, _profile, base_context = _profile_execution_context(
            project_id, env_id, profile_revision_id,
        )
    except ApifoxExperimentError as exc:
        raise MutationLifecycleError(str(exc)) from exc
    if not bool(getattr(environment, "allow_mutation", False)):
        raise MutationLifecycleError("selected test environment does not allow mutation lifecycles")
    allowed_hosts = {str(item).lower() for item in environment_host_names(environment)}
    query = raw_data.objects(source="apifox", project_id=project_id).order_by("ptah_id")
    assets = _bounded_rows(query, limits.max_assets, "Apifox endpoint")
    by_template: Dict[str, Dict[str, List[Any]]] = {}
    for asset in assets:
        by_template.setdefault(_raw_template_path(asset), {}).setdefault(
            str(asset.method or "GET").upper(), [],
        ).append(asset)
    selected = {int(value) for value in pathids}
    skipped = Counter()
    candidates: List[LifecycleCandidate] = []
    for mutation in assets:
        method = str(mutation.method or "").upper()
        if method not in UPDATE_METHODS | {"POST"}:
            continue
        if selected and int(mutation.ptah_id) not in selected:
            continue
        if preflight_only and method == "POST":
            skipped["create_preflight_not_applicable"] += 1
            continue
        mutation_payload = _compose(
            mutation.ptah_id, project_id, env_id, base_context.account_id,
        )
        ready, reason = _payload_ready(mutation_payload, allowed_hosts)
        if not ready:
            skipped[reason] += 1
            continue
        body = mutation_payload.get("body")
        if not isinstance(body, dict) or not body:
            skipped["structured_mutation_body_required"] += 1
            continue
        if _synthetic_required_parameters(mutation_payload):
            skipped["synthetic_required_mutation_value"] += 1
            continue
        template = _raw_template_path(mutation)
        strategy = ""
        read_asset = None
        cleanup_asset = None
        parameter = ""
        if method in UPDATE_METHODS:
            reads = by_template.get(template, {}).get("GET", [])
            if len(reads) != 1:
                skipped["unique_same_resource_get_required"] += 1
                continue
            strategy = "update_restore"
            read_asset = reads[0]
            cleanup_asset = mutation
        else:
            detail_template = template.rstrip("/") + "/{}"
            detail_methods = by_template.get(detail_template, {})
            reads = detail_methods.get("GET", [])
            deletes = detail_methods.get("DELETE", [])
            if len(reads) != 1 or len(deletes) != 1:
                skipped["create_detail_get_delete_required"] += 1
                continue
            parameter = _param_name(str(getattr(reads[0], "path", "") or ""))
            if not parameter:
                skipped["single_resource_id_parameter_required"] += 1
                continue
            if not _historical_id_shape_ready(
                mutation, project_id, env_id, base_context.account_id, parameter,
            ):
                skipped["historical_created_id_shape_required"] += 1
                continue
            strategy = "create_cleanup"
            read_asset, cleanup_asset = reads[0], deletes[0]
        read_payload = _compose(read_asset.ptah_id, project_id, env_id, base_context.account_id)
        cleanup_payload = _compose(cleanup_asset.ptah_id, project_id, env_id, base_context.account_id)
        if strategy == "update_restore" and archive_value_index:
            parameter = _param_name(str(getattr(mutation, "path", "") or ""))
            if not parameter:
                skipped["archive_rotation_single_path_parameter_required"] += 1
                continue
            archive_values = _archive_parameter_values(
                parameter, (int(mutation.ptah_id), int(read_asset.ptah_id)),
                project_id=project_id, env_id=env_id,
                account_id=base_context.account_id,
            )
            if archive_value_index >= len(archive_values):
                skipped["archive_rotation_value_unavailable"] += 1
                continue
            value = archive_values[archive_value_index]
            mutation_payload = _override_path_parameter(mutation_payload, mutation, parameter, value)
            read_payload = _override_path_parameter(read_payload or {}, read_asset, parameter, value)
            cleanup_payload = _override_path_parameter(cleanup_payload or {}, cleanup_asset, parameter, value)
        read_ready, read_reason = _payload_ready(read_payload, allowed_hosts)
        cleanup_ready, cleanup_reason = _payload_ready(cleanup_payload, allowed_hosts)
        if strategy == "create_cleanup":
            # The ID placeholder is intentionally unresolved until the POST response.
            read_payload = _dynamic_detail_payload(read_payload or {}, read_asset, parameter)
            cleanup_payload = _dynamic_detail_payload(cleanup_payload or {}, cleanup_asset, parameter)
            read_ready = bool(read_payload and _headers_are_valid(read_payload.get("headers") or {}))
            cleanup_ready = bool(cleanup_payload and _headers_are_valid(cleanup_payload.get("headers") or {}))
            read_reason = "" if read_ready else "readback_payload_unavailable"
            cleanup_reason = "" if cleanup_ready else "cleanup_payload_unavailable"
        if not read_ready:
            skipped[read_reason] += 1
            continue
        if not cleanup_ready:
            skipped[cleanup_reason] += 1
            continue
        if strategy == "update_restore" and not _update_resource_identity_aligned(
            mutation_payload, read_payload,
        ):
            skipped["readback_resource_identity_mismatch"] += 1
            continue
        hosts = {
            str(urlsplit(str(item.get("rendered_url") or item.get("url") or "")).hostname or "").lower()
            for item in (mutation_payload, read_payload, cleanup_payload)
        }
        if len(hosts) != 1 or "" in hosts:
            skipped["single_host_lifecycle_required"] += 1
            continue
        digest = _sha256({
            "strategy": strategy,
            "mutation_pathid": int(mutation.ptah_id),
            "readback_pathid": int(read_asset.ptah_id),
            "cleanup_pathid": int(cleanup_asset.ptah_id),
            "mutation_payload": _private_payload(mutation_payload),
            "readback_payload": _private_payload(read_payload),
            "cleanup_payload": _private_payload(cleanup_payload),
            "id_parameter": parameter,
        })
        candidates.append(LifecycleCandidate(
            strategy=strategy,
            mutation_asset_id=str(mutation.id),
            mutation_pathid=int(mutation.ptah_id),
            mutation_method=method,
            readback_pathid=int(read_asset.ptah_id),
            cleanup_pathid=int(cleanup_asset.ptah_id),
            host=next(iter(hosts)), id_parameter=parameter,
            mutation_payload=_private_payload(mutation_payload),
            readback_payload=_private_payload(read_payload),
            cleanup_payload=_private_payload(cleanup_payload),
            candidate_sha256=digest,
        ))
    if len(candidates) > limits.max_candidates:
        raise MutationLifecycleError(
            "mutation lifecycle candidate budget exceeded: {} > {}".format(
                len(candidates), limits.max_candidates,
            )
        )
    if not candidates:
        raise MutationLifecycleError("no mutation candidates have a complete readback/cleanup contract")
    watermark = _sha256({
        "project_id": project_id, "env_id": env_id,
        "profile_revision_id": profile_revision_id,
        "profile_config_sha256": str(getattr(revision, "config_sha256", "") or ""),
        "candidate_sha256": [item.candidate_sha256 for item in candidates],
    })
    plan_sha256 = _sha256({
        "schema_version": SCHEMA_VERSION,
        "input_watermark_sha256": watermark,
        "candidate_pathids": [item.mutation_pathid for item in candidates],
        "preflight_only": bool(preflight_only),
        "archive_value_index": archive_value_index,
        "skipped": dict(sorted(skipped.items())),
    })
    fields = {key: value for key, value in base_context.__dict__.items() if key not in {
        "adapter_id", "adapter_version", "plan_version", "plan_sha256",
    }}
    context = ExecutionContext(
        **fields, adapter_id=ADAPTER_ID, adapter_version=ADAPTER_VERSION,
        plan_version=SCHEMA_VERSION, plan_sha256=plan_sha256,
    )
    return MutationLifecyclePlan(
        project_id=project_id, env_id=env_id,
        profile_revision_id=profile_revision_id,
        context=context, candidates=tuple(candidates), skipped=dict(skipped),
        input_watermark_sha256=watermark, plan_sha256=plan_sha256, limits=limits,
        preflight_only=bool(preflight_only),
        archive_value_index=archive_value_index,
    )


def mutation_lifecycle_report(plan: MutationLifecyclePlan, *, mode: str,
                              run: Any = None, records_created: int = 0) -> Dict[str, Any]:
    strategies = Counter(item.strategy for item in plan.candidates)
    methods = Counter(item.mutation_method for item in plan.candidates)
    report = {
        "schema_version": SCHEMA_VERSION, "mode": mode,
        "execution_mode": "readback_preflight" if plan.preflight_only else "mutation_lifecycle",
        "status": "queued" if run is not None else "complete",
        "business_network_requests": 0,
        "database_records_created": int(records_created),
        "context": {
            "project_id": plan.project_id, "env_id": plan.env_id,
            "profile_revision_id": plan.profile_revision_id,
        },
        "input_watermark_sha256": plan.input_watermark_sha256,
        "plan_sha256": plan.plan_sha256,
        "candidates": {
            "count": len(plan.candidates),
            "strategy_counts": dict(sorted(strategies.items())),
            "method_counts": dict(sorted(methods.items())),
            "host_count": len({item.host for item in plan.candidates}),
            "sample_refs": [{
                "candidate_ref_sha256": item.candidate_sha256,
                "strategy": item.strategy, "method": item.mutation_method,
            } for item in plan.candidates[:plan.limits.report_sample_limit]],
        },
        "skipped": dict(sorted(plan.skipped.items())),
        "archive_value_index": int(plan.archive_value_index),
    }
    if run is not None:
        report["run"] = {
            "run_id": str(run.id), "status": str(run.status or ""),
            "total_cases": int(run.total_cases or 0),
            "adapter_id": str(run.adapter_id or ""),
        }
    return report


def enqueue_mutation_lifecycle(
        plan: MutationLifecyclePlan, expected_plan_sha256: str, *,
        max_workers: int = 4, per_host_workers: int = 2,
        min_interval_ms: int = 100, request_timeout_seconds: int = 10,
        operator: str = "",
) -> Dict[str, Any]:
    if str(expected_plan_sha256 or "").strip() != plan.plan_sha256:
        raise MutationLifecycleError("expected plan hash does not match the current plan")
    snapshots = []
    created = 0
    for candidate in plan.candidates:
        template_key = "apifox-mutation-lifecycle:{}:{}".format(
            plan.plan_sha256, candidate.mutation_pathid,
        )
        snapshot = request_snapshot.objects(template_key=template_key).first()
        if snapshot is None:
            endpoint = raw_data.objects(pk=candidate.mutation_asset_id).first()
            data = payload_to_snapshot_data(dict(candidate.mutation_payload), data=endpoint)
            data.update({
                "source": "apifox_mutation_lifecycle",
                "project_id": plan.project_id, "env_id": plan.env_id,
                "account_id": plan.context.account_id, "auth_mode": "account",
                "auth_provider_id": plan.context.auth_provider_id,
                "auth_context_ref": plan.context.auth_context_ref,
                "auth_profile_revision_id": plan.profile_revision_id,
                "auth_realm_revision_id": plan.context.auth_realm_revision_id,
                "auth_adapter_version_id": plan.context.auth_adapter_version_id,
                "adapter_id": ADAPTER_ID, "adapter_version": ADAPTER_VERSION,
                "plan_version": SCHEMA_VERSION, "plan_sha256": plan.plan_sha256,
                "template_key": template_key,
            })
            metadata = dict(data.get("metadata") or {})
            metadata["mutation_lifecycle_plan"] = {
                "schema_version": SCHEMA_VERSION,
                "strategy": candidate.strategy,
                "candidate_sha256": candidate.candidate_sha256,
                "id_parameter": candidate.id_parameter,
                "readback_payload": dict(candidate.readback_payload),
                "cleanup_payload": dict(candidate.cleanup_payload),
                "request_budget": 5 if candidate.strategy == "update_restore" else 4,
                "preflight_only": bool(plan.preflight_only),
            }
            data["metadata"] = metadata
            snapshot = request_snapshot(**data)
            try:
                snapshot.save(force_insert=True)
                created += 1
            except NotUniqueError:
                snapshot = request_snapshot.objects(template_key=template_key).first()
                if snapshot is None:
                    raise
        snapshots.append(snapshot)
    policy = ExecutionPolicy(
        max_workers=max_workers, per_host_workers=per_host_workers,
        min_interval_ms=min_interval_ms,
        request_timeout_seconds=request_timeout_seconds,
        allow_mutation=True, mutation_acknowledged=True,
        transport_error_stop=1, rate_limit_stop=1, server_error_stop=1,
        max_dispatch_attempts=1,
    )
    run, run_created = enqueue_snapshot_batch(
        name="Apifox mutation readback and cleanup",
        check_type="apifox_mutation_lifecycle",
        context=plan.context,
        snapshot_ids=[item.id for item in snapshots], policy=policy,
        scope={
            "candidate_count": len(snapshots),
            "readback_required": True, "cleanup_required": True,
        }, operator=operator, queue_name="snapshot",
    )
    records = created + ((1 + len(snapshots)) if run_created else 0)
    return mutation_lifecycle_report(plan, mode="queued", run=run, records_created=records)


def _transient(payload: Mapping[str, Any], source: Any, suffix: str) -> Any:
    data = payload_to_snapshot_data(dict(payload), data=getattr(source, "raw_data", None))
    data["id"] = "{}:{}".format(str(getattr(source, "id", "lifecycle")), suffix)
    data["project_id"] = str(getattr(source, "project_id", "") or "")
    data["env_id"] = str(getattr(source, "env_id", "") or "")
    data["account_id"] = str(getattr(source, "account_id", "") or "")
    data["auth_mode"] = "account"
    return SimpleNamespace(**data)


def _project_restore(template: Any, source: Any) -> Any:
    if isinstance(template, dict):
        if not isinstance(source, dict):
            raise KeyError("restore source is not an object")
        return {key: _project_restore(value, source[key]) for key, value in template.items()}
    if isinstance(template, list):
        raise KeyError("array mutation restore is not automatically supported")
    return copy.deepcopy(source)


def _restore_body(template: Mapping[str, Any], response: Any) -> Optional[Dict[str, Any]]:
    candidates = []
    def visit(node: Any) -> None:
        if isinstance(node, dict):
            try:
                candidates.append(_project_restore(template, node))
            except KeyError:
                pass
            for item in node.values():
                visit(item)
        elif isinstance(node, list):
            for item in node:
                visit(item)
    visit(response)
    unique: Dict[str, Dict[str, Any]] = {_sha256(item): item for item in candidates}
    return next(iter(unique.values())) if len(unique) == 1 else None


def _render_resource_payload(payload: Mapping[str, Any], parameter: str, value: Any) -> Dict[str, Any]:
    result = copy.deepcopy(dict(payload))
    replacement = str(value)
    for key in ("url", "rendered_url", "path"):
        text = str(result.get(key) or "")
        text = re.sub(r"\{" + re.escape(parameter) + r"\}|:" + re.escape(parameter) + r"(?=/|$)", replacement, text)
        result[key] = text
    path_params = dict(result.get("path_params") or {})
    path_params[parameter] = value
    result["path_params"] = path_params
    return result


def _http_ok(evidence: Mapping[str, Any]) -> bool:
    status = evidence.get("status_code")
    return status is not None and 200 <= int(status) < 400 and not evidence.get("error_type")


def _base_evidence(snapshot: Any, strategy: str) -> Dict[str, Any]:
    return {
        "status_code": None, "ok": False, "elapsed_ms": 0,
        "response_len": 0, "response_sha256": "", "response_content_type": "",
        "response_json_type": "", "domain": str(getattr(snapshot, "domain", "") or ""),
        "auth_mode": "account", "request_method": str(getattr(snapshot, "method", "") or ""),
        "mutation_request": True, "lifecycle_strategy": strategy,
        "before_readback_attempted": False, "after_readback_attempted": False,
        "cleanup_attempted": False, "final_readback_attempted": False,
        "restore_payload_ready": False, "created_id_extracted": False,
        "effect_observed": False, "cleanup_verified": False,
        "lifecycle_request_count": 0, "lifecycle_gap": "",
    }


def _copy_primary(evidence: Dict[str, Any], primary: Mapping[str, Any]) -> None:
    for key in (
        "status_code", "ok", "elapsed_ms", "response_len", "response_sha256",
        "response_content_type", "response_json_type", "error_type",
        "response_record_count", "response_collection_path",
        "response_top_level_keys", "response_field_names",
        "request_origin", "request_path", "request_query_names", "request_header_names",
        "request_cookie_names", "request_body_bytes", "request_content_type",
    ):
        if key in primary:
            evidence[key] = primary.get(key)


def _phase_kwargs(kwargs: Mapping[str, Any], phase: str) -> Dict[str, Any]:
    result = dict(kwargs)
    result["request_trace_phase"] = phase
    return result


def replay_mutation_lifecycle(snapshot: Any, **kwargs: Any) -> Dict[str, Any]:
    plan = dict((getattr(snapshot, "metadata", {}) or {}).get("mutation_lifecycle_plan") or {})
    strategy = str(plan.get("strategy") or "")
    evidence = _base_evidence(snapshot, strategy)
    read_payload = dict(plan.get("readback_payload") or {})
    cleanup_payload = dict(plan.get("cleanup_payload") or {})
    runtime_payload = {
        "rendered_url": str(getattr(snapshot, "url", "") or ""),
        "url": str(getattr(snapshot, "url", "") or ""),
        "path_params": dict(getattr(snapshot, "path_params", None) or {}),
        "query": dict(getattr(snapshot, "query", None) or {}),
        "parameter_sources": dict(getattr(snapshot, "parameter_sources", None) or {}),
    }
    if _synthetic_required_parameters(runtime_payload):
        evidence["lifecycle_gap"] = "synthetic_required_mutation_value"
        return evidence
    if strategy == "update_restore":
        if not _update_resource_identity_aligned(runtime_payload, read_payload):
            evidence["lifecycle_gap"] = "readback_resource_identity_mismatch"
            return evidence
        before_snapshot = _transient(read_payload, snapshot, "before")
        evidence["before_readback_attempted"] = True
        before, before_json = replay_snapshot_with_json(
            before_snapshot, **_phase_kwargs(kwargs, "before_readback"),
        )
        evidence["lifecycle_request_count"] += 1
        evidence["before_status_code"] = before.get("status_code")
        if not _http_ok(before) or before_json is None:
            evidence["lifecycle_gap"] = "before_readback_unavailable"
            _copy_primary(evidence, before)
            return evidence
        restore_body = _restore_body(dict(getattr(snapshot, "body", {}) or {}), before_json)
        evidence["restore_payload_ready"] = restore_body is not None
        if restore_body is None:
            evidence["lifecycle_gap"] = "unique_restore_payload_unavailable"
            _copy_primary(evidence, before)
            return evidence
        if bool(plan.get("preflight_only")):
            evidence["lifecycle_gap"] = "preflight_complete_mutation_not_sent"
            _copy_primary(evidence, before)
            return evidence
        mutation, _mutation_json = replay_snapshot_with_json(
            snapshot, **_phase_kwargs(kwargs, "mutation"),
        )
        evidence["lifecycle_request_count"] += 1
        evidence["mutation_status_code"] = mutation.get("status_code")
        _copy_primary(evidence, mutation)
        if not _http_ok(mutation):
            evidence["lifecycle_gap"] = "mutation_not_accepted"
            return evidence
        after_snapshot = _transient(read_payload, snapshot, "after")
        evidence["after_readback_attempted"] = True
        after, after_json = replay_snapshot_with_json(
            after_snapshot, **_phase_kwargs(kwargs, "after_readback"),
        )
        evidence["lifecycle_request_count"] += 1
        evidence["after_status_code"] = after.get("status_code")
        after_body = _restore_body(dict(getattr(snapshot, "body", {}) or {}), after_json)
        if after_body is not None:
            evidence["effect_observed"] = _sha256(after_body) != _sha256(restore_body)
        restore_payload = dict(cleanup_payload)
        restore_payload["body"] = restore_body
        restore_snapshot = _transient(restore_payload, snapshot, "restore")
        evidence["cleanup_attempted"] = True
        cleanup, _cleanup_json = replay_snapshot_with_json(
            restore_snapshot, **_phase_kwargs(kwargs, "cleanup_restore"),
        )
        evidence["lifecycle_request_count"] += 1
        evidence["cleanup_status_code"] = cleanup.get("status_code")
        if not _http_ok(cleanup):
            evidence["lifecycle_gap"] = "restore_request_failed"
            return evidence
        final_snapshot = _transient(read_payload, snapshot, "final")
        evidence["final_readback_attempted"] = True
        final, final_json = replay_snapshot_with_json(
            final_snapshot, **_phase_kwargs(kwargs, "final_readback"),
        )
        evidence["lifecycle_request_count"] += 1
        evidence["final_status_code"] = final.get("status_code")
        final_body = _restore_body(dict(getattr(snapshot, "body", {}) or {}), final_json)
        evidence["cleanup_verified"] = bool(
            _http_ok(final) and final_body is not None
            and _sha256(final_body) == _sha256(restore_body)
        )
        evidence["lifecycle_gap"] = "" if evidence["cleanup_verified"] else "restore_readback_mismatch"
        return evidence

    if strategy == "create_cleanup":
        mutation, mutation_json = replay_snapshot_with_json(
            snapshot, **_phase_kwargs(kwargs, "mutation_create"),
        )
        evidence["lifecycle_request_count"] += 1
        evidence["mutation_status_code"] = mutation.get("status_code")
        _copy_primary(evidence, mutation)
        if not _http_ok(mutation):
            evidence["lifecycle_gap"] = "mutation_not_accepted"
            return evidence
        resource_id = _extract_unique_id(mutation_json, str(plan.get("id_parameter") or ""))
        evidence["created_id_extracted"] = resource_id is not None
        if resource_id is None:
            evidence["lifecycle_gap"] = "created_id_unavailable_cleanup_not_possible"
            return evidence
        read_payload = _render_resource_payload(read_payload, plan["id_parameter"], resource_id)
        cleanup_payload = _render_resource_payload(cleanup_payload, plan["id_parameter"], resource_id)
        after_snapshot = _transient(read_payload, snapshot, "created")
        evidence["after_readback_attempted"] = True
        after, _after_json = replay_snapshot_with_json(
            after_snapshot, **_phase_kwargs(kwargs, "created_readback"),
        )
        evidence["lifecycle_request_count"] += 1
        evidence["after_status_code"] = after.get("status_code")
        evidence["effect_observed"] = _http_ok(after)
        cleanup_snapshot = _transient(cleanup_payload, snapshot, "delete")
        evidence["cleanup_attempted"] = True
        cleanup, _cleanup_json = replay_snapshot_with_json(
            cleanup_snapshot, **_phase_kwargs(kwargs, "cleanup_delete"),
        )
        evidence["lifecycle_request_count"] += 1
        evidence["cleanup_status_code"] = cleanup.get("status_code")
        final_snapshot = _transient(read_payload, snapshot, "final")
        evidence["final_readback_attempted"] = True
        final, _final_json = replay_snapshot_with_json(
            final_snapshot, **_phase_kwargs(kwargs, "final_readback"),
        )
        evidence["lifecycle_request_count"] += 1
        evidence["final_status_code"] = final.get("status_code")
        evidence["cleanup_verified"] = bool(
            _http_ok(cleanup) and final.get("status_code") in {404, 410}
        )
        evidence["lifecycle_gap"] = "" if evidence["cleanup_verified"] else "delete_cleanup_unverified"
        return evidence
    evidence["error_type"] = "MutationLifecyclePlanError"
    evidence["lifecycle_gap"] = "unsupported_lifecycle_strategy"
    return evidence


def judge_mutation_lifecycle(evidence: Mapping[str, Any], _check_type: str,
                             _auth_mode: str) -> Tuple[str, List[str], float]:
    gap = str(evidence.get("lifecycle_gap") or "")
    if evidence.get("error_type"):
        return "error", [gap or "mutation_lifecycle_transport_error"], 0.9
    if gap == "before_readback_unavailable":
        return "not_evaluable", [gap, "mutation_not_sent"], 0.95
    if gap == "unique_restore_payload_unavailable":
        return "not_evaluable", [gap, "mutation_not_sent"], 0.95
    if gap == "preflight_complete_mutation_not_sent":
        return "not_evaluable", [gap, "restore_payload_ready"], 0.99
    if gap == "mutation_not_accepted":
        return "not_evaluable", [gap], 0.9
    if evidence.get("cleanup_verified"):
        reason = (
            "mutation_effect_observed_and_restored"
            if evidence.get("effect_observed") else "mutation_restored_no_effect_observed"
        )
        return "not_evaluable", [reason], 0.98
    if evidence.get("cleanup_attempted") or gap.endswith("cleanup_not_possible"):
        return "need_review", [gap or "mutation_cleanup_unverified"], 0.98
    return "not_evaluable", [gap or "mutation_lifecycle_incomplete"], 0.8


def build_mutation_lifecycle_adapter() -> ExecutionAdapter:
    return ExecutionAdapter(
        adapter_id=ADAPTER_ID, adapter_version=ADAPTER_VERSION,
        replay=replay_mutation_lifecycle, judge=judge_mutation_lifecycle,
        auth_modes=frozenset({"account"}), requires_account_context=True,
        supports_mutation=True,
    )
