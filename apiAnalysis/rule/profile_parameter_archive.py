"""Build provenance-safe parameter archives from bounded request samples.

The planner is offline with respect to business systems.  It performs only
bounded Mongo reads, keeps raw values inside the private ``parameterArchive``
collection, and exposes a value-free report.  Writes require both ``apply``
and the exact plan hash returned by a preceding dry-run.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Mapping, Sequence, Tuple
from urllib.parse import unquote, urlparse

from apiAnalysis.db.collection import (
    ProjectAccountBinding,
    ProjectAuthProfile,
    ProjectAuthProfileRevision,
    ProjectEnvironment,
    parameter_archive,
    parameter_data,
    req_data,
    request_sample,
    res_data,
)
from apiAnalysis.rule.builtin_rules import classify_parameter_category
from apiAnalysis.tool.parameter_identity import (
    occurrence_alias,
    parameter_identity,
    preferred_parameter_name,
)
from apiAnalysis.tool.parameter_locator import extract_values_at_locator


PROFILE_ARCHIVE_REPORT_VERSION = "profile-parameter-archive.v1"
PROFILE_ARCHIVE_SOURCE_KIND = "profile_scoped_request_sample_v1"
_PROFILE_PROPERTY = "profile_scoped_request_sample_v1"
_PATH_PLACEHOLDER = re.compile(r"^(?:\{([^{}]+)\}|:([A-Za-z_][A-Za-z0-9_-]*))$")


class ProfileArchiveError(RuntimeError):
    pass


@dataclass(frozen=True)
class ProfileArchiveLimits:
    max_samples: int = 5000
    max_occurrences: int = 20000
    max_parameter_rows: int = 20000
    max_existing_archives: int = 20000
    max_values_per_archive: int = 100
    max_value_bytes: int = 512
    max_payload_bytes: int = 65536
    report_sample_limit: int = 20

    def validate(self) -> None:
        bounds = {
            "max_samples": (self.max_samples, 1, 50000),
            "max_occurrences": (self.max_occurrences, 1, 100000),
            "max_parameter_rows": (self.max_parameter_rows, 1, 100000),
            "max_existing_archives": (self.max_existing_archives, 1, 100000),
            "max_values_per_archive": (self.max_values_per_archive, 1, 1000),
            "max_value_bytes": (self.max_value_bytes, 1, 8192),
            "max_payload_bytes": (self.max_payload_bytes, 256, 1048576),
            "report_sample_limit": (self.report_sample_limit, 0, 100),
        }
        for name, (value, minimum, maximum) in bounds.items():
            if type(value) is not int or not minimum <= value <= maximum:
                raise ProfileArchiveError("{} is outside the supported budget".format(name))


@dataclass(frozen=True)
class ArchiveOperation:
    identity: str
    parameter: str
    parameterids: Tuple[int, ...]
    req_pathids: Tuple[int, ...]
    res_pathids: Tuple[int, ...]
    req_values: Tuple[Any, ...]
    res_values: Tuple[Any, ...]
    properties: Tuple[str, ...]
    existing_id: str
    before_sha256: str
    action: str


@dataclass(frozen=True)
class ProfileArchivePlan:
    project_id: str
    env_id: str
    profile_revision_id: str
    account_key: str
    input_watermark_sha256: str
    plan_sha256: str
    operations: Tuple[ArchiveOperation, ...]
    stats: Mapping[str, Any]
    blockers: Tuple[str, ...]
    limits: ProfileArchiveLimits

    @property
    def status(self) -> str:
        return "blocked" if self.blockers else "complete"


def _sha256(value: Any) -> str:
    def fallback(item: Any) -> Any:
        if isinstance(item, bytes):
            return {
                "type": "bytes",
                "length": len(item),
                "sha256": hashlib.sha256(item).hexdigest(),
            }
        return {"type": type(item).__name__, "value": str(item)}

    encoded = json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=fallback,
    )
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _bounded_rows(queryset: Any, limit: int, label: str) -> List[Any]:
    count = int(queryset.count())
    if count > limit:
        raise ProfileArchiveError("{} budget exceeded: {} > {}".format(label, count, limit))
    return list(queryset)


def _normalized_pathids(values: Iterable[Any]) -> set:
    result = set()
    pending = list(values or ())
    while pending:
        value = pending.pop()
        if isinstance(value, (list, tuple, set)):
            pending.extend(value)
            continue
        try:
            result.add(int(value))
        except (TypeError, ValueError):
            continue
    return result


def _value_key(value: Any) -> str:
    return json.dumps(
        {"type": type(value).__name__, "value": value},
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _bounded_scalar(value: Any, limits: ProfileArchiveLimits) -> Tuple[bool, Any, str]:
    if value is None or isinstance(value, (dict, tuple, set)):
        return False, None, "non_scalar_value"
    if isinstance(value, list):
        return False, None, "list_value"
    if isinstance(value, bytes):
        return False, None, "binary_value"
    if isinstance(value, float) and not math.isfinite(value):
        return False, None, "non_finite_value"
    if not isinstance(value, (str, int, float, bool)):
        return False, None, "unsupported_value_type"
    if isinstance(value, str) and not value:
        return False, None, "empty_value"
    encoded = str(value).encode("utf-8", errors="ignore")
    if len(encoded) > limits.max_value_bytes:
        return False, None, "oversized_value"
    return True, value, ""


def _flatten_candidate_values(values: Iterable[Any]) -> Iterable[Any]:
    for value in values or ():
        if isinstance(value, list):
            for item in value:
                yield item
        else:
            yield value


def _json_payload(value: Any, limits: ProfileArchiveLimits) -> Any:
    if isinstance(value, (dict, list)):
        try:
            size = len(json.dumps(value, ensure_ascii=False).encode("utf-8"))
        except (TypeError, ValueError):
            return None
        return value if size <= limits.max_payload_bytes else None
    if isinstance(value, bytes):
        if len(value) > limits.max_payload_bytes:
            return None
        try:
            value = value.decode("utf-8")
        except UnicodeDecodeError:
            return None
    if not isinstance(value, str):
        return None
    if len(value.encode("utf-8", errors="ignore")) > limits.max_payload_bytes:
        return None
    try:
        parsed = json.loads(value)
    except (TypeError, ValueError):
        return None
    return parsed if isinstance(parsed, (dict, list)) else None


def _candidate_names(document: Any) -> Tuple[str, ...]:
    locator = dict(getattr(document, "locator", {}) or {})
    tokens = list(locator.get("tokens") or ())
    leaf = ""
    for token in reversed(tokens):
        if token.get("kind") == "property":
            leaf = str(token.get("value") or "")
            break
    values = (
        str(getattr(document, "parameter", "") or ""),
        str(getattr(document, "canonical_name", "") or ""),
        str(locator.get("raw_path") or ""),
        str(locator.get("canonical_name") or ""),
        leaf,
    )
    result = []
    for value in values:
        if value and value not in result:
            result.append(value)
    return tuple(result)


def _mapping_values(mapping: Any, document: Any, *, case_insensitive: bool) -> List[Any]:
    if not isinstance(mapping, dict):
        return []
    names = _candidate_names(document)
    if case_insensitive:
        lower = {str(key).lower(): key for key in mapping}
        for name in names:
            key = lower.get(name.lower())
            if key is not None:
                return [mapping[key]]
    else:
        for name in names:
            if name in mapping:
                return [mapping[name]]
    identity = parameter_identity(
        getattr(document, "parameter", ""), getattr(document, "canonical_name", ""),
    )
    matches = [value for key, value in mapping.items() if parameter_identity(key) == identity]
    return matches if len(matches) == 1 else []


def _path_values(sample: Any, document: Any) -> List[Any]:
    endpoint = getattr(sample, "raw_data", None)
    template = str(getattr(endpoint, "path", "") or "")
    # request_sample.path is the normalized API template for HAR/flow imports;
    # the concrete captured path remains in the sample URL.
    concrete = urlparse(str(getattr(sample, "url", "") or "")).path
    if not concrete:
        concrete = str(getattr(sample, "path", "") or "")
    template_parts = [part for part in template.split("/") if part != ""]
    concrete_parts = [part for part in concrete.split("/") if part != ""]
    if not template_parts or len(template_parts) != len(concrete_parts):
        return []
    wanted = parameter_identity(
        getattr(document, "parameter", ""), getattr(document, "canonical_name", ""),
    )
    found = []
    for template_part, concrete_part in zip(template_parts, concrete_parts):
        match = _PATH_PLACEHOLDER.fullmatch(template_part)
        if match:
            placeholder = match.group(1) or match.group(2) or ""
            if parameter_identity(placeholder) == wanted:
                concrete_value = unquote(concrete_part)
                if _PATH_PLACEHOLDER.fullmatch(concrete_value):
                    return []
                found.append(concrete_value)
            continue
        if unquote(template_part) != unquote(concrete_part):
            return []
    return found


def _extract_values(document: Any, sample: Any, direction: str,
                    limits: ProfileArchiveLimits) -> Tuple[List[Any], str]:
    locator = dict(getattr(document, "locator", {}) or {})
    if int(locator.get("version") or 0) < 2 or not locator.get("tokens"):
        return [], "missing_typed_locator"
    position = str(getattr(document, "position", "") or locator.get("position") or "").lower()
    if direction == "response":
        if position not in {"", "body"}:
            return [], "unsupported_response_position"
        payload = _json_payload(getattr(sample, "response_sample", None), limits)
        if payload is None:
            return [], "response_json_unavailable"
        return extract_values_at_locator(
            payload, locator, limit=limits.max_values_per_archive,
        ), ""
    if position == "query":
        return _mapping_values(getattr(sample, "query", None), document, case_insensitive=False), ""
    if position == "header":
        return _mapping_values(getattr(sample, "headers", None), document, case_insensitive=True), ""
    if position == "path":
        return _path_values(sample, document), ""
    if position == "cookie":
        return [], "cookie_not_archived"
    if position != "body":
        return [], "unsupported_request_position"
    payload = _json_payload(getattr(sample, "body", None), limits)
    if payload is None:
        return [], "request_json_unavailable"
    return extract_values_at_locator(
        payload, locator, limit=limits.max_values_per_archive,
    ), ""


def _profile_context(project_id: str, env_id: str, profile_revision_id: str) -> Tuple[Any, str, Tuple[str, ...], bool]:
    revision = ProjectAuthProfileRevision.objects(
        profile_revision_id=profile_revision_id,
    ).first()
    if revision is None:
        raise ProfileArchiveError("profile revision was not found")
    profile = ProjectAuthProfile.objects(
        profile_id=revision.profile_id, project_id=project_id, env_id=env_id,
    ).first()
    if profile is None:
        raise ProfileArchiveError("profile revision does not belong to the selected project/environment")
    account_key = str(revision.project_account_key or "")
    if not account_key:
        raise ProfileArchiveError("profile revision has no project account reference")
    refs = {account_key}
    binding = ProjectAccountBinding.objects(
        project_id=project_id, env_id=env_id, account_key=account_key, active=True,
    ).first()
    if binding is not None and str(binding.account_id or ""):
        refs.add(str(binding.account_id))
    environments = list(ProjectEnvironment.objects(
        project_id=project_id, active=True,
    ).only("env_id"))
    if not any(str(item.env_id or "") == env_id for item in environments):
        raise ProfileArchiveError("selected project environment is not active")
    inherit_unset_env = len(environments) == 1 and str(environments[0].env_id or "") == env_id
    return revision, account_key, tuple(sorted(refs)), inherit_unset_env


def _archive_state(row: Any) -> Dict[str, Any]:
    return {
        "parameter": str(getattr(row, "parameter", "") or ""),
        "parameterids": sorted(int(value) for value in (getattr(row, "parameterid", ()) or ())),
        "req_pathids": sorted(_normalized_pathids(getattr(row, "req_pathid", ()) or ())),
        "res_pathids": sorted(_normalized_pathids(getattr(row, "res_pathid", ()) or ())),
        "req_values": list(getattr(row, "req_value", ()) or ()),
        "res_values": list(getattr(row, "res_value", ()) or ()),
        "properties": sorted(str(value) for value in (getattr(row, "properties", ()) or ()) if value),
        "modificator": str(getattr(row, "modificator", "") or ""),
        "project_id": str(getattr(row, "project_id", "") or ""),
        "env_id": str(getattr(row, "env_id", "") or ""),
        "account_id": str(getattr(row, "account_id", "") or ""),
        "profile_revision_id": str(getattr(row, "profile_revision_id", "") or ""),
        "source_kind": str(getattr(row, "source_kind", "") or ""),
        "source_watermark_sha256": str(getattr(row, "source_watermark_sha256", "") or ""),
    }


def _merge_values(existing: Iterable[Any], additions: Iterable[Any], limit: int) -> Tuple[Any, ...]:
    result = []
    seen = set()
    for value in list(existing or ()) + list(additions or ()):
        key = _value_key(value)
        if key in seen:
            continue
        seen.add(key)
        result.append(value)
        if len(result) >= limit:
            break
    return tuple(result)


def build_profile_archive_plan(project_id: str, env_id: str, profile_revision_id: str,
                               limits: ProfileArchiveLimits = ProfileArchiveLimits()) -> ProfileArchivePlan:
    """Read scoped samples and return an immutable, value-bearing in-memory plan."""
    project_id = str(project_id or "").strip()
    env_id = str(env_id or "").strip()
    profile_revision_id = str(profile_revision_id or "").strip()
    if not project_id or not env_id or not profile_revision_id:
        raise ProfileArchiveError("project_id, env_id and profile_revision_id are required")
    limits.validate()
    revision, account_key, account_refs, inherit_unset_env = _profile_context(
        project_id, env_id, profile_revision_id,
    )
    environment_query = {"env_id__in": ["", env_id]} if inherit_unset_env else {"env_id": env_id}
    samples = _bounded_rows(
        request_sample.objects(
            project_id=project_id, account_id__in=list(account_refs), **environment_query,
        ).order_by("id"),
        limits.max_samples,
        "profile-scoped request sample",
    )
    stats = Counter()
    eligible_samples = []
    for sample in samples:
        endpoint = getattr(sample, "raw_data", None)
        sample_env = str(getattr(sample, "env_id", "") or "")
        endpoint_env = str(getattr(endpoint, "env_id", "") or "")
        if endpoint is None or str(getattr(endpoint, "project_id", "") or "") != project_id:
            stats["samples_rejected_endpoint_project"] += 1
            continue
        if sample_env not in ({"", env_id} if inherit_unset_env else {env_id}):
            stats["samples_rejected_environment"] += 1
            continue
        if endpoint_env not in ({"", env_id} if inherit_unset_env else {env_id}):
            stats["samples_rejected_endpoint_environment"] += 1
            continue
        if str(getattr(sample, "account_id", "") or "") not in account_refs:
            stats["samples_rejected_account"] += 1
            continue
        eligible_samples.append(sample)

    endpoint_ids = sorted(
        {getattr(getattr(sample, "raw_data", None), "id", None) for sample in eligible_samples},
        key=str,
    )
    endpoint_ids = [value for value in endpoint_ids if value is not None]
    request_documents = _bounded_rows(
        req_data.objects(raw_data__in=endpoint_ids).order_by("id"),
        limits.max_occurrences,
        "request occurrence",
    ) if endpoint_ids else []
    response_documents = _bounded_rows(
        res_data.objects(raw_data__in=endpoint_ids).order_by("id"),
        limits.max_occurrences,
        "response occurrence",
    ) if endpoint_ids else []
    if len(request_documents) + len(response_documents) > limits.max_occurrences:
        raise ProfileArchiveError("combined parameter occurrence budget exceeded")

    documents_by_endpoint: Dict[Tuple[str, str], List[Any]] = defaultdict(list)
    for direction, documents in (("request", request_documents), ("response", response_documents)):
        for document in documents:
            documents_by_endpoint[(direction, str(getattr(getattr(document, "raw_data", None), "id", "")))].append(document)

    groups: Dict[str, Dict[str, Any]] = {}
    input_samples = []
    for sample in eligible_samples:
        endpoint = getattr(sample, "raw_data", None)
        endpoint_key = str(getattr(endpoint, "id", ""))
        pathid = int(getattr(endpoint, "ptah_id", getattr(sample, "pathid", 0)) or 0)
        input_samples.append({
            "sample_id": str(getattr(sample, "id", "") or ""),
            "sample_signature": str(getattr(sample, "sample_signature", "") or ""),
            "response_hash": str(getattr(sample, "response_hash", "") or ""),
            "pathid": pathid,
            "stored_content_sha256": _sha256({
                "url": str(getattr(sample, "url", "") or ""),
                "query": getattr(sample, "query", None),
                "headers": getattr(sample, "headers", None),
                "body": getattr(sample, "body", None),
                "response_sample": getattr(sample, "response_sample", None),
            }),
        })
        for direction in ("request", "response"):
            for document in documents_by_endpoint.get((direction, endpoint_key), ()):
                identity = parameter_identity(
                    getattr(document, "parameter", ""), getattr(document, "canonical_name", ""),
                )
                if not identity:
                    stats["occurrences_skipped_without_identity"] += 1
                    continue
                name_category = classify_parameter_category(identity)
                if name_category in {"auth_session", "dynamic"}:
                    stats["category_{}_excluded".format(name_category)] += 1
                    continue
                extracted, reason = _extract_values(document, sample, direction, limits)
                if reason:
                    stats["occurrences_skipped_{}".format(reason)] += 1
                    continue
                accepted = []
                for value in _flatten_candidate_values(extracted):
                    valid, normalized, invalid_reason = _bounded_scalar(value, limits)
                    if not valid:
                        stats["values_skipped_{}".format(invalid_reason)] += 1
                        continue
                    accepted.append(normalized)
                if not accepted:
                    stats["occurrences_without_archivable_values"] += 1
                    continue
                category = classify_parameter_category(identity, accepted)
                stats["category_{}_observations".format(category)] += 1
                group = groups.setdefault(identity, {
                    "identity": identity,
                    "aliases": Counter(),
                    "raw_names": set(),
                    "req_pathids": set(),
                    "res_pathids": set(),
                    "req_values": [],
                    "res_values": [],
                })
                alias = occurrence_alias(
                    getattr(document, "parameter", ""), getattr(document, "canonical_name", ""),
                )
                if alias:
                    group["aliases"][alias] += 1
                raw_name = str(getattr(document, "parameter", "") or "")
                if raw_name:
                    group["raw_names"].add(raw_name)
                group["{}_pathids".format("req" if direction == "request" else "res")].add(pathid)
                group["{}_values".format("req" if direction == "request" else "res")].extend(accepted)

    input_watermark = _sha256({
        "project_id": project_id,
        "env_id": env_id,
        "profile_revision_id": profile_revision_id,
        "profile_config_sha256": str(getattr(revision, "config_sha256", "") or ""),
        "samples": input_samples,
    })

    raw_names = sorted({name for group in groups.values() for name in group["raw_names"]})
    parameter_rows = _bounded_rows(
        parameter_data.objects(parameter__in=raw_names),
        limits.max_parameter_rows,
        "parameter metadata",
    ) if raw_names else []
    parameter_ids_by_identity: Dict[str, set] = defaultdict(set)
    for row in parameter_rows:
        identity = parameter_identity(getattr(row, "parameter", ""))
        group = groups.get(identity)
        if group is None:
            continue
        related_pathids = group["req_pathids"] | group["res_pathids"]
        row_pathids = _normalized_pathids(getattr(row, "req_pathid", ()) or ())
        row_pathids.update(_normalized_pathids(getattr(row, "res_pathid", ()) or ()))
        if related_pathids.intersection(row_pathids):
            parameter_ids_by_identity[identity].add(int(row.parameterid))

    existing_rows = _bounded_rows(
        parameter_archive.objects(
            project_id=project_id,
            env_id=env_id,
            account_id=account_key,
            profile_revision_id=profile_revision_id,
            source_kind=PROFILE_ARCHIVE_SOURCE_KIND,
        ),
        limits.max_existing_archives,
        "existing profile archive",
    )
    existing_by_identity: Dict[str, Any] = {}
    for row in existing_rows:
        identity = parameter_identity(getattr(row, "parameter", ""))
        if not identity:
            continue
        if identity in existing_by_identity:
            raise ProfileArchiveError("duplicate profile archive identity detected")
        existing_by_identity[identity] = row

    operations = []
    for identity in sorted(groups):
        group = groups[identity]
        parameterids = tuple(sorted(parameter_ids_by_identity.get(identity, ())))
        if not parameterids:
            stats["groups_without_legacy_parameter_metadata"] += 1
        existing = existing_by_identity.get(identity)
        parameter = str(getattr(existing, "parameter", "") or "") if existing is not None else ""
        parameter = parameter or preferred_parameter_name(identity, group["aliases"])
        existing_req = tuple(getattr(existing, "req_value", ()) or ()) if existing is not None else ()
        existing_res = tuple(getattr(existing, "res_value", ()) or ()) if existing is not None else ()
        req_values = _merge_values(existing_req, group["req_values"], limits.max_values_per_archive)
        res_values = _merge_values(existing_res, group["res_values"], limits.max_values_per_archive)
        req_pathids = tuple(sorted(
            _normalized_pathids(getattr(existing, "req_pathid", ()) or ()) | group["req_pathids"]
        ))
        res_pathids = tuple(sorted(
            _normalized_pathids(getattr(existing, "res_pathid", ()) or ()) | group["res_pathids"]
        ))
        merged_parameterids = tuple(sorted(
            set(parameterids).union(int(value) for value in (getattr(existing, "parameterid", ()) or ()))
        ))
        properties = tuple(sorted(set(
            str(value) for value in (getattr(existing, "properties", ()) or ()) if value
        ).union({_PROFILE_PROPERTY})))
        before_state = _archive_state(existing) if existing is not None else {}
        after_state = {
            "parameter": parameter,
            "parameterids": list(merged_parameterids),
            "req_pathids": list(req_pathids),
            "res_pathids": list(res_pathids),
            "req_values": list(req_values),
            "res_values": list(res_values),
            "properties": list(properties),
            "modificator": PROFILE_ARCHIVE_SOURCE_KIND,
            "project_id": project_id,
            "env_id": env_id,
            "account_id": account_key,
            "profile_revision_id": profile_revision_id,
            "source_kind": PROFILE_ARCHIVE_SOURCE_KIND,
            "source_watermark_sha256": input_watermark,
        }
        action = "create" if existing is None else (
            "unchanged" if before_state == after_state else "update"
        )
        operations.append(ArchiveOperation(
            identity=identity,
            parameter=parameter,
            parameterids=merged_parameterids,
            req_pathids=req_pathids,
            res_pathids=res_pathids,
            req_values=req_values,
            res_values=res_values,
            properties=properties,
            existing_id=str(getattr(existing, "id", "") or ""),
            before_sha256=_sha256(before_state),
            action=action,
        ))

    blockers = []
    if not eligible_samples:
        blockers.append("PROFILE_SCOPED_REQUEST_SAMPLES_UNAVAILABLE")
    elif not operations:
        blockers.append("PROFILE_SCOPED_ARCHIVABLE_VALUES_UNAVAILABLE")
    operation_payload = [{
        "identity": item.identity,
        "parameter": item.parameter,
        "parameterids": item.parameterids,
        "req_pathids": item.req_pathids,
        "res_pathids": item.res_pathids,
        "req_value_digests": tuple(_sha256(_value_key(value)) for value in item.req_values),
        "res_value_digests": tuple(_sha256(_value_key(value)) for value in item.res_values),
        "properties": item.properties,
        "existing_id": item.existing_id,
        "before_sha256": item.before_sha256,
        "action": item.action,
    } for item in operations]
    plan_sha256 = _sha256({
        "schema_version": PROFILE_ARCHIVE_REPORT_VERSION,
        "input_watermark_sha256": input_watermark,
        "operations": operation_payload,
        "blockers": blockers,
    })
    stats.update({
        "request_sample_rows": len(samples),
        "eligible_request_samples": len(eligible_samples),
        "request_occurrence_documents": len(request_documents),
        "response_occurrence_documents": len(response_documents),
        "parameter_metadata_rows": len(parameter_rows),
        "existing_profile_archive_rows": len(existing_rows),
        "legacy_unset_env_inherited": int(inherit_unset_env),
    })
    return ProfileArchivePlan(
        project_id=project_id,
        env_id=env_id,
        profile_revision_id=profile_revision_id,
        account_key=account_key,
        input_watermark_sha256=input_watermark,
        plan_sha256=plan_sha256,
        operations=tuple(operations),
        stats=dict(stats),
        blockers=tuple(blockers),
        limits=limits,
    )


def _operation_state(plan: ProfileArchivePlan, operation: ArchiveOperation) -> Dict[str, Any]:
    return {
        "parameter": operation.parameter,
        "parameterids": list(operation.parameterids),
        "req_pathids": list(operation.req_pathids),
        "res_pathids": list(operation.res_pathids),
        "req_values": list(operation.req_values),
        "res_values": list(operation.res_values),
        "properties": list(operation.properties),
        "modificator": PROFILE_ARCHIVE_SOURCE_KIND,
        "project_id": plan.project_id,
        "env_id": plan.env_id,
        "account_id": plan.account_key,
        "profile_revision_id": plan.profile_revision_id,
        "source_kind": PROFILE_ARCHIVE_SOURCE_KIND,
        "source_watermark_sha256": plan.input_watermark_sha256,
    }


def apply_profile_archive_plan(plan: ProfileArchivePlan, expected_plan_sha256: str) -> int:
    """Apply an exact reviewed plan; fail closed if any input row changed."""
    if plan.blockers:
        raise ProfileArchiveError("blocked profile archive plan cannot be applied")
    if str(expected_plan_sha256 or "").strip() != plan.plan_sha256:
        raise ProfileArchiveError("expected plan hash does not match the current plan")
    writes = 0
    for operation in plan.operations:
        if operation.action == "unchanged":
            continue
        identity_query = {
            "project_id": plan.project_id,
            "env_id": plan.env_id,
            "account_id": plan.account_key,
            "profile_revision_id": plan.profile_revision_id,
            "source_kind": PROFILE_ARCHIVE_SOURCE_KIND,
        }
        if operation.action == "create":
            conflicts = [
                row for row in _bounded_rows(
                    parameter_archive.objects(**identity_query),
                    plan.limits.max_existing_archives,
                    "current profile archive",
                )
                if parameter_identity(getattr(row, "parameter", "")) == operation.identity
            ]
            if conflicts:
                raise ProfileArchiveError("profile archive changed after planning")
            row = parameter_archive()
        else:
            row = parameter_archive.objects(id=operation.existing_id).first()
            if row is None or _sha256(_archive_state(row)) != operation.before_sha256:
                raise ProfileArchiveError("profile archive changed after planning")
        state = _operation_state(plan, operation)
        row.parameter = state["parameter"]
        row.parameterid = state["parameterids"]
        row.req_pathid = state["req_pathids"]
        row.res_pathid = state["res_pathids"]
        row.req_value = state["req_values"]
        row.res_value = state["res_values"]
        row.properties = state["properties"]
        row.modificator = state["modificator"]
        row.project_id = state["project_id"]
        row.env_id = state["env_id"]
        row.account_id = state["account_id"]
        row.profile_revision_id = state["profile_revision_id"]
        row.source_kind = state["source_kind"]
        row.source_watermark_sha256 = state["source_watermark_sha256"]
        row.save()
        writes += 1
    return writes


def profile_archive_report(plan: ProfileArchivePlan, *, mode: str, database_writes: int = 0) -> Dict[str, Any]:
    actions = Counter(item.action for item in plan.operations)
    req_values = sum(len(item.req_values) for item in plan.operations)
    res_values = sum(len(item.res_values) for item in plan.operations)
    samples = [{
        "operation_ref_sha256": _sha256({
            "identity": item.identity,
            "parameter": item.parameter,
            "existing_id": item.existing_id,
        }),
        "action": item.action,
        "request_value_count": len(item.req_values),
        "response_value_count": len(item.res_values),
    } for item in plan.operations[:plan.limits.report_sample_limit]]
    return {
        "schema_version": PROFILE_ARCHIVE_REPORT_VERSION,
        "mode": mode,
        "status": plan.status,
        "blockers": list(plan.blockers),
        "business_network_requests": 0,
        "database_writes": int(database_writes),
        "context": {
            "project_id": plan.project_id,
            "env_id": plan.env_id,
            "profile_revision_id": plan.profile_revision_id,
            "account_ref_sha256": _sha256(plan.account_key),
        },
        "input_watermark_sha256": plan.input_watermark_sha256,
        "plan_sha256": plan.plan_sha256,
        "projection": dict(sorted(plan.stats.items())),
        "operations": {
            "count": len(plan.operations),
            "action_counts": dict(sorted(actions.items())),
            "request_value_count": req_values,
            "response_value_count": res_values,
            "sample_refs": samples,
        },
    }


def generate_profile_parameter_archive(project_id: str, env_id: str, profile_revision_id: str,
                                       *, apply: bool = False, expected_plan_sha256: str = "",
                                       limits: ProfileArchiveLimits = ProfileArchiveLimits()) -> Dict[str, Any]:
    plan = build_profile_archive_plan(project_id, env_id, profile_revision_id, limits)
    if not apply:
        return profile_archive_report(plan, mode="dry_run", database_writes=0)
    writes = apply_profile_archive_plan(plan, expected_plan_sha256)
    return profile_archive_report(plan, mode="applied", database_writes=writes)
