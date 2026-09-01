"""Sanitized view models for project routing and execution lifecycle UI."""
from typing import Any, Dict, Iterable, Mapping


def _text(value: Any, limit: int = 240) -> str:
    return str(value or "").replace("\r", " ").replace("\n", " ")[:limit]


def _string_list(values: Iterable[Any], limit: int = 30) -> list:
    return [_text(value, 120) for value in list(values or [])[:limit] if value not in (None, "")]


def safe_auth_context_summary(summary: Mapping[str, Any]) -> Dict[str, Any]:
    summary = summary if isinstance(summary, Mapping) else {}
    return {
        "status": _text(summary.get("status"), 40),
        "provider_id": _text(summary.get("provider_id"), 100),
        "project_id": _text(summary.get("project_id"), 100),
        "env_id": _text(summary.get("env_id"), 100),
        "account_id": _text(summary.get("account_id"), 100),
        "context_ref": _text(summary.get("context_ref"), 100),
        "auth_kind": _text(summary.get("auth_kind"), 80),
        "header_names": _string_list(summary.get("header_names") or []),
        "cookie_names": _string_list(summary.get("cookie_names") or []),
        "allowed_hosts": _string_list(summary.get("allowed_hosts") or []),
        "issued_at": _text(summary.get("issued_at"), 40),
        "expires_at": _text(summary.get("expires_at"), 40),
        "error_type": _text(summary.get("error_type"), 100),
    }


def safe_host_state(host_state: Mapping[str, Any]) -> list:
    host_state = host_state if isinstance(host_state, Mapping) else {}
    result = []
    for item in list(host_state.get("hosts") or [])[:100]:
        if not isinstance(item, Mapping):
            continue
        result.append({
            "host": _text(item.get("host"), 255),
            "transport_errors": int(item.get("transport_errors") or 0),
            "rate_limits": int(item.get("rate_limits") or 0),
            "server_errors": int(item.get("server_errors") or 0),
            "stopped_reason": _text(item.get("stopped_reason"), 100),
        })
    return result


def execution_run_view(run: Any, project_name: str = "") -> Dict[str, Any]:
    summary = getattr(run, "summary", None) or {}
    if not isinstance(summary, Mapping):
        summary = {}
    return {
        "id": _text(getattr(run, "id", ""), 80),
        "name": _text(getattr(run, "name", ""), 240),
        "project_id": _text(getattr(run, "project_id", ""), 100),
        "project_name": _text(project_name, 160),
        "env_id": _text(getattr(run, "env_id", ""), 100),
        "account_id": _text(getattr(run, "account_id", ""), 100),
        "auth_mode": _text(getattr(run, "auth_mode", ""), 40),
        "auth_provider_id": _text(getattr(run, "auth_provider_id", ""), 100),
        "auth_context_ref": _text(
            getattr(run, "auth_context_ref", "") or getattr(run, "account_id", ""), 100,
        ),
        "adapter_id": _text(getattr(run, "adapter_id", ""), 120),
        "adapter_version": _text(getattr(run, "adapter_version", ""), 40),
        "check_type": _text(getattr(run, "check_type", ""), 100),
        "status": _text(getattr(run, "status", ""), 40),
        "total_cases": int(getattr(run, "total_cases", 0) or 0),
        "pending_cases": int(getattr(run, "pending_cases", 0) or 0),
        "running_cases": int(getattr(run, "running_cases", 0) or 0),
        "completed_cases": int(getattr(run, "completed_cases", 0) or 0),
        "failed_cases": int(getattr(run, "failed_cases", 0) or 0),
        "skipped_cases": int(getattr(run, "skipped_cases", 0) or 0),
        "cancelled_cases": int(getattr(run, "cancelled_cases", 0) or 0),
        "dispatch_attempt": int(getattr(run, "dispatch_attempt", 0) or 0),
        "last_error_type": _text(getattr(run, "last_error_type", ""), 100),
        "queued_at": _text(getattr(run, "queued_at", ""), 40),
        "updated_at": _text(getattr(run, "updated_at", ""), 40),
        "started_at": _text(getattr(run, "started_at", ""), 40),
        "finished_at": _text(getattr(run, "finished_at", ""), 40),
        "cluster_count": int(summary.get("cluster_count") or 0),
        "review_candidate_count": int(summary.get("review_candidate_count") or 0),
        "pause_reason": _text(summary.get("pause_reason"), 100),
        "auth_context": safe_auth_context_summary(
            getattr(run, "auth_context_summary", None) or {},
        ),
        "hosts": safe_host_state(getattr(run, "host_state", None) or {}),
    }


def checkpoint_view(checkpoint: Any) -> Dict[str, Any]:
    outcome = getattr(checkpoint, "outcome_summary", None) or {}
    if not isinstance(outcome, Mapping):
        outcome = {}
    status_code = outcome.get("status_code")
    try:
        status_number = int(status_code) if status_code is not None else None
    except (TypeError, ValueError):
        status_number = None
    error_type = _text(
        getattr(checkpoint, "error_type", "") or outcome.get("error_type"),
        100,
    )
    if error_type:
        execution_effect = "传输失败"
        execution_effect_tone = "error"
    elif status_number is None:
        execution_effect = "未收到响应"
        execution_effect_tone = "muted"
    elif 200 <= status_number < 300:
        execution_effect = "业务响应成功"
        execution_effect_tone = "success"
    elif status_number in {401, 403}:
        execution_effect = "认证被拒绝"
        execution_effect_tone = "warning"
    elif status_number == 429:
        execution_effect = "触发限流"
        execution_effect_tone = "warning"
    elif 500 <= status_number < 600:
        execution_effect = "服务端异常"
        execution_effect_tone = "error"
    else:
        execution_effect = "已收到响应"
        execution_effect_tone = "muted"
    return {
        "id": _text(getattr(checkpoint, "id", ""), 80),
        "ordinal": int(getattr(checkpoint, "ordinal", 0) or 0),
        "snapshot_id": _text(getattr(checkpoint, "snapshot_id", ""), 80),
        "pathid": getattr(checkpoint, "pathid", None),
        "host": _text(getattr(checkpoint, "host", ""), 255),
        "status": _text(getattr(checkpoint, "status", ""), 40),
        "attempt_count": int(getattr(checkpoint, "attempt_count", 0) or 0),
        "reason_codes": _string_list(getattr(checkpoint, "reason_codes", None) or []),
        "error_type": _text(getattr(checkpoint, "error_type", ""), 100),
        "status_code": status_code,
        "execution_effect": execution_effect,
        "execution_effect_tone": execution_effect_tone,
        "elapsed_ms": outcome.get("elapsed_ms"),
        "response_len": outcome.get("response_len"),
        "response_content_type": _text(outcome.get("response_content_type"), 120),
        "response_json_type": _text(outcome.get("response_json_type"), 40),
        "response_record_count": outcome.get("response_record_count"),
        "response_collection_path": _text(
            outcome.get("response_collection_path"), 160,
        ),
        "response_top_level_keys": _string_list(
            outcome.get("response_top_level_keys") or [], limit=60,
        ),
        "response_field_names": _string_list(
            outcome.get("response_field_names") or [], limit=60,
        ),
        "request_method": _text(outcome.get("request_method"), 20),
        "request_origin": _text(outcome.get("request_origin"), 300),
        "request_path": _text(outcome.get("request_path"), 500),
        "request_query_names": _string_list(
            outcome.get("request_query_names") or [], limit=100,
        ),
        "request_header_names": _string_list(
            outcome.get("request_header_names") or [], limit=100,
        ),
        "request_cookie_names": _string_list(
            outcome.get("request_cookie_names") or [], limit=100,
        ),
        "request_auth_header_names": _string_list(
            outcome.get("request_auth_header_names") or [], limit=100,
        ),
        "request_auth_cookie_names": _string_list(
            outcome.get("request_auth_cookie_names") or [], limit=100,
        ),
        "request_body_bytes": int(outcome.get("request_body_bytes") or 0),
        "request_content_type": _text(
            outcome.get("request_content_type"), 120,
        ),
        "request_timeout_seconds": outcome.get("request_timeout_seconds"),
        "request_allow_redirects": bool(
            outcome.get("request_allow_redirects", False)
        ),
        "request_tls_verify": bool(outcome.get("request_tls_verify", True)),
        "auth_request_count": int(outcome.get("auth_request_count") or 0),
    }


def execution_result_view(result: Any) -> Dict[str, Any]:
    return {
        "id": _text(getattr(result, "id", ""), 80),
        "snapshot_id": _text(getattr(result, "snapshot_id", ""), 80),
        "pathid": getattr(result, "related_pathid", None),
        "case_name": _text(getattr(result, "case_name", ""), 300),
        "check_type": _text(getattr(result, "check_type", ""), 100),
        "method": _text(getattr(result, "method", ""), 20),
        "verdict": _text(getattr(result, "verdict", ""), 60),
        "outcome_class": _text(getattr(result, "outcome_class", ""), 40),
        "priority": _text(getattr(result, "priority", ""), 40),
        "confidence": float(getattr(result, "confidence", 0.0) or 0.0),
        "reason_codes": _string_list(getattr(result, "reason_codes", None) or []),
    }


def routing_decision_view(decision: Mapping[str, Any], observation: Any,
                          project_names: Mapping[str, str]) -> Dict[str, Any]:
    candidates = []
    for candidate in list(decision.get("candidate_projects") or [])[:30]:
        if not isinstance(candidate, Mapping):
            continue
        project_id = _text(candidate.get("project_id"), 100)
        candidates.append({
            "project_id": project_id,
            "project_name": _text(project_names.get(project_id), 160),
            "score": float(candidate.get("score") or 0.0),
            "reason_codes": _string_list(candidate.get("reason_codes") or []),
        })
    return {
        "id": _text(decision.get("_id"), 80),
        "observation_id": _text(decision.get("observation_id"), 100),
        "decision": _text(decision.get("decision"), 40),
        "confidence": float(decision.get("confidence") or 0.0),
        "reason_codes": _string_list(decision.get("reason_codes") or []),
        "selected_project_id": _text(decision.get("selected_project_id"), 100),
        "selected_env_id": _text(decision.get("selected_env_id"), 100),
        "selected_project_name": _text(
            project_names.get(_text(decision.get("selected_project_id"), 100)), 160,
        ),
        "candidates": candidates,
        "method": _text(getattr(observation, "method", ""), 20),
        "domain": _text(getattr(observation, "domain", ""), 255),
        "path": _text(getattr(observation, "path", ""), 500),
        "source_type": _text(getattr(observation, "source_type", ""), 80),
        "source_id": _text(getattr(observation, "source_id", ""), 120),
        "data_source_id": _text(
            getattr(observation, "data_source_id", ""), 100,
        ),
        "workspace_id": _text(getattr(observation, "workspace_id", ""), 100),
        "import_run_id": _text(
            getattr(observation, "import_run_id", ""), 100,
        ),
        "env_id": _text(getattr(observation, "env_id", ""), 100),
        "request_header_names": _string_list(
            (getattr(observation, "request_metadata", None) or {}).get(
                "header_names",
            ) or [],
            limit=100,
        ),
        "request_query_names": _string_list(
            (getattr(observation, "request_metadata", None) or {}).get(
                "query_names",
            ) or [],
            limit=100,
        ),
        "body_shape": (
            getattr(observation, "request_metadata", None) or {}
        ).get("body_shape") or {},
        "response_status": (
            getattr(observation, "response_metadata", None) or {}
        ).get("status"),
        "response_length": int(
            (
                getattr(observation, "response_metadata", None) or {}
            ).get("length") or 0
        ),
        "captured_at": _text(getattr(observation, "captured_at", ""), 40),
        "ctime": _text(decision.get("ctime"), 40),
    }


def source_binding_view(binding: Any, project_name: str = "") -> Dict[str, Any]:
    rules = getattr(binding, "routing_rules", None) or {}
    if not isinstance(rules, Mapping):
        rules = {}
    return {
        "id": _text(getattr(binding, "id", ""), 80),
        "project_id": _text(getattr(binding, "project_id", ""), 100),
        "project_name": _text(project_name, 160),
        "data_source_id": _text(
            getattr(binding, "data_source_id", ""), 100,
        ),
        "source_type": _text(getattr(binding, "source_type", ""), 80),
        "source_id": _text(getattr(binding, "source_id", ""), 160),
        "env_id": _text(getattr(binding, "env_id", ""), 100),
        "workspace_id": _text(getattr(binding, "workspace_id", ""), 100),
        "active": bool(getattr(binding, "active", False)),
        "hosts": _string_list(rules.get("hosts") or [], limit=100),
        "path_prefixes": _string_list(rules.get("path_prefixes") or [], limit=100),
        "signature_count": len(list(rules.get("signatures") or [])),
    }


def data_source_view(source: Any, bindings=None, run_summary=None,
                     observation_summary=None) -> Dict[str, Any]:
    bindings = list(bindings or [])
    run_summary = run_summary if isinstance(run_summary, Mapping) else {}
    observation_summary = (
        observation_summary
        if isinstance(observation_summary, Mapping)
        else {}
    )
    return {
        "data_source_id": _text(
            getattr(source, "data_source_id", ""), 100,
        ),
        "source_type": _text(getattr(source, "source_type", ""), 80),
        "external_id": _text(getattr(source, "external_id", ""), 180),
        "name": _text(getattr(source, "name", ""), 240),
        "workspace_id": _text(getattr(source, "workspace_id", ""), 100),
        "lifecycle": _text(getattr(source, "lifecycle", ""), 40),
        "current_import_run_id": _text(
            getattr(source, "current_import_run_id", ""), 100,
        ),
        "ctime": _text(getattr(source, "ctime", ""), 40),
        "mtime": _text(getattr(source, "mtime", ""), 40),
        "bindings": list(bindings),
        "binding_count": len(bindings),
        "run_count": int(run_summary.get("count") or 0),
        "failed_run_count": int(run_summary.get("failed") or 0),
        "last_run_at": _text(run_summary.get("last_started_at"), 40),
        "observation_count": int(observation_summary.get("count") or 0),
        "last_observed_at": _text(
            observation_summary.get("last_captured_at"), 40,
        ),
    }


def import_run_view(run: Any, source_name: str = "",
                    project_names: Mapping[str, str] = None) -> Dict[str, Any]:
    project_names = project_names or {}
    summary = getattr(run, "summary", None) or {}
    if not isinstance(summary, Mapping):
        summary = {}
    project_ids = list(
        dict.fromkeys(
            [
                str(item)
                for item in (
                    list(getattr(run, "project_ids", None) or [])
                    + [getattr(run, "project_id", "")]
                )
                if item
            ]
        )
    )
    return {
        "import_run_id": _text(getattr(run, "import_run_id", ""), 100),
        "data_source_id": _text(
            getattr(run, "data_source_id", ""), 100,
        ),
        "source_name": _text(source_name, 240),
        "source_type": _text(getattr(run, "source_type", ""), 80),
        "source_id": _text(getattr(run, "source_id", ""), 180),
        "status": _text(getattr(run, "status", ""), 40),
        "project_ids": project_ids,
        "projects": [
            {
                "project_id": project_id,
                "project_name": _text(
                    project_names.get(project_id), 160,
                ),
            }
            for project_id in project_ids
        ],
        "env_id": _text(getattr(run, "env_id", ""), 100),
        "asset_count": int(summary.get("asset_count") or 0),
        "observation_count": int(summary.get("observation_count") or 0),
        "parameter_analysis": bool(summary.get("parameter_analysis")),
        "error_summary": _text(
            getattr(run, "error_summary", ""), 500,
        ),
        "started_at": _text(getattr(run, "started_at", ""), 40),
        "finished_at": _text(getattr(run, "finished_at", ""), 40),
    }
