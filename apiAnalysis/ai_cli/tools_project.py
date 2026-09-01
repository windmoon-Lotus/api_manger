"""Real project tools exposed to AI sessions.

These wrap the existing read/queue/plan services.  Anything that persists
state is marked ``writes=True`` and goes through the approval gate; read-only
tools stay low-risk.  Mongo is connected lazily only when a project tool is
actually invoked, so ``capabilities`` works on a machine without Mongo.
"""
from __future__ import annotations

from typing import Any, Dict, Optional

from .policy import (
    CAP_DATA_READ,
    CAP_FILESYSTEM_WRITE,
    CAP_PROJECT_READ,
)
from .registry import ToolRegistry, ToolSpec, _jsonable


def _ensure_mongo() -> None:
    from apiAnalysis.main import _ensure_mongo_connection

    _ensure_mongo_connection()


def _doc_to_dict(doc: Any, fields: tuple) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    for name in fields:
        value = getattr(doc, name, None)
        if isinstance(value, (str, int, float, bool)) or value is None:
            result[name] = value
        else:
            result[name] = _jsonable(value)
    if getattr(doc, "id", None) is not None:
        result["id"] = str(doc.id)
    return result


def _chain_candidates(arguments: Dict[str, Any]) -> Dict[str, Any]:
    from apiAnalysis.tool.interface_knowledge import project_chain_candidates

    _ensure_mongo()
    return _jsonable(
        project_chain_candidates(str(arguments.get("project_id") or ""))
    )


def _review_queue(arguments: Dict[str, Any]) -> Dict[str, Any]:
    from apiAnalysis.tool.result_review import get_review_queue, review_target_label

    _ensure_mongo()
    limit = int(arguments.get("limit") or 50)
    rows = get_review_queue(
        project_id=str(arguments.get("project_id") or "") or None,
        run_id=str(arguments.get("run_id") or "") or None,
        limit=max(1, min(200, limit)),
    )
    fields = (
        "project_id",
        "env_id",
        "run_id",
        "case_name",
        "check_type",
        "method",
        "verdict",
        "outcome_class",
        "priority",
        "severity",
        "confidence",
        "reason_codes",
        "evidence_ref",
        "related_pathid",
        "ctime",
    )
    queue = []
    for row in rows:
        item = _doc_to_dict(row, fields)
        item["target"] = review_target_label(row)
        item["run_id"] = str(row.run_id) if getattr(row, "run_id", None) else ""
        queue.append(item)
    return {"count": len(queue), "items": queue}


def _list_plans(arguments: Dict[str, Any]) -> Dict[str, Any]:
    from apiAnalysis.tool.test_plan import list_plans

    _ensure_mongo()
    status = str(arguments.get("status") or "") or None
    rows = list_plans(
        project_id=str(arguments.get("project_id") or ""),
        status=status,
        check_type=str(arguments.get("check_type") or "") or None,
    )
    fields = (
        "name",
        "project_id",
        "env_id",
        "version",
        "status",
        "check_type",
        "adapter_id",
        "adapter_version",
        "auth_mode",
        "auth_profile_id",
        "scope",
        "execution_policy",
        "snapshot_filter",
        "request_budget",
        "description",
        "created_at",
        "updated_at",
    )
    return {"count": len(rows), "items": [_doc_to_dict(row, fields) for row in rows]}


def _analyze_relations(arguments: Dict[str, Any]) -> Dict[str, Any]:
    from apiAnalysis.tool.interface_knowledge import discover_project_relations

    _ensure_mongo()
    changed = arguments.get("changed_pathids")
    if isinstance(changed, (list, tuple)):
        changed = [int(item) for item in changed if str(item).strip()]
    else:
        changed = None
    return _jsonable(
        discover_project_relations(
            str(arguments.get("project_id") or ""),
            changed_pathids=changed,
        )
    )


def _create_plan(arguments: Dict[str, Any]) -> Dict[str, Any]:
    from apiAnalysis.tool.test_plan import create_plan

    _ensure_mongo()
    scope = arguments.get("scope")
    if isinstance(scope, dict):
        scope = dict(scope)
    execution_policy = arguments.get("execution_policy")
    if isinstance(execution_policy, dict):
        execution_policy = dict(execution_policy)
    snapshot_filter = arguments.get("snapshot_filter")
    if isinstance(snapshot_filter, dict):
        snapshot_filter = dict(snapshot_filter)
    plan = create_plan(
        name=str(arguments.get("name") or ""),
        project_id=str(arguments.get("project_id") or ""),
        check_type=str(arguments.get("check_type") or ""),
        env_id=str(arguments.get("env_id") or "") or None,
        adapter_id=str(arguments.get("adapter_id") or "") or None,
        adapter_version=str(arguments.get("adapter_version") or "") or None,
        auth_mode=str(arguments.get("auth_mode") or "inherit"),
        auth_profile_id=str(arguments.get("auth_profile_id") or "") or None,
        scope=scope,
        execution_policy=execution_policy,
        snapshot_filter=snapshot_filter,
        request_budget=arguments.get("request_budget"),
        description=str(arguments.get("description") or "") or None,
        created_by=str(arguments.get("operator") or "ai_cli"),
    )
    fields = (
        "name",
        "project_id",
        "env_id",
        "version",
        "status",
        "check_type",
        "adapter_id",
        "auth_mode",
        "request_budget",
        "created_at",
    )
    return {"plan": _doc_to_dict(plan, fields)}


def _execute_plan(arguments: Dict[str, Any]) -> Dict[str, Any]:
    from apiAnalysis.tool.test_plan import schedule_plan_execution

    _ensure_mongo()
    result = schedule_plan_execution(
        str(arguments.get("plan_id") or ""),
        operator=str(arguments.get("operator") or "ai_cli"),
        run_name=str(arguments.get("run_name") or "") or None,
    )
    return {"scheduled": _jsonable(result)}


def register_project_tools(registry: ToolRegistry) -> None:
    registry.register(ToolSpec(
        name="project.chains",
        description="Build the live project resource-chain view (read-only).",
        parameters={
            "type": "object",
            "properties": {"project_id": {"type": "string"}},
            "required": ["project_id"],
        },
        function=_chain_candidates,
        capability=CAP_PROJECT_READ,
        risk="low",
        provenance="managed",
    ))
    registry.register(ToolSpec(
        name="project.review_queue",
        description="List unresolved review-queue candidates (read-only).",
        parameters={
            "type": "object",
            "properties": {
                "project_id": {"type": "string"},
                "run_id": {"type": "string"},
                "limit": {"type": "integer", "default": 50},
            },
        },
        function=_review_queue,
        capability=CAP_DATA_READ,
        risk="low",
        provenance="managed",
    ))
    registry.register(ToolSpec(
        name="project.list_plans",
        description="List versioned test plans for a project (read-only).",
        parameters={
            "type": "object",
            "properties": {
                "project_id": {"type": "string"},
                "status": {"type": "string"},
                "check_type": {"type": "string"},
            },
            "required": ["project_id"],
        },
        function=_list_plans,
        capability=CAP_PROJECT_READ,
        risk="low",
        provenance="managed",
    ))
    registry.register(ToolSpec(
        name="project.analyze_relations",
        description="Run durable project relation discovery and preprocessing.",
        parameters={
            "type": "object",
            "properties": {
                "project_id": {"type": "string"},
                "changed_pathids": {
                    "type": "array",
                    "items": {"type": "integer"},
                },
            },
            "required": ["project_id"],
        },
        function=_analyze_relations,
        capability=CAP_PROJECT_READ,
        writes=True,
        risk="medium",
        provenance="managed",
    ))
    registry.register(ToolSpec(
        name="project.create_plan",
        description="Create a draft versioned test plan (persists a draft).",
        parameters={
            "type": "object",
            "properties": {
                "name": {"type": "string"},
                "project_id": {"type": "string"},
                "check_type": {"type": "string"},
                "env_id": {"type": "string"},
                "adapter_id": {"type": "string"},
                "adapter_version": {"type": "string"},
                "auth_mode": {"type": "string", "default": "inherit"},
                "auth_profile_id": {"type": "string"},
                "scope": {"type": "object"},
                "execution_policy": {"type": "object"},
                "snapshot_filter": {"type": "object"},
                "request_budget": {"type": "integer"},
                "description": {"type": "string"},
                "operator": {"type": "string"},
            },
            "required": ["name", "project_id", "check_type"],
        },
        function=_create_plan,
        capability=CAP_FILESYSTEM_WRITE,
        writes=True,
        risk="medium",
        provenance="managed",
    ))
    registry.register(ToolSpec(
        name="project.execute_plan",
        description="Create immutable snapshots and enqueue one active plan version.",
        parameters={
            "type": "object",
            "properties": {
                "plan_id": {"type": "string"},
                "operator": {"type": "string"},
                "run_name": {"type": "string"},
            },
            "required": ["plan_id"],
        },
        function=_execute_plan,
        capability=CAP_FILESYSTEM_WRITE,
        writes=True,
        risk="high",
        provenance="managed",
    ))
