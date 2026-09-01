"""Single-shot task surface for external agents (A1 subset).

Each task maps on to one registry tool.  ``--input`` JSON is merged over the
CLI defaults so an external agent can pass a context bundle without new
project-specific flags.
"""
from __future__ import annotations

from typing import Any, Dict, Optional


TASK_TOOL = {
    "analyze-relations": "project.analyze_relations",
    "chain-candidates": "project.chains",
    "review-queue": "project.review_queue",
    "list-plans": "project.list_plans",
    "build-plan": "project.create_plan",
    "execute": "project.execute_plan",
}

TASK_DESCRIPTIONS = {
    "analyze-relations": "Run durable project relation discovery and preprocessing.",
    "chain-candidates": "Build the live project resource-chain view.",
    "review-queue": "List unresolved review-queue candidates.",
    "list-plans": "List versioned test plans for a project.",
    "build-plan": "Create a draft versioned test plan.",
    "execute": "Enqueue one active test plan for execution.",
}

DEFAULT_TASK_ARGUMENTS: Dict[str, Dict[str, Any]] = {
    "analyze-relations": {"project_id": "", "changed_pathids": None},
    "chain-candidates": {"project_id": ""},
    "review-queue": {"project_id": "", "run_id": "", "limit": 50},
    "list-plans": {"project_id": "", "status": "", "check_type": ""},
    "build-plan": {
        "name": "",
        "project_id": "",
        "check_type": "",
        "env_id": "",
        "adapter_id": "",
        "adapter_version": "",
        "auth_mode": "inherit",
        "auth_profile_id": "",
        "scope": None,
        "execution_policy": None,
        "snapshot_filter": None,
        "request_budget": None,
        "description": "",
        "operator": "ai_cli",
    },
    "execute": {"plan_id": "", "operator": "ai_cli", "run_name": ""},
}


def task_names() -> list:
    return sorted(TASK_TOOL)


def task_default_arguments(task_name: str) -> Dict[str, Any]:
    return dict(DEFAULT_TASK_ARGUMENTS.get(task_name) or {})


def merge_task_arguments(
    task_name: str,
    cli_values: Dict[str, Any],
    input_payload: Any,
) -> Dict[str, Any]:
    merged = task_default_arguments(task_name)
    for key, value in (cli_values or {}).items():
        if value not in (None, ""):
            merged[key] = value
    if isinstance(input_payload, dict):
        for key, value in input_payload.items():
            set_value = value
            if isinstance(value, str) and value.strip() == "":
                set_value = ""
            merged[key] = set_value
    return merged
