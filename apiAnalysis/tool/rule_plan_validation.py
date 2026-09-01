"""Promote offline RuleSpec drafts into bounded validation lifecycle plans.

The source drafts remain immutable, non-executable candidates.  Promotion only
selects their explicit path scope and delegates network execution to the
readback/cleanup lifecycle adapter.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Dict, Mapping, Tuple

from apiAnalysis.db.collection import raw_data, security_test_plan
from apiAnalysis.tool.apifox_mutation_lifecycle import (
    MutationLifecycleLimits,
    MutationLifecyclePlan,
    build_mutation_lifecycle_plan,
    enqueue_mutation_lifecycle,
    mutation_lifecycle_report,
)


SCHEMA_VERSION = "rule-draft-validation.v1"
SOURCE_ADAPTER_ID = "rule_plan_draft_only"


class RuleDraftValidationError(RuntimeError):
    pass


@dataclass(frozen=True)
class RuleDraftValidationPlan:
    project_id: str
    env_id: str
    profile_revision_id: str
    source_draft_ids: Tuple[str, ...]
    source_draft_sha256: Tuple[str, ...]
    source_pathids: Tuple[int, ...]
    selected_mutation_pathids: Tuple[int, ...]
    lifecycle_plan: MutationLifecyclePlan
    promotion_sha256: str


def _sha256(value: Any) -> str:
    encoded = json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
        default=lambda item: str(item),
    )
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def build_rule_draft_validation_plan(
        project_id: str, env_id: str, profile_revision_id: str, *,
        preflight_only: bool = True, max_drafts: int = 500,
        selected_pathids: Tuple[int, ...] = (), archive_value_index: int = 0,
        lifecycle_limits: MutationLifecycleLimits = MutationLifecycleLimits(),
) -> RuleDraftValidationPlan:
    project_id = str(project_id or "").strip()
    env_id = str(env_id or "").strip()
    profile_revision_id = str(profile_revision_id or "").strip()
    if not project_id or not env_id or not profile_revision_id:
        raise RuleDraftValidationError(
            "project_id, env_id and profile_revision_id are required"
        )
    drafts = list(security_test_plan.objects(
        project_id=project_id, env_id=env_id, status=security_test_plan.DRAFT,
        adapter_id=SOURCE_ADAPTER_ID,
    ).order_by("id"))
    if not drafts:
        raise RuleDraftValidationError("no offline RuleSpec drafts are available")
    if len(drafts) > int(max_drafts):
        raise RuleDraftValidationError(
            "rule draft budget exceeded: {} > {}".format(len(drafts), max_drafts)
        )
    invalid = [item for item in drafts if bool((item.scope or {}).get("execution_allowed"))]
    if invalid:
        raise RuleDraftValidationError("a source rule draft unexpectedly allows execution")

    pathids = tuple(sorted({
        int(value) for item in drafts for value in ((item.scope or {}).get("pathids") or [])
    }))
    methods = {"PUT", "PATCH"} if preflight_only else {"POST", "PUT", "PATCH"}
    mutation_pathids = tuple(sorted(
        int(item.ptah_id) for item in raw_data.objects(
            project_id=project_id, ptah_id__in=list(pathids), method__in=sorted(methods),
        ).only("ptah_id")
    ))
    if selected_pathids:
        requested = {int(value) for value in selected_pathids}
        if requested - set(pathids):
            raise RuleDraftValidationError("selected pathids are outside the source draft scope")
        mutation_pathids = tuple(value for value in mutation_pathids if value in requested)
    if not mutation_pathids:
        raise RuleDraftValidationError("rule drafts contain no supported mutation interfaces")
    lifecycle = build_mutation_lifecycle_plan(
        project_id, env_id, profile_revision_id,
        pathids=mutation_pathids, preflight_only=preflight_only,
        archive_value_index=archive_value_index,
        limits=lifecycle_limits,
    )
    draft_hashes = tuple(sorted(
        str((item.scope or {}).get("draft_sha256") or "") for item in drafts
    ))
    promotion_sha256 = _sha256({
        "schema_version": SCHEMA_VERSION,
        "project_id": project_id, "env_id": env_id,
        "profile_revision_id": profile_revision_id,
        "source_draft_ids": [str(item.id) for item in drafts],
        "source_draft_sha256": draft_hashes,
        "source_pathids": pathids,
        "selected_mutation_pathids": mutation_pathids,
        "lifecycle_plan_sha256": lifecycle.plan_sha256,
        "preflight_only": bool(preflight_only),
        "archive_value_index": int(archive_value_index),
    })
    return RuleDraftValidationPlan(
        project_id=project_id, env_id=env_id,
        profile_revision_id=profile_revision_id,
        source_draft_ids=tuple(str(item.id) for item in drafts),
        source_draft_sha256=draft_hashes, source_pathids=pathids,
        selected_mutation_pathids=mutation_pathids,
        lifecycle_plan=lifecycle, promotion_sha256=promotion_sha256,
    )


def rule_draft_validation_report(
        plan: RuleDraftValidationPlan, *, mode: str = "dry_run",
        execution_report: Mapping[str, Any] = None,
) -> Dict[str, Any]:
    lifecycle = mutation_lifecycle_report(plan.lifecycle_plan, mode="dry_run")
    report = {
        "schema_version": SCHEMA_VERSION,
        "mode": mode,
        "status": "queued" if execution_report else "complete",
        "promotion_sha256": plan.promotion_sha256,
        "source": {
            "adapter_id": SOURCE_ADAPTER_ID,
            "draft_count": len(plan.source_draft_ids),
            "pathid_count": len(plan.source_pathids),
            "execution_allowed": False,
        },
        "selection": {
            "mutation_pathid_count": len(plan.selected_mutation_pathids),
            "eligible_candidate_count": len(plan.lifecycle_plan.candidates),
            "preflight_only": bool(plan.lifecycle_plan.preflight_only),
        },
        "lifecycle": lifecycle,
        "safety": {
            "source_drafts_modified": 0,
            "finding_records_created": 0,
            "mutation_requests_planned": 0 if plan.lifecycle_plan.preflight_only else len(plan.lifecycle_plan.candidates),
        },
    }
    if execution_report:
        report["execution"] = dict(execution_report)
    return report


def enqueue_rule_draft_validation(
        plan: RuleDraftValidationPlan, expected_promotion_sha256: str, **kwargs: Any,
) -> Dict[str, Any]:
    if str(expected_promotion_sha256 or "").strip() != plan.promotion_sha256:
        raise RuleDraftValidationError("expected promotion hash does not match the current plan")
    execution = enqueue_mutation_lifecycle(
        plan.lifecycle_plan, plan.lifecycle_plan.plan_sha256, **kwargs,
    )
    return rule_draft_validation_report(plan, mode="queued", execution_report=execution)
