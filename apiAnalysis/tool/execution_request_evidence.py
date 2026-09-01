"""Read-only local inspection of request values used by execution runs."""
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence

from bson import ObjectId

from apiAnalysis.db.collection import (
    request_snapshot,
    security_execution_checkpoint,
    security_test_result,
    security_test_run,
)
from apiAnalysis.tool.apifox_mutation_lifecycle import _transient
from apiAnalysis.tool.request_evidence_preview import request_evidence_preview


class ExecutionRequestEvidenceError(RuntimeError):
    pass


def _phase(snapshot: Any, phase: str, *, payload: Optional[Mapping[str, Any]] = None,
           suffix: str = "inspect", executed: bool = False,
           status_code: Any = None, note: str = "") -> Dict[str, Any]:
    target = _transient(payload, snapshot, suffix) if payload is not None else snapshot
    preview = request_evidence_preview(target, phase=phase)
    preview["executed"] = bool(executed)
    preview["status_code"] = status_code
    if note:
        preview["note"] = note
    return preview


def snapshot_phase_previews(snapshot: Any,
                            evidence: Optional[Mapping[str, Any]] = None) -> List[Dict[str, Any]]:
    """Project stored lifecycle metadata into safe, useful request previews."""
    result = dict(evidence or {})
    plan = dict((getattr(snapshot, "metadata", {}) or {}).get("mutation_lifecycle_plan") or {})
    strategy = str(plan.get("strategy") or "")
    if not strategy:
        return [_phase(
            snapshot, "request", executed=bool(result),
            status_code=result.get("status_code"),
        )]

    readback = dict(plan.get("readback_payload") or {})
    cleanup = dict(plan.get("cleanup_payload") or {})
    if strategy == "update_restore":
        rows = [_phase(
            snapshot, "before_readback", payload=readback, suffix="before-inspect",
            executed=bool(result.get("before_readback_attempted")),
            status_code=result.get("before_status_code"),
        )]
        rows.append(_phase(
            snapshot, "mutation", executed=result.get("mutation_status_code") is not None,
            status_code=result.get("mutation_status_code"),
        ))
        rows.append(_phase(
            snapshot, "after_readback", payload=readback, suffix="after-inspect",
            executed=bool(result.get("after_readback_attempted")),
            status_code=result.get("after_status_code"),
        ))
        rows.append(_phase(
            snapshot, "cleanup_restore", payload=cleanup, suffix="restore-inspect",
            executed=bool(result.get("cleanup_attempted")),
            status_code=result.get("cleanup_status_code"),
            note=(
                "stored template only; the actual before-derived restore body was transient and was not persisted"
            ),
        ))
        rows.append(_phase(
            snapshot, "final_readback", payload=readback, suffix="final-inspect",
            executed=bool(result.get("final_readback_attempted")),
            status_code=result.get("final_status_code"),
        ))
        return rows

    if strategy == "create_cleanup":
        return [
            _phase(
                snapshot, "mutation_create",
                executed=result.get("mutation_status_code") is not None,
                status_code=result.get("mutation_status_code"),
            ),
            _phase(
                snapshot, "created_readback", payload=readback, suffix="created-inspect",
                executed=bool(result.get("after_readback_attempted")),
                status_code=result.get("after_status_code"),
                note="resource id placeholders are resolved only after a successful create response",
            ),
            _phase(
                snapshot, "cleanup_delete", payload=cleanup, suffix="delete-inspect",
                executed=bool(result.get("cleanup_attempted")),
                status_code=result.get("cleanup_status_code"),
                note="resource id placeholders are resolved only after a successful create response",
            ),
            _phase(
                snapshot, "final_readback", payload=readback, suffix="final-inspect",
                executed=bool(result.get("final_readback_attempted")),
                status_code=result.get("final_status_code"),
            ),
        ]
    return [_phase(snapshot, "request", executed=bool(result), status_code=result.get("status_code"))]


def build_run_request_evidence(run_id: str, *, limit: int = 20,
                               ordinals: Sequence[int] = ()) -> Dict[str, Any]:
    try:
        object_id = ObjectId(str(run_id))
    except Exception as exc:
        raise ExecutionRequestEvidenceError("invalid run id") from exc
    run = security_test_run.objects(id=object_id).first()
    if not run:
        raise ExecutionRequestEvidenceError("run not found")
    query: Dict[str, Any] = {"run_id": run.id}
    if ordinals:
        query["ordinal__in"] = sorted(set(int(item) for item in ordinals))
    checkpoints = list(
        security_execution_checkpoint.objects(**query).order_by("ordinal").limit(max(1, min(int(limit), 200)))
    )
    snapshot_ids = [item.snapshot_id for item in checkpoints]
    snapshots = {item.id: item for item in request_snapshot.objects(id__in=snapshot_ids)}
    results = {
        item.snapshot_id: item
        for item in security_test_result.objects(run_id=run.id, snapshot_id__in=snapshot_ids)
    }
    cases = []
    for checkpoint in checkpoints:
        snapshot = snapshots.get(checkpoint.snapshot_id)
        if snapshot is None:
            continue
        result = results.get(checkpoint.snapshot_id)
        evidence = dict(getattr(result, "evidence_summary", {}) or {})
        cases.append({
            "ordinal": int(checkpoint.ordinal),
            "checkpoint_status": str(checkpoint.status or ""),
            "result_verdict": str(getattr(result, "verdict", "") or ""),
            "reason_codes": list(getattr(result, "reason_codes", None) or checkpoint.reason_codes or []),
            "lifecycle_gap": str(evidence.get("lifecycle_gap") or ""),
            "requests": snapshot_phase_previews(snapshot, evidence),
        })
    return {
        "report_version": "1",
        "storage_policy": "read_only_stdout_no_network",
        "run": {
            "id": str(run.id), "name": str(run.name or ""),
            "status": str(run.status or ""), "adapter_id": str(run.adapter_id or ""),
            "check_type": str(run.check_type or ""), "project_id": str(run.project_id or ""),
            "env_id": str(run.env_id or ""), "auth_mode": str(run.auth_mode or ""),
            "total_cases": int(run.total_cases or 0),
        },
        "case_count": len(cases),
        "cases": cases,
    }
