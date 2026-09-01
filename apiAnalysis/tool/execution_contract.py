"""Shared orchestration contract over existing snapshot and result models.

This is intentionally not a request composer. It binds plan/project/auth
metadata to the existing create_request_snapshot -> replay_snapshot chain.
"""
from dataclasses import dataclass
from typing import Any, Dict, Optional

from mongoengine.errors import NotUniqueError

from apiAnalysis.db.collection import security_test_result, security_test_run
from apiAnalysis.tool.compose_request import create_request_snapshot
from apiAnalysis.tool.result_review import project_outcome_class
from apiAnalysis.version import EXECUTION_CONTRACT_VERSION, RESULT_CONTRACT_VERSION


AUTH_MODES = {"anonymous", "account", "inherit", "matrix"}


@dataclass(frozen=True)
class ExecutionResultInput:
    """Normalized, sanitized conclusion accepted by every result writer."""

    case_name: str
    check_type: str
    verdict: str
    target: Optional[Dict[str, Any]] = None
    method: str = ""
    evidence_summary: Optional[Dict[str, Any]] = None
    evidence_ref: str = ""
    reason_codes: Optional[Any] = None
    confidence: float = 0.0
    priority: str = ""
    severity: str = ""
    related_pathid: Optional[int] = None
    execution_key: str = ""

    def validate(self) -> None:
        if not str(self.case_name or "").strip():
            raise ValueError("case_name is required")
        if not str(self.check_type or "").strip():
            raise ValueError("check_type is required")
        if not str(self.verdict or "").strip():
            raise ValueError("verdict is required")
        if self.target is not None and not isinstance(self.target, dict):
            raise ValueError("target must be a dictionary")
        if self.evidence_summary is not None and not isinstance(self.evidence_summary, dict):
            raise ValueError("evidence_summary must be a dictionary")
        if not 0.0 <= float(self.confidence or 0.0) <= 1.0:
            raise ValueError("confidence must be between 0 and 1")
        if self.related_pathid is not None and int(self.related_pathid) < 0:
            raise ValueError("related_pathid must be non-negative")


@dataclass(frozen=True)
class ExecutionContext:
    project_id: str
    env_id: str = ""
    account_id: str = ""
    auth_mode: str = "inherit"
    auth_provider_id: str = ""
    auth_context_ref: str = ""
    auth_profile_revision_id: str = ""
    auth_realm_revision_id: str = ""
    auth_adapter_version_id: str = ""
    adapter_id: str = "snapshot_batch"
    adapter_version: str = "1"
    plan_version: str = ""
    plan_sha256: str = ""
    parent_run_id: Any = None
    retry_of_run_id: Any = None

    def validate(self) -> None:
        if not self.project_id:
            raise ValueError("project_id is required")
        if self.auth_mode not in AUTH_MODES:
            raise ValueError("unsupported auth_mode: {}".format(self.auth_mode))
        if self.auth_mode == "anonymous" and any((
            self.account_id, self.auth_provider_id, self.auth_context_ref,
        )):
            raise ValueError("anonymous execution cannot bind account context")
        if self.auth_mode == "account" and not all((
            self.env_id, self.account_id, self.auth_provider_id,
        )):
            raise ValueError("account auth requires env_id, account_id and auth_provider_id")
        if self.auth_mode == "matrix" and any((
            self.account_id,
            self.auth_provider_id,
            self.auth_context_ref,
            self.auth_profile_revision_id,
            self.auth_realm_revision_id,
            self.auth_adapter_version_id,
        )):
            raise ValueError(
                "matrix execution binds principals per case, not one run-level account"
            )
        if self.auth_mode != "account" and any((self.auth_provider_id, self.auth_context_ref)):
            raise ValueError("auth provider references require account auth_mode")
        version_refs = (
            self.auth_profile_revision_id,
            self.auth_realm_revision_id,
            self.auth_adapter_version_id,
        )
        if self.auth_mode != "account" and any(version_refs):
            raise ValueError("auth version references require account auth_mode")
        if self.auth_provider_id == "auth_recipe" and not all(version_refs):
            raise ValueError("recipe auth requires pinned profile, realm and adapter versions")

    def snapshot_metadata(self) -> Dict[str, str]:
        self.validate()
        return {
            "plan_version": self.plan_version,
            "plan_sha256": self.plan_sha256,
            "adapter_id": self.adapter_id,
            "adapter_version": self.adapter_version,
            "auth_provider_id": self.auth_provider_id,
            "auth_context_ref": self.auth_context_ref,
            "auth_profile_revision_id": self.auth_profile_revision_id,
            "auth_realm_revision_id": self.auth_realm_revision_id,
            "auth_adapter_version_id": self.auth_adapter_version_id,
        }

    def run_fields(self) -> Dict[str, Any]:
        self.validate()
        return {
            "project_id": self.project_id,
            "env_id": self.env_id,
            "account_id": self.account_id,
            "auth_mode": self.auth_mode,
            "auth_provider_id": self.auth_provider_id,
            "auth_context_ref": self.auth_context_ref,
            "auth_profile_revision_id": self.auth_profile_revision_id,
            "auth_realm_revision_id": self.auth_realm_revision_id,
            "auth_adapter_version_id": self.auth_adapter_version_id,
            "adapter_id": self.adapter_id,
            "adapter_version": self.adapter_version,
            "plan_version": self.plan_version,
            "plan_sha256": self.plan_sha256,
            "parent_run_id": self.parent_run_id,
            "retry_of_run_id": self.retry_of_run_id,
        }


def create_execution_snapshot(pathid: int, context: ExecutionContext, source: str = "execution_plan"):
    return create_request_snapshot(
        pathid,
        account_id=context.account_id or None,
        env_id=context.env_id or None,
        project_id=context.project_id,
        auth_mode=context.auth_mode,
        source=source,
        execution_metadata=context.snapshot_metadata(),
    )


def create_execution_run(name: str, check_type: str, context: ExecutionContext,
                         scope: Optional[Dict[str, Any]] = None, evidence_ref: str = "",
                         operator: str = ""):
    run = security_test_run(
        name=name,
        check_type=check_type,
        scope=scope or {},
        evidence_ref=evidence_ref,
        operator=operator,
        source="execution_contract",
        contract_version=EXECUTION_CONTRACT_VERSION,
        status=security_test_run.RUNNING,
        **context.run_fields()
    )
    run.save()
    return run


def record_execution_result_input(run, snapshot, value: ExecutionResultInput):
    """Persist a validated result.v1 value with idempotent execution identity."""
    value.validate()
    if value.execution_key:
        existing = security_test_result.objects(execution_key=value.execution_key).first()
        if existing:
            return existing
    target = {
        "project_id": run.project_id,
        "env_id": run.env_id,
        "account_id": run.account_id or "",
        "auth_mode": run.auth_mode or "",
        "auth_provider_id": run.auth_provider_id or "",
        "auth_context_ref": run.auth_context_ref or "",
        "snapshot_id": str(snapshot.id) if snapshot and snapshot.id else "",
        "pathid": snapshot.pathid if snapshot else value.related_pathid,
    }
    target.update(dict(value.target or {}))
    result = security_test_result(
        run_id=run.id,
        execution_key=value.execution_key or None,
        contract_version=RESULT_CONTRACT_VERSION,
        project_id=run.project_id,
        env_id=run.env_id or "",
        account_id=run.account_id or "",
        auth_mode=run.auth_mode or "",
        auth_provider_id=run.auth_provider_id or "",
        snapshot_id=snapshot.id if snapshot else None,
        case_name=value.case_name,
        check_type=value.check_type,
        target=target,
        method=(snapshot.method if snapshot else value.method) or "",
        verdict=value.verdict,
        outcome_class=project_outcome_class(value.verdict),
        priority=value.priority,
        severity=value.severity,
        confidence=float(value.confidence or 0.0),
        reason_codes=[str(item) for item in (value.reason_codes or [])],
        evidence_summary=dict(value.evidence_summary or {}),
        evidence_ref=value.evidence_ref,
        related_pathid=(
            snapshot.pathid if snapshot else value.related_pathid
        ),
        expires_at=getattr(run, "expires_at", None),
    )
    try:
        result.save(force_insert=bool(value.execution_key))
    except NotUniqueError:
        if not value.execution_key:
            raise
        result = security_test_result.objects(execution_key=value.execution_key).first()
        if not result:
            raise
    return result


def record_execution_result(run, snapshot, case_name: str, check_type: str,
                            verdict: str, evidence_summary: Optional[Dict[str, Any]] = None,
                            evidence_ref: str = "", reason_codes=None,
                            confidence: float = 0.0, priority: str = "",
                            execution_key: str = "", target: Optional[Dict[str, Any]] = None,
                            method: str = "", severity: str = "",
                            related_pathid: Optional[int] = None):
    """Compatibility wrapper over the single result.v1 write contract."""
    return record_execution_result_input(
        run,
        snapshot,
        ExecutionResultInput(
            case_name=case_name,
            check_type=check_type,
            verdict=verdict,
            target=target,
            method=method,
            evidence_summary=evidence_summary,
            evidence_ref=evidence_ref,
            reason_codes=reason_codes,
            confidence=confidence,
            priority=priority,
            severity=severity,
            related_pathid=related_pathid,
            execution_key=execution_key,
        ),
    )
