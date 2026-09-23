"""Persistent snapshot execution scheduling over the existing run/result models.

MongoDB is the source of truth. Redis is only a best-effort wake-up signal, so
queue state survives Redis restarts and a worker can recover expired leases.
The default adapter executes read-only snapshots unless mutations are explicitly
acknowledged. Generic mutation results require separate effect verification.
"""
import datetime as dt
import hashlib
import json
import socket
import threading
import time
import uuid
from collections import Counter
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from dataclasses import asdict, dataclass
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple
from urllib.parse import urlsplit

import redis
from bson import ObjectId
from mongoengine.errors import NotUniqueError
from pymongo import UpdateOne

from apiAnalysis.db.collection import (
    parameter_relation,
    request_snapshot,
    security_execution_checkpoint,
    security_test_result,
    security_test_run,
)
from apiAnalysis.tool import redis_pool
from apiAnalysis.tool.account_context import (
    AccountContextError,
    AccountContextRef,
    AccountContextResolver,
    resolver_from_environment,
)
from apiAnalysis.tool.execution_adapter import (
    ExecutionAdapter,
    ExecutionAdapterError,
    ExecutionRequestBlocked,
    UnsupportedExecutionAdapter,
    adapter_registry,
    builtin_execution_adapters,
)
from apiAnalysis.tool.execution_contract import ExecutionContext, record_execution_result
from apiAnalysis.version import EXECUTION_CONTRACT_VERSION
from apiAnalysis.tool.snapshot_runner import replay_snapshot
from apiAnalysis.tool.parameter_sources import (
    apply_required_parameter_gate,
    required_parameter_quality_summary,
)
from apiAnalysis.tool.trace_capture import RESPONSE_TEXT_ADAPTER_IDS


WAKEUP_KEY = "api_manager:execution:wakeup"
SAFE_METHODS = ("GET", "HEAD", "OPTIONS")
FINAL_RUN_STATUSES = {
    security_test_run.DONE,
    security_test_run.FAILED,
    security_test_run.CANCELLED,
}


def _sync_parameter_relation_run_state(run: Any, status: str, reason: str = "") -> None:
    """Release relation rows when a validation run cannot continue.

    One run may represent many fields on the same interface pair.  Leaving
    those rows as ``running`` after an auth pause or terminal worker failure
    makes the UI look permanently busy and prevents a clean retry.
    """
    if str(getattr(run, "adapter_id", "") or "") != "parameter_relation_validation":
        return
    updates = {
        "set__preprocess_status": status,
        "set__mtime": utcnow(),
    }
    if reason:
        updates["set__preprocess_reason_codes"] = [str(reason)[:120]]
    relation_query = parameter_relation.objects(last_validation_run_id=run.id)
    if status == "running":
        relation_query = relation_query.filter(
            preprocess_status__in=["running", "needs_context", "automatic_failed"],
        )
    else:
        relation_query = relation_query.filter(preprocess_status="running")
    relation_query.update(**updates)
CHECKPOINT_COUNT_FIELDS = {
    "pending_cases": security_execution_checkpoint.PENDING,
    "running_cases": security_execution_checkpoint.RUNNING,
    "completed_cases": security_execution_checkpoint.DONE,
    "failed_cases": security_execution_checkpoint.ERROR,
    "skipped_cases": security_execution_checkpoint.SKIPPED,
    "cancelled_cases": security_execution_checkpoint.CANCELLED,
}


def utcnow() -> dt.datetime:
    return dt.datetime.utcnow()


@dataclass(frozen=True)
class ExecutionPolicy:
    """Bounded concurrency and recovery policy for one scheduled batch."""

    max_workers: int = 8
    per_host_workers: int = 4
    min_interval_ms: int = 25
    request_timeout_seconds: int = 5
    lease_seconds: int = 60
    transport_error_stop: int = 2
    rate_limit_stop: int = 3
    server_error_stop: int = 3
    max_dispatch_attempts: int = 3
    allow_mutation: bool = False
    mutation_acknowledged: bool = False

    def validate(self) -> None:
        if not 1 <= int(self.max_workers) <= 64:
            raise ValueError("max_workers must be between 1 and 64")
        if not 1 <= int(self.per_host_workers) <= int(self.max_workers):
            raise ValueError("per_host_workers must be between 1 and max_workers")
        if not 0 <= int(self.min_interval_ms) <= 60000:
            raise ValueError("min_interval_ms must be between 0 and 60000")
        if not 1 <= int(self.request_timeout_seconds) <= 300:
            raise ValueError("request_timeout_seconds must be between 1 and 300")
        if not 15 <= int(self.lease_seconds) <= 3600:
            raise ValueError("lease_seconds must be between 15 and 3600")
        for name in ("transport_error_stop", "rate_limit_stop", "server_error_stop"):
            value = int(getattr(self, name))
            if not 0 <= value <= 100:
                raise ValueError("{} must be between 0 and 100".format(name))
        if not 1 <= int(self.max_dispatch_attempts) <= 20:
            raise ValueError("max_dispatch_attempts must be between 1 and 20")
        if self.allow_mutation and not self.mutation_acknowledged:
            raise ValueError("mutation execution requires explicit acknowledgement")

    def to_dict(self) -> Dict[str, Any]:
        self.validate()
        return asdict(self)

    @classmethod
    def from_dict(cls, values: Optional[Dict[str, Any]] = None) -> "ExecutionPolicy":
        values = dict(values or {})
        known = {key: values[key] for key in cls.__dataclass_fields__ if key in values}
        policy = cls(**known)
        policy.validate()
        return policy


def normalize_snapshot_ids(snapshot_ids: Iterable[Any]) -> List[ObjectId]:
    normalized = []
    seen = set()
    for value in snapshot_ids or []:
        try:
            object_id = value if isinstance(value, ObjectId) else ObjectId(str(value))
        except Exception as exc:
            raise ValueError("invalid snapshot id") from exc
        if object_id in seen:
            continue
        seen.add(object_id)
        normalized.append(object_id)
    if not normalized:
        raise ValueError("at least one snapshot id is required")
    return normalized


def build_idempotency_key(context: ExecutionContext, snapshot_ids: Sequence[Any],
                          check_type: str, policy: ExecutionPolicy) -> str:
    """Return a stable content identity; batch names do not affect execution."""
    context.validate()
    payload = {
        "project_id": context.project_id,
        "env_id": context.env_id,
        "account_id": context.account_id,
        "auth_mode": context.auth_mode,
        "auth_provider_id": context.auth_provider_id,
        "auth_context_ref": context.auth_context_ref,
        "auth_profile_revision_id": context.auth_profile_revision_id,
        "auth_realm_revision_id": context.auth_realm_revision_id,
        "auth_adapter_version_id": context.auth_adapter_version_id,
        "adapter_id": context.adapter_id,
        "adapter_version": context.adapter_version,
        "plan_version": context.plan_version,
        "plan_sha256": context.plan_sha256,
        "check_type": check_type,
        "snapshot_ids": sorted(str(item) for item in normalize_snapshot_ids(snapshot_ids)),
        "policy": policy.to_dict(),
    }
    encoded = json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _snapshot_host(snapshot: Any) -> str:
    return str(getattr(snapshot, "domain", "") or urlsplit(str(snapshot.url)).hostname or "<unknown>").lower()


def _load_and_validate_snapshots(snapshot_ids: Sequence[ObjectId], context: ExecutionContext,
                                 policy: ExecutionPolicy) -> List[Any]:
    snapshots = list(request_snapshot.objects(id__in=list(snapshot_ids)))
    by_id = {item.id: item for item in snapshots}
    missing = [str(item) for item in snapshot_ids if item not in by_id]
    if missing:
        raise ValueError("snapshot ids not found: {}".format(",".join(missing[:5])))
    ordered = [by_id[item] for item in snapshot_ids]
    wrong_project = [str(item.id) for item in ordered if str(item.project_id or "") != context.project_id]
    if wrong_project:
        raise ValueError("snapshot project does not match execution context")
    if context.env_id and any(str(item.env_id or "") not in {"", context.env_id} for item in ordered):
        raise ValueError("snapshot environment does not match execution context")
    if context.auth_mode == "account":
        bindings = (
            ("account_id", context.account_id),
            ("auth_provider_id", context.auth_provider_id),
            ("auth_context_ref", context.auth_context_ref or context.account_id),
            ("auth_profile_revision_id", context.auth_profile_revision_id),
            ("auth_realm_revision_id", context.auth_realm_revision_id),
            ("auth_adapter_version_id", context.auth_adapter_version_id),
        )
        for field, expected in bindings:
            if not expected:
                continue
            if any(str(getattr(item, field, "") or "") not in {"", expected} for item in ordered):
                raise ValueError("snapshot account binding does not match execution context")
    unsafe = ["{}:{}".format(item.method, item.id) for item in ordered
              if str(item.method or "").upper() not in SAFE_METHODS]
    if unsafe and not policy.allow_mutation:
        raise ValueError("mutation snapshots require an explicitly acknowledged policy")
    if unsafe and context.adapter_id in {"snapshot_batch", "authenticated_snapshot_batch"}:
        if policy.max_dispatch_attempts != 1:
            raise ValueError("generic mutation batches require max_dispatch_attempts=1")
    return ordered


def _ensure_checkpoints(run: Any, snapshots: Sequence[Any]) -> None:
    now = utcnow()
    operations = []
    for ordinal, snapshot in enumerate(snapshots):
        operations.append(UpdateOne(
            {"run_id": run.id, "snapshot_id": snapshot.id},
            {"$setOnInsert": {
                "run_id": run.id,
                "snapshot_id": snapshot.id,
                "project_id": run.project_id or "",
                "env_id": run.env_id or "",
                "pathid": snapshot.pathid,
                "ordinal": ordinal,
                "host": _snapshot_host(snapshot),
                "status": security_execution_checkpoint.PENDING,
                "attempt_count": 0,
                "reason_codes": [],
                "outcome_summary": {},
                "updated_at": now,
                "expires_at": run.expires_at,
            }},
            upsert=True,
        ))
    if operations:
        security_execution_checkpoint._get_collection().bulk_write(operations, ordered=False)


def signal_execution_queue(run_id: Any) -> bool:
    """Best-effort wakeup only; failure never loses the Mongo-backed job."""
    try:
        client = redis.Redis(connection_pool=redis_pool)
        client.lpush(WAKEUP_KEY, str(run_id))
        client.ltrim(WAKEUP_KEY, 0, 9999)
        return True
    except Exception:
        return False


def enqueue_snapshot_batch(name: str, check_type: str, context: ExecutionContext,
                           snapshot_ids: Sequence[Any], policy: Optional[ExecutionPolicy] = None,
                           scope: Optional[Dict[str, Any]] = None, evidence_ref: str = "",
                           operator: str = "", priority: int = 100, queue_name: str = "snapshot",
                           idempotency_key: str = "") -> Tuple[Any, bool]:
    """Idempotently persist a run and its per-snapshot checkpoints."""
    context.validate()
    policy = policy or ExecutionPolicy()
    policy.validate()
    ids = normalize_snapshot_ids(snapshot_ids)
    snapshots = _load_and_validate_snapshots(ids, context, policy)
    key = idempotency_key or build_idempotency_key(context, ids, check_type, policy)
    existing = security_test_run.objects(idempotency_key=key).first()
    if existing:
        existing_ids = {str(item) for item in (existing.snapshot_ids or [])}
        requested_ids = {str(item) for item in ids}
        if existing_ids != requested_ids:
            raise ValueError(
                "idempotency_key already used with different snapshot_ids"
            )
    if existing and existing.status != security_test_run.PREPARING:
        return existing, False

    created = False
    run = existing
    if not run:
        try:
            run = security_test_run(
                name=name,
                check_type=check_type,
                scope=dict(scope or {}, snapshot_count=len(ids)),
                evidence_ref=evidence_ref,
                operator=operator,
                source="execution_scheduler",
                contract_version=EXECUTION_CONTRACT_VERSION,
                status=security_test_run.PREPARING,
                scheduler_managed=True,
                idempotency_key=key,
                queue_name=queue_name,
                priority=int(priority),
                snapshot_ids=ids,
                execution_policy=policy.to_dict(),
                total_cases=len(ids),
                pending_cases=len(ids),
                max_dispatch_attempts=policy.max_dispatch_attempts,
                started_at=None,
                updated_at=utcnow(),
                **context.run_fields()
            )
            run.save(force_insert=True)
            created = True
        except NotUniqueError:
            run = security_test_run.objects(idempotency_key=key).first()
            if not run:
                raise
    if run.status == security_test_run.PREPARING:
        _ensure_checkpoints(run, snapshots)
        now = utcnow()
        security_test_run.objects(id=run.id, status=security_test_run.PREPARING).update_one(
            set__status=security_test_run.QUEUED,
            set__queued_at=now,
            set__updated_at=now,
            set__pending_cases=len(ids),
        )
        run.reload()
        signal_execution_queue(run.id)
    return run, created


def claim_next_execution(worker_id: str, queue_name: str = "snapshot",
                         lease_seconds: int = 60) -> Optional[Any]:
    if not worker_id:
        raise ValueError("worker_id is required")
    if not 15 <= int(lease_seconds) <= 3600:
        raise ValueError("lease_seconds must be between 15 and 3600")
    now = utcnow()
    token = uuid.uuid4().hex
    return security_test_run.objects(
        scheduler_managed=True,
        queue_name=queue_name,
        status=security_test_run.QUEUED,
    ).order_by("-priority", "queued_at").modify(
        new=True,
        set__status=security_test_run.RUNNING,
        set__lease_owner=worker_id,
        set__lease_token=token,
        set__lease_expires_at=now + dt.timedelta(seconds=int(lease_seconds)),
        set__heartbeat_at=now,
        set__started_at=now,
        set__updated_at=now,
        inc__dispatch_attempt=1,
    )


def heartbeat_execution(run_id: Any, lease_token: str, lease_seconds: int) -> bool:
    now = utcnow()
    updated = security_test_run.objects(
        id=ObjectId(str(run_id)),
        lease_token=lease_token,
        status__in=[security_test_run.RUNNING, security_test_run.CANCEL_REQUESTED],
    ).update_one(
        set__heartbeat_at=now,
        set__lease_expires_at=now + dt.timedelta(seconds=int(lease_seconds)),
        set__updated_at=now,
    )
    return bool(updated)


def checkpoint_counts(run_id: Any) -> Dict[str, int]:
    return {
        field: security_execution_checkpoint.objects(run_id=run_id, status=status).count()
        for field, status in CHECKPOINT_COUNT_FIELDS.items()
    }


def _count_updates(run_id: Any) -> Dict[str, Any]:
    return {
        "set__{}".format(field): value
        for field, value in checkpoint_counts(run_id).items()
    }


def _finalize_cancelled_run(run: Any, reason: str = "cancel_requested") -> None:
    now = utcnow()
    security_execution_checkpoint.objects(
        run_id=run.id,
        status__in=[security_execution_checkpoint.PENDING, security_execution_checkpoint.RUNNING],
    ).update(
        set__status=security_execution_checkpoint.CANCELLED,
        set__reason_codes=[reason],
        set__finished_at=now,
        set__updated_at=now,
        unset__lease_token=1,
    )
    updates = _count_updates(run.id)
    updates.update({
        "set__status": security_test_run.CANCELLED,
        "set__finished_at": now,
        "set__updated_at": now,
        "unset__lease_owner": 1,
        "unset__lease_token": 1,
        "unset__lease_expires_at": 1,
    })
    security_test_run.objects(id=run.id).update_one(**updates)


def request_execution_cancel(run_id: Any, reason: str = "operator_requested") -> Optional[Any]:
    run = security_test_run.objects(id=ObjectId(str(run_id)), scheduler_managed=True).first()
    if not run or run.status in FINAL_RUN_STATUSES:
        return run
    if run.status in {security_test_run.PREPARING, security_test_run.QUEUED, security_test_run.PAUSED}:
        _finalize_cancelled_run(run, reason=reason)
    else:
        security_test_run.objects(id=run.id, status=security_test_run.RUNNING).update_one(
            set__status=security_test_run.CANCEL_REQUESTED,
            set__cancel_reason=reason,
            set__updated_at=utcnow(),
        )
    return security_test_run.objects(id=run.id).first()


def resume_execution(run_id: Any) -> Optional[Any]:
    run = security_test_run.objects(id=ObjectId(str(run_id)), scheduler_managed=True).first()
    if not run:
        return None
    if run.status == security_test_run.PAUSED:
        changed = security_test_run.objects(
            id=run.id, status=security_test_run.PAUSED
        ).update_one(
            set__status=security_test_run.QUEUED,
            set__queued_at=utcnow(),
            set__updated_at=utcnow(),
            unset__last_error_type=1,
        )
        if changed:
            _sync_parameter_relation_run_state(run, "running", "resumed")
            signal_execution_queue(run.id)
    return security_test_run.objects(id=run.id).first()


def resume_auth_dependency(run_id: Any, profile_revision_id: str) -> Optional[Any]:
    """CAS-resume one run paused specifically on the verified auth revision."""
    try:
        object_id = ObjectId(str(run_id))
    except Exception:
        return None
    revision_id = str(profile_revision_id or "")
    if not revision_id:
        return security_test_run.objects(id=object_id).first()
    run = security_test_run.objects(
        id=object_id,
        scheduler_managed=True,
        status=security_test_run.PAUSED,
        dependency_type="auth_profile",
        dependency_id=revision_id,
    ).first()
    if not run:
        return security_test_run.objects(id=object_id).first()
    changed = security_test_run.objects(
        id=run.id,
        status=security_test_run.PAUSED,
        dependency_type="auth_profile",
        dependency_id=revision_id,
    ).update_one(
        set__status=security_test_run.QUEUED,
        set__queued_at=utcnow(),
        set__updated_at=utcnow(),
        unset__last_error_type=1,
        unset__pause_code=1,
        unset__dependency_type=1,
        unset__dependency_id=1,
        unset__dependency_revision_id=1,
    )
    if changed:
        _sync_parameter_relation_run_state(run, "running", "auth_repaired")
        signal_execution_queue(run.id)
    return security_test_run.objects(id=run.id).first()


def recover_expired_executions(now: Optional[dt.datetime] = None,
                               queue_name: str = "",
                               orphan_grace_seconds: int = 300,
                               legacy_stale_seconds: int = 86400) -> Dict[str, int]:
    """Reconcile expired, orphaned and retired-chain execution state."""
    now = now or utcnow()
    recovered = 0
    orphaned_recovered = 0
    legacy_expired = 0
    cancelled = 0
    preparing_recovered = 0
    preparing_failed = 0
    preparing_cutoff = now - dt.timedelta(minutes=5)
    preparing_query = {
        "scheduler_managed": True,
        "status": security_test_run.PREPARING,
        "updated_at__lte": preparing_cutoff,
    }
    if queue_name:
        preparing_query["queue_name"] = queue_name
    for run in security_test_run.objects(
        **preparing_query
    ):
        snapshots = list(request_snapshot.objects(id__in=list(run.snapshot_ids or [])))
        if not run.snapshot_ids or len(snapshots) != len(run.snapshot_ids):
            changed = security_test_run.objects(
                id=run.id, status=security_test_run.PREPARING
            ).update_one(
                set__status=security_test_run.FAILED,
                set__last_error_type="PreparingSnapshotsUnavailable",
                set__finished_at=now,
                set__updated_at=now,
            )
            preparing_failed += int(bool(changed))
            continue
        by_id = {item.id: item for item in snapshots}
        _ensure_checkpoints(run, [by_id[item] for item in run.snapshot_ids])
        changed = security_test_run.objects(
            id=run.id, status=security_test_run.PREPARING
        ).update_one(
            set__status=security_test_run.QUEUED,
            set__queued_at=now,
            set__total_cases=len(run.snapshot_ids),
            set__pending_cases=len(run.snapshot_ids),
            set__updated_at=now,
        )
        if changed:
            preparing_recovered += 1
            signal_execution_queue(run.id)
    expired_query = {
        "scheduler_managed": True,
        "status": security_test_run.RUNNING,
        "lease_expires_at__lte": now,
    }
    if queue_name:
        expired_query["queue_name"] = queue_name
    expired = list(security_test_run.objects(**expired_query))
    for run in expired:
        token = run.lease_token or ""
        security_execution_checkpoint.objects(
            run_id=run.id,
            status=security_execution_checkpoint.RUNNING,
            lease_token=token,
        ).update(
            set__status=security_execution_checkpoint.PENDING,
            set__updated_at=now,
            unset__lease_token=1,
            unset__started_at=1,
        )
        changed = security_test_run.objects(
            id=run.id,
            status=security_test_run.RUNNING,
            lease_token=token,
            lease_expires_at__lte=now,
        ).update_one(
            set__status=security_test_run.QUEUED,
            set__queued_at=now,
            set__updated_at=now,
            unset__lease_owner=1,
            unset__lease_token=1,
            unset__lease_expires_at=1,
        )
        if changed:
            security_test_run.objects(id=run.id).update_one(**_count_updates(run.id))
            recovered += 1
            signal_execution_queue(run.id)

    # A scheduler-managed RUNNING row without any lease can be left behind by
    # an interrupted pre-lease migration or an older worker. Active workers
    # always own a lease, so after a short grace period this state is safe to
    # return to the durable queue.
    orphan_cutoff = now - dt.timedelta(seconds=max(60, int(orphan_grace_seconds)))
    missing_lease = {
        "$or": [
            {"lease_expires_at": None},
            {"lease_expires_at": {"$exists": False}},
        ],
    }
    orphan_query = {
        "scheduler_managed": True,
        "status": security_test_run.RUNNING,
        "started_at__lte": orphan_cutoff,
        "__raw__": missing_lease,
    }
    if queue_name:
        orphan_query["queue_name"] = queue_name
    for run in list(security_test_run.objects(**orphan_query)):
        security_execution_checkpoint.objects(
            run_id=run.id,
            status=security_execution_checkpoint.RUNNING,
        ).update(
            set__status=security_execution_checkpoint.PENDING,
            set__updated_at=now,
            unset__lease_token=1,
            unset__started_at=1,
        )
        changed = security_test_run.objects(
            id=run.id,
            scheduler_managed=True,
            status=security_test_run.RUNNING,
            started_at__lte=orphan_cutoff,
            __raw__=missing_lease,
        ).update_one(
            set__status=security_test_run.QUEUED,
            set__queued_at=now,
            set__updated_at=now,
            set__last_error_type="OrphanedLeaseRecovered",
            unset__lease_owner=1,
            unset__lease_token=1,
            unset__lease_expires_at=1,
        )
        if changed:
            security_test_run.objects(id=run.id).update_one(**_count_updates(run.id))
            orphaned_recovered += 1
            signal_execution_queue(run.id)

    # The old synchronous Workspace chain has no lease or heartbeat contract,
    # so an old RUNNING row cannot be resumed safely. Preserve its evidence and
    # make the terminal state explicit instead of displaying it forever.
    legacy_cutoff = now - dt.timedelta(seconds=max(3600, int(legacy_stale_seconds)))
    legacy_query = {
        "scheduler_managed__ne": True,
        "status": security_test_run.RUNNING,
        "started_at__lte": legacy_cutoff,
    }
    for run in list(security_test_run.objects(**legacy_query)):
        changed = security_test_run.objects(
            id=run.id,
            scheduler_managed__ne=True,
            status=security_test_run.RUNNING,
            started_at__lte=legacy_cutoff,
        ).update_one(
            set__status=security_test_run.FAILED,
            set__last_error_type="LegacyRunExpired",
            set__finished_at=now,
            set__updated_at=now,
        )
        legacy_expired += int(bool(changed))

    cancel_query = {
        "scheduler_managed": True,
        "status": security_test_run.CANCEL_REQUESTED,
        "$or": [
            {"lease_expires_at": {"$lte": now}},
            {"lease_expires_at": None},
            {"lease_expires_at": {"$exists": False}},
        ],
    }
    if queue_name:
        cancel_query["queue_name"] = queue_name
    for run in security_test_run.objects(__raw__=cancel_query):
        _finalize_cancelled_run(run, reason=run.cancel_reason or "cancel_requested")
        cancelled += 1
    return {
        "recovered": recovered,
        "orphaned_recovered": orphaned_recovered,
        "legacy_expired": legacy_expired,
        "cancelled": cancelled,
        "preparing_recovered": preparing_recovered,
        "preparing_failed": preparing_failed,
    }


def sanitize_execution_evidence(evidence: Dict[str, Any]) -> Dict[str, Any]:
    """Keep transport metadata only; never persist body samples or raw errors."""
    allowed = (
        "status_code", "expected_status_codes", "ok", "elapsed_ms",
        "response_len", "domain", "auth_mode", "error_type",
        "response_sha256", "response_content_type", "response_json_type",
        "response_record_count", "response_collection_path",
        "response_top_level_keys", "response_field_names",
        "request_method", "request_origin", "request_path",
        "request_query_names", "request_header_names", "request_cookie_names",
        "request_auth_header_names", "request_auth_cookie_names",
        "request_body_bytes", "request_content_type",
        "request_timeout_seconds", "request_allow_redirects",
        "request_tls_verify", "auth_request_count",
        "apifox_experiment", "mutation_request",
        "before_readback_attempted", "after_readback_attempted",
        "cleanup_attempted", "final_readback_attempted", "lifecycle_gap",
        "lifecycle_strategy", "lifecycle_request_count",
        "before_status_code", "mutation_status_code", "after_status_code",
        "cleanup_status_code", "final_status_code", "effect_observed",
        "cleanup_verified", "restore_payload_ready", "created_id_extracted",
        "source_status_code", "consumer_status_code",
        "authorization_matrix_case", "authorization_case_key",
        "authorization_policy_key", "authorization_policy_version_id",
        "authorization_policy_version", "resource_owner_principal_id",
        "subject_principal_id", "authorization_expected_decision",
        "authorization_observed_decision", "authorization_matched_rule_id",
        "authorization_rule_reason_codes", "authorization_resource_family",
        "authorization_action", "authorization_resource_match_count",
        "authorization_resource_field_count", "resource_path", "value_digest",
        "sqli_screen",
        "parameter_quality",
    )
    sanitized = {key: evidence.get(key) for key in allowed if key in evidence}
    sanitized["cluster_key"] = response_cluster_key(sanitized)
    return sanitized


def response_cluster_key(evidence: Dict[str, Any]) -> str:
    error_type = str(evidence.get("error_type") or "")
    if error_type:
        return "transport:{}".format(error_type)
    status = evidence.get("status_code")
    length = int(evidence.get("response_len") or 0)
    if length == 0:
        length_bucket = "0"
    elif length < 100:
        length_bucket = "1-99"
    elif length < 1000:
        length_bucket = "100-999"
    elif length < 10000:
        length_bucket = "1k-9k"
    else:
        length_bucket = "10k+"
    return "http:{}:{}:{}:{}".format(
        status if status is not None else "none",
        str(evidence.get("response_content_type") or "unknown"),
        str(evidence.get("response_json_type") or "none"),
        length_bucket,
    )


def classify_execution_result(evidence: Dict[str, Any], check_type: str,
                              auth_mode: str) -> Tuple[str, List[str], float]:
    error_type = evidence.get("error_type") or ("RequestError" if evidence.get("error") else "")
    if error_type:
        return "error", ["transport_error"], 0.9
    status = evidence.get("status_code")
    if status is None:
        return "error", ["transport_error"], 0.9
    status = int(status)
    is_unauth = auth_mode == "anonymous" and check_type in {"unauth_access", "anonymous_access"}
    if is_unauth and status in {401, 403}:
        return "no_vuln", ["anonymous_authentication_required"], 0.97
    if is_unauth and 200 <= status < 300:
        return "need_review", ["anonymous_2xx_requires_content_review"], 0.65
    if status == 429:
        return "not_evaluable", ["rate_limited"], 0.9
    if 500 <= status < 600:
        return "not_evaluable", ["server_error"], 0.8
    if 300 <= status < 400:
        return "not_evaluable", ["redirect_requires_review"], 0.65
    if is_unauth:
        return "not_evaluable", ["anonymous_response_not_conclusive"], 0.6
    return "not_evaluable", ["adapter_judge_required"], 0.95


def classify_generic_mutation_result(evidence: Dict[str, Any]) -> Tuple[str, List[str], float]:
    """Report an executed mutation for review without inferring its state change."""
    if evidence.get("error_type") or evidence.get("error"):
        return "error", ["transport_error"], 0.9
    status = evidence.get("status_code")
    if status is None:
        return "error", ["transport_error"], 0.9
    status = int(status)
    if status == 429:
        return "not_evaluable", ["rate_limited"], 0.9
    if 500 <= status < 600:
        return "not_evaluable", ["server_error"], 0.8
    if 300 <= status < 400:
        return "not_evaluable", ["redirect_requires_review"], 0.65
    return "need_review", ["mutation_response_requires_effect_review"], 0.75


def summarize_execution_records(checkpoints: Sequence[Any], results: Sequence[Any],
                                max_clusters: int = 1000,
                                max_review_candidates: int = 1000) -> Dict[str, Any]:
    """Build bounded, body-free clusters and a targeted Review queue."""
    groups: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for checkpoint in checkpoints:
        summary = dict(getattr(checkpoint, "outcome_summary", {}) or {})
        cluster_key = str(summary.get("cluster_key") or response_cluster_key(summary))
        host = str(getattr(checkpoint, "host", "") or "<unknown>")
        key = (host, cluster_key)
        group = groups.setdefault(key, {
            "host": host,
            "cluster_key": cluster_key,
            "count": 0,
            "hashes": set(),
            "representative_pathid": getattr(checkpoint, "pathid", None),
            "representative_snapshot_id": str(getattr(checkpoint, "snapshot_id", "") or ""),
        })
        group["count"] += 1
        response_hash = str(summary.get("response_sha256") or "")
        if response_hash:
            group["hashes"].add(response_hash)
    clusters = []
    for group in groups.values():
        hashes = group.pop("hashes")
        group["distinct_response_hashes"] = len(hashes)
        clusters.append(group)
    clusters.sort(key=lambda item: (-item["count"], item["host"], item["cluster_key"]))

    verdict_counts = Counter()
    reason_counts = Counter()
    review_candidates = []
    for result in results:
        verdict = str(getattr(result, "verdict", "") or "unknown")
        verdict_counts[verdict] += 1
        reasons = list(getattr(result, "reason_codes", []) or [])
        reason_counts.update(str(reason) for reason in reasons)
        if verdict in {"need_review", "potential_vuln", "error"}:
            if len(review_candidates) < max_review_candidates:
                review_candidates.append({
                    "result_id": str(getattr(result, "id", "") or ""),
                    "snapshot_id": str(getattr(result, "snapshot_id", "") or ""),
                    "pathid": getattr(result, "related_pathid", None),
                    "verdict": verdict,
                    "reason_codes": reasons,
                })
    return {
        "cluster_count": len(clusters),
        "clusters": clusters[:max_clusters],
        "clusters_truncated": len(clusters) > max_clusters,
        "verdict_counts": dict(sorted(verdict_counts.items())),
        "reason_counts": dict(sorted(reason_counts.items())),
        "review_candidate_count": sum(
            count for verdict, count in verdict_counts.items()
            if verdict in {"need_review", "potential_vuln", "error"}
        ),
        "review_candidates": review_candidates,
        "review_candidates_truncated": (
            sum(
                count for verdict, count in verdict_counts.items()
                if verdict in {"need_review", "potential_vuln", "error"}
            ) > len(review_candidates)
        ),
    }


class HostPolicyCoordinator:
    """Thread-safe host concurrency, pacing, and independent stop state."""

    def __init__(self, policy: ExecutionPolicy, persisted: Optional[Dict[str, Any]] = None):
        self.policy = policy
        self._lock = threading.Lock()
        self._semaphores: Dict[str, threading.BoundedSemaphore] = {}
        self._states: Dict[str, Dict[str, Any]] = {}
        for item in (persisted or {}).get("hosts", []):
            host = str(item.get("host") or "<unknown>").lower()
            self._states[host] = {
                "transport_errors": int(item.get("transport_errors") or 0),
                "rate_limits": int(item.get("rate_limits") or 0),
                "server_errors": int(item.get("server_errors") or 0),
                "stopped_reason": str(item.get("stopped_reason") or ""),
                "next_allowed": 0.0,
            }

    def _state(self, host: str) -> Dict[str, Any]:
        return self._states.setdefault(host, {
            "transport_errors": 0,
            "rate_limits": 0,
            "server_errors": 0,
            "stopped_reason": "",
            "next_allowed": 0.0,
        })

    def acquire(self, host: str, should_abort: Callable[[], bool]) -> Tuple[bool, str, Any]:
        host = str(host or "<unknown>").lower()
        with self._lock:
            semaphore = self._semaphores.setdefault(
                host, threading.BoundedSemaphore(self.policy.per_host_workers)
            )
        while True:
            if should_abort():
                return False, "execution_stopping", None
            if semaphore.acquire(timeout=0.1):
                break
        with self._lock:
            state = self._state(host)
            if state["stopped_reason"]:
                reason = state["stopped_reason"]
                semaphore.release()
                return False, reason, None
            now = time.monotonic()
            start_at = max(now, float(state["next_allowed"]))
            state["next_allowed"] = start_at + (self.policy.min_interval_ms / 1000.0)
        delay = max(0.0, start_at - time.monotonic())
        while delay > 0:
            if should_abort():
                semaphore.release()
                return False, "execution_stopping", None
            step = min(delay, 0.1)
            time.sleep(step)
            delay = max(0.0, start_at - time.monotonic())
        with self._lock:
            reason = self._state(host)["stopped_reason"]
        if reason or should_abort():
            semaphore.release()
            return False, reason or "execution_stopping", None
        return True, "", semaphore

    @staticmethod
    def release(permit: Any) -> None:
        if permit is not None:
            permit.release()

    def record_outcome(self, host: str, evidence: Dict[str, Any]) -> str:
        host = str(host or "<unknown>").lower()
        with self._lock:
            state = self._state(host)
            if state["stopped_reason"]:
                return state["stopped_reason"]
            error = bool(evidence.get("error_type") or evidence.get("error"))
            status = evidence.get("status_code")
            if error:
                state["transport_errors"] += 1
                state["rate_limits"] = 0
                state["server_errors"] = 0
                threshold = self.policy.transport_error_stop
                if threshold and state["transport_errors"] >= threshold:
                    state["stopped_reason"] = "transport_error_threshold"
            elif status == 429:
                state["transport_errors"] = 0
                state["rate_limits"] += 1
                state["server_errors"] = 0
                threshold = self.policy.rate_limit_stop
                if threshold and state["rate_limits"] >= threshold:
                    state["stopped_reason"] = "rate_limit_threshold"
            elif status is not None and 500 <= int(status) < 600:
                state["transport_errors"] = 0
                state["rate_limits"] = 0
                state["server_errors"] += 1
                threshold = self.policy.server_error_stop
                if threshold and state["server_errors"] >= threshold:
                    state["stopped_reason"] = "server_error_threshold"
            else:
                state["transport_errors"] = 0
                state["rate_limits"] = 0
                state["server_errors"] = 0
            return state["stopped_reason"]

    def snapshot(self) -> Dict[str, Any]:
        with self._lock:
            hosts = []
            for host in sorted(self._states):
                state = self._states[host]
                hosts.append({
                    "host": host,
                    "transport_errors": state["transport_errors"],
                    "rate_limits": state["rate_limits"],
                    "server_errors": state["server_errors"],
                    "stopped_reason": state["stopped_reason"],
                })
            return {"hosts": hosts}


def _build_coordinated_request_executor(
        coordinator: HostPolicyCoordinator, host: str,
        should_abort: Callable[[], bool]) -> Callable[[Callable[[], Any]], Any]:
    def execute(request_call: Callable[[], Any]) -> Any:
        allowed, block_reason, permit = coordinator.acquire(host, should_abort)
        if not allowed:
            raise ExecutionRequestBlocked(block_reason)
        try:
            try:
                result = request_call()
            except ExecutionRequestBlocked:
                raise
            except Exception as exc:
                coordinator.record_outcome(host, {
                    "error_type": exc.__class__.__name__,
                    "error": str(exc),
                })
                raise
            evidence = result[0] if isinstance(result, tuple) and result else result
            if not isinstance(evidence, dict):
                raise TypeError("request executor callback must return evidence")
            coordinator.record_outcome(host, evidence)
            return result
        finally:
            coordinator.release(permit)

    return execute


class _HeartbeatThread(threading.Thread):
    def __init__(self, run_id: Any, lease_token: str, lease_seconds: int):
        super().__init__(daemon=True)
        self.run_id = run_id
        self.lease_token = lease_token
        self.lease_seconds = lease_seconds
        self.stop_event = threading.Event()
        self.lost_event = threading.Event()

    def run(self) -> None:
        interval = max(5.0, min(20.0, self.lease_seconds / 3.0))
        while not self.stop_event.wait(interval):
            if not heartbeat_execution(self.run_id, self.lease_token, self.lease_seconds):
                self.lost_event.set()
                return

    def close(self) -> None:
        self.stop_event.set()
        self.join(timeout=2)


class ExecutionWorker:
    def __init__(self, worker_id: str = "", queue_name: str = "snapshot",
                 lease_seconds: int = 60,
                 replay: Callable[..., Dict[str, Any]] = replay_snapshot,
                 judge: Callable[[Dict[str, Any], str, str], Tuple[str, List[str], float]] = classify_execution_result,
                 supported_adapter_ids: Optional[Sequence[str]] = None,
                 adapters: Optional[Sequence[ExecutionAdapter]] = None,
                 account_context_resolver: Optional[AccountContextResolver] = None,
                 request_trace_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
                 trace_recorder: Optional[Any] = None):
        self.worker_id = worker_id or "{}:{}".format(socket.gethostname(), uuid.uuid4().hex[:8])
        self.queue_name = queue_name
        self.lease_seconds = int(lease_seconds)
        self.replay = replay
        self.judge = judge
        self.account_context_resolver = account_context_resolver or resolver_from_environment()
        self.request_trace_callback = request_trace_callback
        # Persists one searchable request/response trace per execution.  A
        # recorder is an observer: its failures are counted, never raised.
        self.trace_recorder = trace_recorder
        registered = builtin_execution_adapters(replay, judge)
        from apiAnalysis.tool.authorization_matrix import build_authorization_matrix_adapter
        from apiAnalysis.tool.apifox_experiment import build_apifox_experiment_adapter
        from apiAnalysis.tool.apifox_mutation_lifecycle import build_mutation_lifecycle_adapter
        from apiAnalysis.tool.parameter_validation import build_parameter_validation_adapter
        from apiAnalysis.tool.sqli_screen import build_sqli_screen_adapter
        workflow_adapters = [
            build_parameter_validation_adapter(self.account_context_resolver),
            build_authorization_matrix_adapter(self.account_context_resolver),
            build_apifox_experiment_adapter(),
            build_mutation_lifecycle_adapter(),
            build_sqli_screen_adapter(),
        ]
        registered.update(adapter_registry(workflow_adapters))
        if adapters:
            registered.update(adapter_registry(adapters))
        if supported_adapter_ids is not None:
            supported = set(supported_adapter_ids)
            registered = {key: value for key, value in registered.items() if key in supported}
        self.adapters = registered
        self.supported_adapter_ids = set(registered)
        self.stop_event = threading.Event()

    @staticmethod
    def _account_reference(run: Any) -> AccountContextRef:
        return AccountContextRef(
            project_id=str(run.project_id or ""),
            env_id=str(run.env_id or ""),
            account_id=str(run.account_id or ""),
            provider_id=str(run.auth_provider_id or ""),
            context_ref=str(run.auth_context_ref or ""),
        )

    @staticmethod
    def _unavailable_auth_summary(run: Any, exc: Exception) -> Dict[str, Any]:
        summary = {
            "status": "unavailable",
            "provider_id": str(run.auth_provider_id or ""),
            "project_id": str(run.project_id or ""),
            "env_id": str(run.env_id or ""),
            "account_id": str(run.account_id or ""),
            "context_ref": str(run.auth_context_ref or run.account_id or ""),
            "error_type": exc.__class__.__name__,
            "error_detail": str(exc or "")[:160],
        }
        for field in (
            "auth_profile_revision_id", "auth_realm_revision_id",
            "auth_adapter_version_id",
        ):
            value = str(getattr(run, field, "") or "")
            if value:
                summary[field] = value
        code = str(getattr(exc, "code", "") or "")
        if code:
            summary["error_code"] = code[:80]
        return summary

    @staticmethod
    def _pause_claimed_run(run: Any, exc: Exception,
                           auth_summary: Optional[Dict[str, Any]] = None) -> None:
        updates = {
            "set__status": security_test_run.PAUSED,
            "set__last_error_type": exc.__class__.__name__,
            "set__pause_code": "auth_unavailable",
            "set__dependency_type": "auth_profile",
            "set__dependency_id": str(run.auth_profile_revision_id or run.auth_context_ref or ""),
            "set__dependency_revision_id": str(run.auth_profile_revision_id or ""),
            "set__updated_at": utcnow(),
            "unset__lease_owner": 1,
            "unset__lease_token": 1,
            "unset__lease_expires_at": 1,
        }
        if auth_summary is not None:
            updates["set__auth_context_summary"] = dict(auth_summary)
        security_test_run.objects(
            id=run.id,
            lease_token=run.lease_token,
            status=security_test_run.RUNNING,
        ).update_one(**updates)
        relation_status = "needs_context" if isinstance(exc, AccountContextError) else "automatic_failed"
        _sync_parameter_relation_run_state(run, relation_status, exc.__class__.__name__)

    def _preflight(self, run: Any, adapter: ExecutionAdapter,
                   policy: ExecutionPolicy) -> None:
        adapter.validate(run, allow_mutation=policy.allow_mutation)
        if not adapter.requires_account_context:
            return
        reference = self._account_reference(run)
        hosts = sorted(set(
            str(host or "") for host in security_execution_checkpoint.objects(
                run_id=run.id,
            ).scalar("host")
        )) or [""]
        context = None
        min_validity = max(30, int(policy.request_timeout_seconds) + 5)
        for host in hosts:
            context = self.account_context_resolver.resolve(
                reference, host=host, min_validity_seconds=min_validity,
            )
        if context is not None:
            security_test_run.objects(id=run.id, lease_token=run.lease_token).update_one(
                set__auth_context_summary=context.descriptor(),
                set__last_error_type="",
                set__updated_at=utcnow(),
            )

    @staticmethod
    def _execution_key(run: Any, snapshot_id: Any) -> str:
        return "{}:{}".format(run.id, snapshot_id)

    @staticmethod
    def _sync_counts(run_id: Any, coordinator: Optional[HostPolicyCoordinator] = None) -> Dict[str, int]:
        counts = checkpoint_counts(run_id)
        updates = {"set__{}".format(field): value for field, value in counts.items()}
        updates["set__updated_at"] = utcnow()
        if coordinator is not None:
            updates["set__host_state"] = coordinator.snapshot()
        security_test_run.objects(id=run_id).update_one(**updates)
        return counts

    @staticmethod
    def _finish_checkpoint(checkpoint: Any, lease_token: str, status: str,
                           reason_codes: Optional[List[str]] = None,
                           summary: Optional[Dict[str, Any]] = None,
                           result_id: Any = None, error_type: str = "") -> None:
        updates = {
            "set__status": status,
            "set__reason_codes": list(reason_codes or []),
            "set__outcome_summary": dict(summary or {}),
            "set__error_type": error_type,
            "set__finished_at": utcnow(),
            "set__updated_at": utcnow(),
            "unset__lease_token": 1,
        }
        if result_id:
            updates["set__result_id"] = result_id
        security_execution_checkpoint.objects(
            id=checkpoint.id,
            status=security_execution_checkpoint.RUNNING,
            lease_token=lease_token,
        ).update_one(**updates)

    def _execute_checkpoint(self, run: Any, checkpoint_id: Any,
                            adapter: ExecutionAdapter,
                            policy: ExecutionPolicy, coordinator: HostPolicyCoordinator,
                            cancel_event: threading.Event,
                            lease_lost_event: threading.Event,
                            auth_failure_event: threading.Event,
                            auth_failure_state: Dict[str, Any],
                            auth_failure_lock: threading.Lock) -> str:
        checkpoint = security_execution_checkpoint.objects(
            id=checkpoint_id,
            run_id=run.id,
            status=security_execution_checkpoint.PENDING,
        ).modify(
            new=True,
            set__status=security_execution_checkpoint.RUNNING,
            set__lease_token=run.lease_token,
            set__started_at=utcnow(),
            set__updated_at=utcnow(),
            inc__attempt_count=1,
        )
        if not checkpoint:
            return "not_claimed"
        execution_key = self._execution_key(run, checkpoint.snapshot_id)
        existing = security_test_result.objects(execution_key=execution_key).first()
        if existing:
            existing_summary = dict(existing.evidence_summary or {})
            if adapter.request_policy_scope == "checkpoint":
                coordinator.record_outcome(checkpoint.host, existing_summary)
            existing_status = (
                security_execution_checkpoint.ERROR
                if existing.verdict == "error" or existing_summary.get("error_type")
                else security_execution_checkpoint.DONE
            )
            self._finish_checkpoint(
                checkpoint, run.lease_token, existing_status,
                reason_codes=list(existing.reason_codes or []),
                summary=existing_summary, result_id=existing.id,
                error_type=str(existing_summary.get("error_type") or ""),
            )
            return existing_status

        snapshot = request_snapshot.objects(id=checkpoint.snapshot_id).first()
        if not snapshot:
            self._finish_checkpoint(
                checkpoint, run.lease_token, security_execution_checkpoint.ERROR,
                reason_codes=["snapshot_not_found"], error_type="SnapshotNotFound",
            )
            return security_execution_checkpoint.ERROR

        def should_abort() -> bool:
            return (
                cancel_event.is_set() or lease_lost_event.is_set()
                or auth_failure_event.is_set() or self.stop_event.is_set()
            )

        def finish_blocked(block_reason: str) -> str:
            if block_reason == "execution_stopping":
                status = (
                    security_execution_checkpoint.PENDING
                    if lease_lost_event.is_set() or auth_failure_event.is_set() or self.stop_event.is_set()
                    else security_execution_checkpoint.CANCELLED
                )
            else:
                status = security_execution_checkpoint.SKIPPED
            if status == security_execution_checkpoint.PENDING:
                security_execution_checkpoint.objects(
                    id=checkpoint.id, status=security_execution_checkpoint.RUNNING,
                    lease_token=run.lease_token,
                ).update_one(
                    set__status=status, set__reason_codes=[block_reason],
                    set__updated_at=utcnow(), unset__lease_token=1, unset__started_at=1,
                )
            else:
                self._finish_checkpoint(
                    checkpoint, run.lease_token, status, reason_codes=[block_reason],
                )
            return status

        permit = None
        if adapter.request_policy_scope == "checkpoint":
            allowed, block_reason, permit = coordinator.acquire(checkpoint.host, should_abort)
            if not allowed:
                return finish_blocked(block_reason)

        # Widened response text for the trace chain, when the adapter can supply
        # it.  Initialised before the try so it survives an exception path.
        # Append, never overwrite: a lifecycle adapter fires several requests
        # (before-read, mutation, after-read, cleanup, final readback) through
        # one replay call, and each deserves its own trace.
        captured_response_text: List[str] = []

        try:
            if should_abort():
                status = (
                    security_execution_checkpoint.PENDING
                    if lease_lost_event.is_set() or auth_failure_event.is_set() or self.stop_event.is_set()
                    else security_execution_checkpoint.CANCELLED
                )
                if status == security_execution_checkpoint.PENDING:
                    reason = "account_context_unavailable" if auth_failure_event.is_set() else "lease_lost"
                    security_execution_checkpoint.objects(
                        id=checkpoint.id, status=security_execution_checkpoint.RUNNING,
                        lease_token=run.lease_token,
                    ).update_one(
                        set__status=status, set__reason_codes=[reason],
                        set__updated_at=utcnow(), unset__lease_token=1, unset__started_at=1,
                    )
                else:
                    self._finish_checkpoint(checkpoint, run.lease_token, status, reason_codes=["cancel_requested"])
                return status
            account_context = None
            if adapter.requires_account_context:
                try:
                    account_context = self.account_context_resolver.resolve(
                        self._account_reference(run),
                        host=checkpoint.host,
                        min_validity_seconds=max(30, int(policy.request_timeout_seconds) + 5),
                    )
                except AccountContextError as exc:
                    with auth_failure_lock:
                        if not auth_failure_state:
                            auth_failure_state.update(self._unavailable_auth_summary(run, exc))
                    auth_failure_event.set()
                    security_execution_checkpoint.objects(
                        id=checkpoint.id,
                        status=security_execution_checkpoint.RUNNING,
                        lease_token=run.lease_token,
                    ).update_one(
                        set__status=security_execution_checkpoint.PENDING,
                        set__reason_codes=["account_context_unavailable"],
                        set__error_type=exc.__class__.__name__,
                        set__updated_at=utcnow(),
                        unset__lease_token=1,
                        unset__started_at=1,
                    )
                    return "auth_paused"
            replay_kwargs = {
                "auth_mode": run.auth_mode,
                "request_options": {
                    "timeout": policy.request_timeout_seconds,
                    "allow_redirects": False,
                },
            }
            if account_context is not None:
                replay_kwargs["account_context"] = account_context
            if adapter.request_policy_scope == "request":
                replay_kwargs["request_executor"] = _build_coordinated_request_executor(
                    coordinator, checkpoint.host, should_abort,
                )
            if self.request_trace_callback is not None and adapter.adapter_id in {
                "snapshot_batch", "authenticated_snapshot_batch",
                "apifox_test_experiment", "apifox_mutation_lifecycle",
            }:
                def report_request_trace(preview: Dict[str, Any]) -> None:
                    trace = {
                        "event": "request_preview",
                        "run_id": str(run.id),
                        "checkpoint_id": str(checkpoint.id),
                        "ordinal": int(checkpoint.ordinal),
                        "adapter_id": adapter.adapter_id,
                        **dict(preview or {}),
                    }
                    try:
                        self.request_trace_callback(trace)
                    except Exception:
                        # Local display failures must never alter request execution.
                        pass

                replay_kwargs["request_trace_callback"] = report_request_trace
            if (
                self.trace_recorder is not None
                and getattr(self.trace_recorder, "enabled", False)
                and adapter.adapter_id in RESPONSE_TEXT_ADAPTER_IDS
            ):
                def capture_response_text(text: str) -> None:
                    captured_response_text.append(str(text or ""))

                replay_kwargs["response_text_callback"] = capture_response_text
            if adapter.adapter_id in {"parameter_relation_validation", "authorization_matrix"}:
                def report_progress(progress: Dict[str, Any]) -> None:
                    progress = dict(progress or {})
                    safe_progress = {
                        "phase": str(progress.get("phase") or "")[:60],
                        "message": str(progress.get("message") or "")[:240],
                        "request_count": max(0, int(progress.get("request_count") or 0)),
                        "request_budget": max(0, int(progress.get("request_budget") or 0)),
                        "attempt": max(0, int(progress.get("attempt") or 0)),
                        "status_code": progress.get("status_code"),
                    }
                    security_execution_checkpoint.objects(
                        id=checkpoint.id,
                        status=security_execution_checkpoint.RUNNING,
                        lease_token=run.lease_token,
                    ).update_one(
                        set__outcome_summary=safe_progress,
                        set__updated_at=utcnow(),
                    )

                replay_kwargs["progress_callback"] = report_progress
            evidence = adapter.replay(snapshot, **replay_kwargs)
        except ExecutionRequestBlocked as exc:
            return finish_blocked(exc.reason)
        except Exception as exc:
            evidence = {
                "status_code": None,
                "ok": False,
                "elapsed_ms": 0,
                "response_len": 0,
                "domain": checkpoint.host,
                "auth_mode": run.auth_mode,
                "error_type": exc.__class__.__name__,
            }
        finally:
            coordinator.release(permit)

        if adapter.request_policy_scope == "checkpoint":
            coordinator.record_outcome(checkpoint.host, evidence)
        # Provenance labels only, never a parameter value: this lets the gate
        # below refuse a pass that rests on an unestablished required value,
        # and persists the reason for later review.
        parameter_quality = required_parameter_quality_summary(
            getattr(snapshot, "parameter_sources", None),
        )
        if parameter_quality["blocks_pass"] or parameter_quality["request_sample_only_required"]:
            evidence["parameter_quality"] = parameter_quality
        summary = sanitize_execution_evidence(evidence)
        if (adapter.adapter_id in {"snapshot_batch", "authenticated_snapshot_batch"}
                and str(snapshot.method or "").upper() not in SAFE_METHODS):
            verdict, reasons, confidence = classify_generic_mutation_result(evidence)
        else:
            verdict, reasons, confidence = adapter.judge(evidence, run.check_type, run.auth_mode)
        verdict, reasons, confidence = apply_required_parameter_gate(
            verdict, reasons, confidence, evidence.get("parameter_quality"),
        )
        result = record_execution_result(
            run,
            snapshot,
            case_name="{} {}".format(snapshot.method, snapshot.path or urlsplit(snapshot.url).path),
            check_type=run.check_type,
            verdict=verdict,
            evidence_summary=summary,
            target=(
                dict(evidence.get("result_target") or {})
                if isinstance(evidence.get("result_target"), dict) else {}
            ),
            evidence_ref=run.evidence_ref or "",
            reason_codes=reasons,
            confidence=confidence,
            execution_key=execution_key,
        )
        if adapter.record is not None:
            adapter.record(run, snapshot, evidence, result, checkpoint)
        if self.trace_recorder is not None:
            # Observation only: this must not change the checkpoint outcome, so
            # the recorder is contractually fail-soft.  One trace per captured
            # response, so a multi-request lifecycle is indexed per request
            # rather than collapsed into its last response.
            for ordinal, text in enumerate(captured_response_text):
                self.trace_recorder.record(
                    run=run,
                    snapshot=snapshot,
                    evidence=evidence,
                    result=result,
                    response_text=text,
                    ordinal=ordinal,
                )
            if not captured_response_text:
                # Adapters outside the response-text allowlist still get a trace
                # from the evidence they return (their bounded text_sample).
                self.trace_recorder.record(
                    run=run, snapshot=snapshot, evidence=evidence, result=result,
                )
        checkpoint_status = (
            security_execution_checkpoint.ERROR
            if summary.get("error_type") else security_execution_checkpoint.DONE
        )
        self._finish_checkpoint(
            checkpoint,
            run.lease_token,
            checkpoint_status,
            reason_codes=reasons,
            summary=summary,
            result_id=result.id,
            error_type=str(summary.get("error_type") or ""),
        )
        return checkpoint_status

    def _mark_future_failure(self, checkpoint_id: Any, run: Any, exc: Exception) -> None:
        checkpoint = security_execution_checkpoint.objects(
            id=checkpoint_id,
            status=security_execution_checkpoint.RUNNING,
            lease_token=run.lease_token,
        ).first()
        if checkpoint:
            self._finish_checkpoint(
                checkpoint,
                run.lease_token,
                security_execution_checkpoint.ERROR,
                reason_codes=["worker_case_failure"],
                error_type=exc.__class__.__name__,
            )

    def execute_run(self, run: Any, adapter: ExecutionAdapter) -> str:
        policy = ExecutionPolicy.from_dict(run.execution_policy)
        lease_seconds = max(self.lease_seconds, policy.lease_seconds)
        if not heartbeat_execution(run.id, run.lease_token, lease_seconds):
            return "lease_lost"
        coordinator = HostPolicyCoordinator(policy, persisted=run.host_state)
        cancel_event = threading.Event()
        auth_failure_event = threading.Event()
        auth_failure_state: Dict[str, Any] = {}
        auth_failure_lock = threading.Lock()
        heartbeat = _HeartbeatThread(run.id, run.lease_token, lease_seconds)
        heartbeat.start()
        checkpoint_ids = list(security_execution_checkpoint.objects(
            run_id=run.id,
            status=security_execution_checkpoint.PENDING,
        ).order_by("ordinal").scalar("id"))
        cursor = 0
        futures: Dict[Any, Any] = {}
        last_sync = 0.0
        last_status_check = 0.0
        try:
            with ThreadPoolExecutor(max_workers=policy.max_workers) as executor:
                while cursor < len(checkpoint_ids) or futures:
                    if heartbeat.lost_event.is_set() or self.stop_event.is_set():
                        cancel_event.set()
                    if time.monotonic() - last_status_check >= 0.5:
                        current = security_test_run.objects(id=run.id).only("status").first()
                        if current and current.status == security_test_run.CANCEL_REQUESTED:
                            cancel_event.set()
                        last_status_check = time.monotonic()
                    while (
                        cursor < len(checkpoint_ids)
                        and len(futures) < policy.max_workers
                        and not cancel_event.is_set()
                        and not heartbeat.lost_event.is_set()
                        and not auth_failure_event.is_set()
                    ):
                        checkpoint_id = checkpoint_ids[cursor]
                        cursor += 1
                        future = executor.submit(
                            self._execute_checkpoint,
                            run,
                            checkpoint_id,
                            adapter,
                            policy,
                            coordinator,
                            cancel_event,
                            heartbeat.lost_event,
                            auth_failure_event,
                            auth_failure_state,
                            auth_failure_lock,
                        )
                        futures[future] = checkpoint_id
                    if not futures:
                        break
                    done, _ = wait(list(futures), timeout=0.5, return_when=FIRST_COMPLETED)
                    for future in done:
                        checkpoint_id = futures.pop(future)
                        try:
                            future.result()
                        except Exception as exc:
                            self._mark_future_failure(checkpoint_id, run, exc)
                    if time.monotonic() - last_sync >= 1.0:
                        self._sync_counts(run.id, coordinator)
                        last_sync = time.monotonic()

            if heartbeat.lost_event.is_set() or self.stop_event.is_set():
                security_execution_checkpoint.objects(
                    run_id=run.id,
                    status=security_execution_checkpoint.RUNNING,
                    lease_token=run.lease_token,
                ).update(
                    set__status=security_execution_checkpoint.PENDING,
                    set__reason_codes=["lease_lost"],
                    set__updated_at=utcnow(),
                    unset__lease_token=1,
                    unset__started_at=1,
                )
                self._sync_counts(run.id, coordinator)
                if self.stop_event.is_set() and not heartbeat.lost_event.is_set():
                    changed = security_test_run.objects(
                        id=run.id,
                        lease_token=run.lease_token,
                        status=security_test_run.RUNNING,
                    ).update_one(
                        set__status=security_test_run.QUEUED,
                        set__queued_at=utcnow(),
                        set__updated_at=utcnow(),
                        unset__lease_owner=1,
                        unset__lease_token=1,
                        unset__lease_expires_at=1,
                    )
                    if changed:
                        signal_execution_queue(run.id)
                    return "worker_stopped"
                return "lease_lost"

            if auth_failure_event.is_set() and not cancel_event.is_set():
                security_execution_checkpoint.objects(
                    run_id=run.id,
                    status=security_execution_checkpoint.RUNNING,
                    lease_token=run.lease_token,
                ).update(
                    set__status=security_execution_checkpoint.PENDING,
                    set__reason_codes=["account_context_unavailable"],
                    set__updated_at=utcnow(),
                    unset__lease_token=1,
                    unset__started_at=1,
                )
                counts = self._sync_counts(run.id, coordinator)
                error_type = str(auth_failure_state.get("error_type") or "AccountContextUnavailable")
                security_test_run.objects(id=run.id, lease_token=run.lease_token).update_one(
                    set__status=security_test_run.PAUSED,
                    set__summary=dict(counts, pause_reason="account_context_unavailable"),
                    set__auth_context_summary=dict(auth_failure_state),
                    set__last_error_type=error_type,
                    set__pause_code="auth_unavailable",
                    set__dependency_type="auth_profile",
                    set__dependency_id=str(run.auth_profile_revision_id or run.auth_context_ref or ""),
                    set__dependency_revision_id=str(run.auth_profile_revision_id or ""),
                    set__host_state=coordinator.snapshot(),
                    set__updated_at=utcnow(),
                    unset__lease_owner=1,
                    unset__lease_token=1,
                    unset__lease_expires_at=1,
                )
                _sync_parameter_relation_run_state(run, "needs_context", error_type)
                return security_test_run.PAUSED

            if cancel_event.is_set():
                now = utcnow()
                security_execution_checkpoint.objects(
                    run_id=run.id,
                    status__in=[security_execution_checkpoint.PENDING, security_execution_checkpoint.RUNNING],
                ).update(
                    set__status=security_execution_checkpoint.CANCELLED,
                    set__reason_codes=["cancel_requested"],
                    set__finished_at=now,
                    set__updated_at=now,
                    unset__lease_token=1,
                )
                final_status = security_test_run.CANCELLED
            else:
                final_status = security_test_run.DONE
            counts = self._sync_counts(run.id, coordinator)
            summary = dict(counts)
            aggregate = summarize_execution_records(
                list(security_execution_checkpoint.objects(run_id=run.id)),
                list(security_test_result.objects(run_id=run.id)),
            )
            summary.update({
                "processed_cases": counts["completed_cases"] + counts["failed_cases"] + counts["skipped_cases"],
                "host_state": coordinator.snapshot(),
                "requests_are_at_least_once": True,
            })
            summary.update(aggregate)
            security_test_run.objects(id=run.id, lease_token=run.lease_token).update_one(
                set__status=final_status,
                set__summary=summary,
                set__host_state=coordinator.snapshot(),
                set__finished_at=utcnow(),
                set__updated_at=utcnow(),
                unset__lease_owner=1,
                unset__lease_token=1,
                unset__lease_expires_at=1,
            )
            if final_status == security_test_run.CANCELLED:
                _sync_parameter_relation_run_state(run, "automatic_failed", "cancelled")
            return final_status
        finally:
            heartbeat.close()

    def _handle_dispatch_failure(self, run: Any, exc: Exception) -> None:
        security_execution_checkpoint.objects(
            run_id=run.id,
            status=security_execution_checkpoint.RUNNING,
            lease_token=run.lease_token,
        ).update(
            set__status=security_execution_checkpoint.PENDING,
            set__reason_codes=["worker_dispatch_failure"],
            set__updated_at=utcnow(),
            unset__lease_token=1,
            unset__started_at=1,
        )
        retryable = int(run.dispatch_attempt or 0) < int(run.max_dispatch_attempts or 3)
        status = security_test_run.QUEUED if retryable else security_test_run.FAILED
        updates = {
            "set__status": status,
            "set__last_error_type": exc.__class__.__name__,
            "set__updated_at": utcnow(),
            "unset__lease_owner": 1,
            "unset__lease_token": 1,
            "unset__lease_expires_at": 1,
        }
        if retryable:
            updates["set__queued_at"] = utcnow()
        else:
            updates["set__finished_at"] = utcnow()
        security_test_run.objects(id=run.id, lease_token=run.lease_token).update_one(**updates)
        if retryable:
            signal_execution_queue(run.id)
        else:
            _sync_parameter_relation_run_state(run, "automatic_failed", exc.__class__.__name__)

    def run_once(self) -> bool:
        recover_expired_executions(queue_name=self.queue_name)
        run = claim_next_execution(self.worker_id, self.queue_name, self.lease_seconds)
        if not run:
            return False
        adapter = self.adapters.get(str(run.adapter_id or ""))
        if adapter is None:
            self._pause_claimed_run(run, UnsupportedExecutionAdapter("execution adapter is not registered"))
            return True
        try:
            policy = ExecutionPolicy.from_dict(run.execution_policy)
            self._preflight(run, adapter, policy)
        except ExecutionAdapterError as exc:
            self._pause_claimed_run(run, exc)
            return True
        except AccountContextError as exc:
            self._pause_claimed_run(run, exc, self._unavailable_auth_summary(run, exc))
            return True
        try:
            self.execute_run(run, adapter)
        except Exception as exc:
            self._handle_dispatch_failure(run, exc)
        return True

    def wait_for_signal(self, timeout_seconds: int = 5) -> bool:
        timeout_seconds = max(1, min(60, int(timeout_seconds)))
        try:
            client = redis.Redis(connection_pool=redis_pool)
            return bool(client.blpop(WAKEUP_KEY, timeout=timeout_seconds))
        except Exception:
            return self.stop_event.wait(timeout_seconds)

    def run_forever(self, poll_seconds: int = 5) -> None:
        recover_expired_executions(queue_name=self.queue_name)
        while not self.stop_event.is_set():
            if self.run_once():
                continue
            self.wait_for_signal(poll_seconds)

    def stop(self) -> None:
        self.stop_event.set()


def retry_execution(run_id: Any,
                    checkpoint_statuses: Sequence[str] = (
                        security_execution_checkpoint.ERROR,
                        security_execution_checkpoint.SKIPPED,
                        security_execution_checkpoint.CANCELLED,
                    ),
                    operator: str = "") -> Tuple[Any, bool]:
    old = security_test_run.objects(id=ObjectId(str(run_id)), scheduler_managed=True).first()
    if not old:
        raise ValueError("scheduled run not found")
    snapshot_ids = list(security_execution_checkpoint.objects(
        run_id=old.id,
        status__in=list(checkpoint_statuses),
    ).order_by("ordinal").scalar("snapshot_id"))
    if not snapshot_ids:
        raise ValueError("no checkpoints match retry statuses")
    context = ExecutionContext(
        project_id=old.project_id,
        env_id=old.env_id or "",
        account_id=old.account_id or "",
        auth_mode=old.auth_mode,
        auth_provider_id=old.auth_provider_id or "",
        auth_context_ref=old.auth_context_ref or "",
        auth_profile_revision_id=old.auth_profile_revision_id or "",
        auth_realm_revision_id=old.auth_realm_revision_id or "",
        auth_adapter_version_id=old.auth_adapter_version_id or "",
        adapter_id=old.adapter_id or "snapshot_batch",
        adapter_version=old.adapter_version or "1",
        plan_version=old.plan_version or "",
        plan_sha256=old.plan_sha256 or "",
        parent_run_id=old.id,
        retry_of_run_id=old.id,
    )
    policy = ExecutionPolicy.from_dict(old.execution_policy)
    retry_key = hashlib.sha256(
        "retry:{}:{}".format(old.id, uuid.uuid4().hex).encode("utf-8")
    ).hexdigest()
    return enqueue_snapshot_batch(
        name="{} retry".format(old.name),
        check_type=old.check_type,
        context=context,
        snapshot_ids=snapshot_ids,
        policy=policy,
        scope={"retry_of_run_id": str(old.id), "retry_statuses": list(checkpoint_statuses)},
        evidence_ref=old.evidence_ref or "",
        operator=operator,
        priority=old.priority,
        queue_name=old.queue_name,
        idempotency_key=retry_key,
    )
