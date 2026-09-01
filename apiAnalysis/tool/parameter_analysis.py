"""Durable local-only full-project parameter relation analysis.

The analysis worker intentionally does not use the HTTP execution scheduler:
it reads imported schemas, saved request fixtures and existing observations,
then persists preprocessing projections.  No business request is sent.
"""
from __future__ import annotations

import datetime as dt
import logging
import socket
import threading
import time
import uuid
from collections import Counter
from typing import Any, Dict, Optional, Tuple

from apiAnalysis.db.collection import (
    ProjectAuthProfile,
    ProjectEnvironment,
    parameter_relation,
    parameter_relation_analysis_run,
)
# Kept importable for compatibility with older tests/extensions. The P1 worker
# no longer invokes this write-capable discovery path.
from apiAnalysis.tool.interface_knowledge import discover_project_relations  # noqa: F401
from apiAnalysis.tool.parameter_relation_workbench import preprocess_relation
from apiAnalysis.tool.unified_rule_analysis import (
    ANALYSIS_VERSION,
    UnifiedRuleAnalysisError,
    analyze_project,
    create_non_executable_plan_drafts,
    persist_typed_outputs,
)


logger = logging.getLogger(__name__)


def utcnow() -> dt.datetime:
    return dt.datetime.utcnow()


def _text(value: Any) -> str:
    return str(value or "").strip()


def enqueue_relation_analysis(
    project_id: str,
    *,
    env_id: str = "",
    source_profile_id: str = "",
    consumer_profile_id: str = "",
    operator: str = "",
) -> Tuple[parameter_relation_analysis_run, bool]:
    """Create or reuse one active full-project local analysis run."""
    project_id = _text(project_id)
    if not project_id:
        raise ValueError("请选择需要分析的项目")

    existing = parameter_relation_analysis_run.objects(
        project_id=project_id,
        status__in=list(parameter_relation_analysis_run.ACTIVE_STATUSES),
    ).order_by("-updated_at").first()
    if existing:
        return existing, False

    environment = None
    if env_id:
        environment = ProjectEnvironment.objects(
            project_id=project_id,
            env_id=_text(env_id),
            active=True,
        ).first()
        if not environment:
            raise ValueError("所选环境不存在或已停用")

    for label, profile_id in (
        ("来源", source_profile_id),
        ("消费", consumer_profile_id),
    ):
        if profile_id and not ProjectAuthProfile.objects(
            project_id=project_id,
            profile_id=_text(profile_id),
            active=True,
        ).first():
            raise ValueError("{}认证方案不存在或已停用".format(label))

    now = utcnow()
    run = parameter_relation_analysis_run(
        project_id=project_id,
        env_id=_text(getattr(environment, "env_id", "") or env_id),
        source_profile_id=_text(source_profile_id),
        consumer_profile_id=_text(consumer_profile_id),
        status=parameter_relation_analysis_run.STATUS_QUEUED,
        phase="queued",
        operator=_text(operator)[:120],
        status_counts={},
        discovery_summary={},
        result_summary={},
        created_at=now,
        updated_at=now,
    )
    run.save()
    return run, True


def cancel_relation_analysis(run_id: Any, *, project_id: str = "") -> bool:
    query: Dict[str, Any] = {
        "id": run_id,
        "status__in": [
            parameter_relation_analysis_run.STATUS_QUEUED,
            parameter_relation_analysis_run.STATUS_RUNNING,
        ],
    }
    if project_id:
        query["project_id"] = _text(project_id)
    return bool(parameter_relation_analysis_run.objects(**query).update_one(
        set__status=parameter_relation_analysis_run.STATUS_CANCEL_REQUESTED,
        set__phase="cancel_requested",
        set__updated_at=utcnow(),
    ))


class ParameterRelationAnalysisWorker:
    """Single durable worker for local relation discovery and preprocessing."""

    def __init__(
        self,
        *,
        worker_id: str = "",
        poll_seconds: float = 2.0,
        lease_seconds: int = 60,
    ):
        self.worker_id = worker_id or "{}:{}".format(
            socket.gethostname(), uuid.uuid4().hex[:8],
        )
        self.poll_seconds = max(0.2, float(poll_seconds))
        self.lease_seconds = max(30, int(lease_seconds))
        self.stop_event = threading.Event()

    def stop(self) -> None:
        self.stop_event.set()

    def _lease_until(self) -> dt.datetime:
        return utcnow() + dt.timedelta(seconds=self.lease_seconds)

    def recover_abandoned(self) -> int:
        now = utcnow()
        return int(parameter_relation_analysis_run.objects(__raw__={
            "status": parameter_relation_analysis_run.STATUS_RUNNING,
            "$or": [
                {"lease_expires_at": {"$lte": now}},
                {"lease_expires_at": None},
                {"lease_expires_at": {"$exists": False}},
            ],
        }).update(
            set__status=parameter_relation_analysis_run.STATUS_QUEUED,
            set__phase="queued",
            set__updated_at=now,
            unset__worker_id=1,
            unset__lease_expires_at=1,
        ))

    def _claim(self) -> Optional[parameter_relation_analysis_run]:
        now = utcnow()
        cancelled = parameter_relation_analysis_run.objects(
            status=parameter_relation_analysis_run.STATUS_CANCEL_REQUESTED,
        ).modify(
            new=True,
            set__status=parameter_relation_analysis_run.STATUS_CANCELLED,
            set__phase="cancelled",
            set__finished_at=now,
            set__updated_at=now,
            unset__worker_id=1,
            unset__lease_expires_at=1,
        )
        if cancelled:
            return None
        return parameter_relation_analysis_run.objects(
            status=parameter_relation_analysis_run.STATUS_QUEUED,
        ).order_by("created_at").modify(
            new=True,
            set__status=parameter_relation_analysis_run.STATUS_RUNNING,
            set__phase="discovery",
            set__worker_id=self.worker_id,
            set__lease_expires_at=self._lease_until(),
            set__started_at=now,
            set__updated_at=now,
        )

    def _heartbeat(
        self,
        run: parameter_relation_analysis_run,
        *,
        phase: str,
        processed: int,
        cursor: Any,
        counts: Counter,
        error_type: str = "",
        error_reference: str = "",
    ) -> bool:
        updates: Dict[str, Any] = {
            "set__phase": _text(phase)[:60],
            "set__processed_relations": max(0, int(processed)),
            "set__status_counts": dict(counts),
            "set__lease_expires_at": self._lease_until(),
            "set__updated_at": utcnow(),
        }
        if cursor is not None:
            updates["set__cursor_relation_id"] = cursor
        if error_type:
            updates["set__error_type"] = _text(error_type)[:120]
        if error_reference:
            updates["set__error_reference"] = _text(error_reference)[:32]
        return bool(parameter_relation_analysis_run.objects(
            id=run.id,
            status=parameter_relation_analysis_run.STATUS_RUNNING,
            worker_id=self.worker_id,
        ).update_one(**updates))

    @staticmethod
    def _profiles(run: parameter_relation_analysis_run):
        environment = None
        if run.env_id:
            environment = ProjectEnvironment.objects(
                project_id=run.project_id,
                env_id=run.env_id,
                active=True,
            ).first()
            if not environment:
                raise ValueError("分析环境已不存在或停用")

        def profile(profile_id: str):
            if not profile_id:
                return None
            value = ProjectAuthProfile.objects(
                project_id=run.project_id,
                profile_id=profile_id,
                active=True,
            ).first()
            if not value:
                raise ValueError("分析使用的认证方案已不存在或停用")
            return value

        return environment, profile(run.source_profile_id), profile(run.consumer_profile_id)

    def _cancelled(self, run: parameter_relation_analysis_run) -> bool:
        current = parameter_relation_analysis_run.objects(id=run.id).only("status").first()
        return bool(
            not current
            or current.status == parameter_relation_analysis_run.STATUS_CANCEL_REQUESTED
            or self.stop_event.is_set()
        )

    def _finish_cancelled(self, run: parameter_relation_analysis_run) -> None:
        now = utcnow()
        if self.stop_event.is_set():
            parameter_relation_analysis_run.objects(
                id=run.id,
                status=parameter_relation_analysis_run.STATUS_RUNNING,
                worker_id=self.worker_id,
            ).update_one(
                set__status=parameter_relation_analysis_run.STATUS_QUEUED,
                set__phase="queued",
                set__updated_at=now,
                unset__worker_id=1,
                unset__lease_expires_at=1,
            )
            return
        parameter_relation_analysis_run.objects(
            id=run.id,
            status__in=[
                parameter_relation_analysis_run.STATUS_RUNNING,
                parameter_relation_analysis_run.STATUS_CANCEL_REQUESTED,
            ],
        ).update_one(
            set__status=parameter_relation_analysis_run.STATUS_CANCELLED,
            set__phase="cancelled",
            set__finished_at=now,
            set__updated_at=now,
            unset__worker_id=1,
            unset__lease_expires_at=1,
        )

    def execute(self, run: parameter_relation_analysis_run) -> str:
        # Full-project deterministic evaluation can exceed the normal short
        # queue lease. Extend only this CPU-bound phase; persistence resumes
        # with the configured heartbeat lease below.
        parameter_relation_analysis_run.objects(
            id=run.id,
            status=parameter_relation_analysis_run.STATUS_RUNNING,
            worker_id=self.worker_id,
        ).update_one(
            set__phase="rule_projection",
            set__lease_expires_at=utcnow() + dt.timedelta(
                seconds=max(self.lease_seconds, 900),
            ),
            set__updated_at=utcnow(),
        )
        analysis = analyze_project(
            run.project_id,
            env_id=run.env_id,
            profile_id=run.source_profile_id,
        )
        if (
            run.input_watermark_sha256
            and run.input_watermark_sha256 != analysis.input_watermark_sha256
        ):
            raise UnifiedRuleAnalysisError(
                "analysis input changed after the persistent cursor was established"
            )
        run.env_id = analysis.env_id
        rule_summary = {
            "analysis_version": ANALYSIS_VERSION,
            "rule_bundle_sha256": analysis.rule_bundle_sha256,
            "input_watermark_sha256": analysis.input_watermark_sha256,
            "projection": dict(analysis.summary.get("projection") or {}),
            "relation_projection": dict(analysis.summary.get("relation_projection") or {}),
            "output_counts": dict(analysis.summary.get("output_counts") or {}),
            "business_network_requests": 0,
        }
        comparison = dict(analysis.summary.get("legacy_diff") or {})
        parameter_relation_analysis_run.objects(
            id=run.id,
            status=parameter_relation_analysis_run.STATUS_RUNNING,
            worker_id=self.worker_id,
        ).update_one(
            set__env_id=analysis.env_id,
            set__analysis_version=ANALYSIS_VERSION,
            set__profile_revision_id=analysis.profile_revision_id,
            set__rule_bundle_sha256=analysis.rule_bundle_sha256,
            set__input_watermark_sha256=analysis.input_watermark_sha256,
            set__rule_summary=rule_summary,
            set__comparison_summary=comparison,
            set__phase="rule_persistence",
            set__cursor_phase=str(run.cursor_phase or "rule_persistence"),
            set__updated_at=utcnow(),
            set__lease_expires_at=self._lease_until(),
        )

        if str(run.cursor_phase or "") == "preprocessing":
            persistence = dict(run.persistence_summary or {})
            drafts = dict(run.plan_draft_summary or {})
        else:
            progress_state = {"count": 0}

            def report_rule_progress(cursor_key: str, counts: Dict[str, int]) -> None:
                progress_state["count"] += 1
                if progress_state["count"] % 100:
                    return
                if self._cancelled(run):
                    raise InterruptedError("analysis cancellation requested")
                updated = parameter_relation_analysis_run.objects(
                    id=run.id,
                    status=parameter_relation_analysis_run.STATUS_RUNNING,
                    worker_id=self.worker_id,
                ).update_one(
                    set__cursor_phase="rule_persistence",
                    set__cursor_key=str(cursor_key)[:500],
                    set__persistence_summary=dict(counts),
                    set__phase="rule_persistence",
                    set__updated_at=utcnow(),
                    set__lease_expires_at=self._lease_until(),
                )
                if not updated:
                    raise InterruptedError("analysis lease was lost")

            try:
                persistence = persist_typed_outputs(
                    analysis,
                    resume_after=str(run.cursor_key or "")
                    if str(run.cursor_phase or "") == "rule_persistence" else "",
                    progress_callback=report_rule_progress,
                    initial_counts=dict(run.persistence_summary or {}),
                )
            except InterruptedError:
                self._finish_cancelled(run)
                return "cancelled"
            drafts = create_non_executable_plan_drafts(
                analysis, created_by=run.operator or "rule-engine",
            )
            parameter_relation_analysis_run.objects(
                id=run.id,
                status=parameter_relation_analysis_run.STATUS_RUNNING,
                worker_id=self.worker_id,
            ).update_one(
                set__persistence_summary=dict(persistence),
                set__plan_draft_summary=dict(drafts),
                set__cursor_phase="preprocessing",
                set__phase="preprocessing",
                set__updated_at=utcnow(),
                set__lease_expires_at=self._lease_until(),
                unset__cursor_key=1,
            )

        discovery = {
            "engine": ANALYSIS_VERSION,
            "candidates": sum(
                int(value) for key, value in dict(analysis.summary.get("output_counts") or {}).items()
                if key.endswith("Candidate")
            ),
            "created": int(persistence.get("relation_created") or 0),
            "updated": 0,
            "preserved": int(persistence.get("relation_protected") or 0)
            + int(persistence.get("relation_existing_create_only") or 0),
            "stale": 0,
        }
        total = parameter_relation.objects(
            project_id=run.project_id,
            manual_decision__ne="deleted",
        ).count()
        parameter_relation_analysis_run.objects(
            id=run.id,
            status=parameter_relation_analysis_run.STATUS_RUNNING,
            worker_id=self.worker_id,
        ).update_one(
            set__discovery_summary={
                key: int(discovery.get(key) or 0)
                for key in ("candidates", "created", "updated", "preserved", "stale")
            },
            set__total_relations=int(total),
            set__phase="preprocessing",
            set__updated_at=utcnow(),
            set__lease_expires_at=self._lease_until(),
        )

        # P1 deliberately stops at offline candidates and non-executable plan
        # drafts.  The former loop called preprocess_relation() for every row,
        # which projected candidates toward auto_ready online validation and
        # made human/execution readiness part of this offline phase. Preserve
        # protected/legacy states and mark only P1-created machine relations as
        # unverified candidates in one guarded update.
        marked = parameter_relation.objects(
            project_id=run.project_id,
            discovery_source="abstract_rule_p1",
            verified=False,
            manual_decision__in=[None, ""],
        ).update(
            set__preprocess_version=ANALYSIS_VERSION,
            set__preprocess_status="candidate_unverified",
            set__preprocess_reason_codes=[
                "ABSTRACT_RULE_CANDIDATE",
                "ONLINE_VALIDATION_NOT_SCHEDULED",
            ],
            set__approval_status="not_required",
            set__last_preprocessed_at=utcnow(),
        )
        counts: Counter = Counter({"candidate_unverified": int(marked)})
        processed = int(total)

        current_counts = Counter(
            (item.preprocess_status or "pending")
            for item in parameter_relation.objects(
                project_id=run.project_id,
                manual_decision__ne="deleted",
            ).only("preprocess_status")
        )
        pair_count = len({
            (item.res_pathid, item.req_pathid)
            for item in parameter_relation.objects(
                project_id=run.project_id,
                manual_decision__ne="deleted",
            ).only("res_pathid", "req_pathid")
        })
        now = utcnow()
        parameter_relation_analysis_run.objects(
            id=run.id,
            status=parameter_relation_analysis_run.STATUS_RUNNING,
            worker_id=self.worker_id,
        ).update_one(
            set__status=parameter_relation_analysis_run.STATUS_DONE,
            set__phase="done",
            set__processed_relations=processed,
            set__status_counts=dict(counts),
            set__result_summary={
                "relation_count": sum(current_counts.values()),
                "pair_count": pair_count,
                "status_counts": dict(current_counts),
                "item_error_count": int(counts.get("analysis_error") or 0),
                "analysis_version": ANALYSIS_VERSION,
                "rule_bundle_sha256": analysis.rule_bundle_sha256,
                "input_watermark_sha256": analysis.input_watermark_sha256,
                "rule_output_counts": dict(analysis.summary.get("output_counts") or {}),
                "legacy_diff": comparison,
                "typed_persistence": dict(persistence),
                "plan_drafts": dict(drafts),
                "business_network_requests": 0,
                "finding_writes": 0,
            },
            set__cursor_phase="done",
            set__finished_at=now,
            set__updated_at=now,
            unset__worker_id=1,
            unset__lease_expires_at=1,
        )
        return "done"

    def _fail(self, run: parameter_relation_analysis_run, exc: Exception) -> None:
        reference = uuid.uuid4().hex[:12]
        logger.exception("relation analysis failed ref=%s run=%s", reference, run.id)
        now = utcnow()
        parameter_relation_analysis_run.objects(
            id=run.id,
            status=parameter_relation_analysis_run.STATUS_RUNNING,
            worker_id=self.worker_id,
        ).update_one(
            set__status=parameter_relation_analysis_run.STATUS_FAILED,
            set__phase="failed",
            set__error_type=exc.__class__.__name__[:120],
            set__error_reference=reference,
            set__finished_at=now,
            set__updated_at=now,
            unset__worker_id=1,
            unset__lease_expires_at=1,
        )

    def run_once(self) -> str:
        run = self._claim()
        if not run:
            return "idle"
        try:
            return self.execute(run)
        except Exception as exc:
            self._fail(run, exc)
            return "failed"

    def run_forever(self) -> None:
        self.recover_abandoned()
        while not self.stop_event.is_set():
            result = self.run_once()
            if result == "idle":
                self.stop_event.wait(self.poll_seconds)
