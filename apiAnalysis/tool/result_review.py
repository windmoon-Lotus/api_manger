"""
Result review workflow.

Machine results (security_test_result) are immutable. Human and rule
dispositions are recorded as append-only result_review_event documents.
Confirmed results can be promoted to vulnerability_finding.
"""
import datetime
import logging
from urllib.parse import urlsplit

from bson import ObjectId

from ..db.collection import (
    result_review_event,
    security_test_result,
    vulnerability_finding,
    finding_event,
)

logger = logging.getLogger(__name__)

REVIEWABLE_VERDICTS = (
    "potential_vuln", "need_review", "review",
    "PARTIAL_IDOR_PARAM", "UNAUTH_EXPOSURE",
)

TERMINAL_REVIEW_ACTIONS = (
    result_review_event.CONFIRM,
    result_review_event.REJECT,
    result_review_event.DUPLICATE,
)

VERDICT_OUTCOME_MAP = {
    # Standard verdicts
    "potential_vuln": "candidate",
    "need_review": "review",
    "no_vuln": "pass",
    "not_evaluable": "blocked",
    "error": "error",
    # IDOR / privilege engine verdicts
    "isolated_not_found": "pass",
    "isolated_blocked": "pass",
    "blocked_own_data": "pass",
    "relation_verified": "informational",
    "blocked_empty": "blocked",
    "rejected_input": "blocked",
    "PARTIAL_IDOR_PARAM": "candidate",
    "UNAUTH_EXPOSURE": "candidate",
    "review": "review",
}


def project_outcome_class(verdict):
    """Map a machine verdict to its outcome_class projection."""
    return VERDICT_OUTCOME_MAP.get(verdict, "informational")


def backfill_outcome_class(run_id=None, batch_size=500):
    """Backfill outcome_class for results that lack it."""
    qs = security_test_result.objects(outcome_class__in=[None, ""])
    if run_id:
        qs = qs.filter(run_id=run_id)
    updated = 0
    for result in qs.limit(batch_size):
        result.outcome_class = project_outcome_class(result.verdict)
        result.save()
        updated += 1
    if updated:
        logger.info("backfilled outcome_class for %d results", updated)
    return updated


def _normalized_target_path(result):
    target = result.target if isinstance(getattr(result, "target", None), dict) else {}
    value = ""
    for key in ("path", "cleanup_path", "endpoint_name", "url"):
        if target.get(key):
            value = str(target[key]).strip()
            break
    if not value:
        return ""
    if "://" in value:
        value = urlsplit(value).path
    parts = [part for part in value.strip("/").split("/") if part]
    while parts and (parts[-1].isdigit() or (parts[-1].startswith("{") and parts[-1].endswith("}"))):
        parts.pop()
    return "/" + "/".join(parts) if parts else value


def review_result_identity(result):
    """Stable case identity used to let a newer conclusion supersede an old one."""
    related_pathid = getattr(result, "related_pathid", None)
    snapshot_id = getattr(result, "snapshot_id", None)
    endpoint = (
        "pathid:{}".format(related_pathid)
        if related_pathid is not None
        else _normalized_target_path(result)
    )
    if not endpoint and snapshot_id:
        endpoint = "snapshot:{}".format(snapshot_id)
    if not endpoint:
        endpoint = "case:{}".format(str(getattr(result, "case_name", "") or ""))
    target = result.target if isinstance(getattr(result, "target", None), dict) else {}
    account_scope = tuple(
        str(target.get(key) or "")
        for key in (
            "baseline_account_id", "source_account_id", "target_account_id",
            "actor_role", "resource_family",
        )
    )
    return (
        str(getattr(result, "project_id", "") or ""),
        str(getattr(result, "env_id", "") or ""),
        str(getattr(result, "check_type", "") or ""),
        endpoint,
        str(getattr(result, "auth_mode", "") or ""),
        str(getattr(result, "account_id", "") or ""),
        account_scope,
    )


def review_target_label(result):
    """Return a value-free endpoint label so similar cases are distinguishable."""
    target = result.target if isinstance(getattr(result, "target", None), dict) else {}
    path = ""
    for key in ("path", "cleanup_path", "endpoint_name", "url"):
        if target.get(key):
            path = str(target[key]).strip()
            break
    if "://" in path:
        path = urlsplit(path).path
    if path and not path.startswith("/"):
        path = "/" + path
    pathid = getattr(result, "related_pathid", None)
    if not path and pathid is not None:
        path = "PathId {}".format(pathid)
    method = str(getattr(result, "method", "") or target.get("method") or "").upper()
    return "{} {}".format(method, path).strip() or "未记录目标"


def latest_review_candidates(results):
    """Project newest-first results into the currently actionable candidates."""
    seen = set()
    candidates = []
    for result in results:
        identity = review_result_identity(result)
        if identity in seen:
            continue
        seen.add(identity)
        if result.verdict in REVIEWABLE_VERDICTS:
            candidates.append(result)
    return candidates


def unresolved_review_candidates(candidates, terminal_result_ids=()):
    terminal_ids = {str(value) for value in terminal_result_ids}
    return [
        item for item in candidates
        if str(getattr(item, "id", "")) not in terminal_ids
        and not getattr(item, "related_vuln_id", None)
    ]


def get_review_queue(project_id=None, run_id=None, limit=100):
    """Return unresolved latest conclusions that need human review, newest first.

    A later pass/blocked/error conclusion for the same project, environment,
    endpoint and account scope supersedes an older candidate. Confirmed,
    rejected and duplicate results remain immutable but leave the active queue.
    Suppression is deliberately scoped to the selected run when ``run_id`` is
    supplied so historical-run inspection remains reproducible.
    """
    qs = security_test_result.objects()
    if project_id:
        qs = qs.filter(project_id=project_id)
    if run_id:
        qs = qs.filter(run_id=run_id)
    candidates = latest_review_candidates(qs.order_by("-ctime"))
    candidate_ids = [item.id for item in candidates if getattr(item, "id", None)]
    terminal_ids = set()
    if candidate_ids:
        terminal_ids = {
            str(value)
            for value in result_review_event.objects(
                result_id__in=candidate_ids,
                action__in=TERMINAL_REVIEW_ACTIONS,
            ).scalar("result_id")
        }
    open_candidates = unresolved_review_candidates(candidates, terminal_ids)
    return open_candidates if limit is None else open_candidates[:max(0, int(limit))]


def get_review_events(result_id):
    return result_review_event.objects(result_id=result_id).order_by("-ctime")


def add_review_event(
    result_id,
    action,
    reviewer,
    run_id=None,
    project_id=None,
    reviewer_role=None,
    reason=None,
    reason_codes=None,
    finding_id=None,
    duplicate_of_result_id=None,
    evidence_note=None,
):
    result = security_test_result.objects(id=result_id).first()
    if result is None:
        raise ValueError(f"result {result_id} not found")

    event = result_review_event(
        result_id=result_id,
        run_id=run_id or result.run_id,
        project_id=project_id or result.project_id,
        action=action,
        reviewer=reviewer,
        reviewer_role=reviewer_role,
        reason=reason,
        reason_codes=reason_codes or [],
        finding_id=finding_id,
        duplicate_of_result_id=duplicate_of_result_id,
        evidence_note=evidence_note,
    )
    event.save()
    logger.info(
        "review event [%s] on result %s by %s", action, result_id, reviewer
    )
    return event


def confirm_result(
    result_id,
    reviewer,
    title=None,
    severity=None,
    reason=None,
    reviewer_role=None,
):
    """Confirm a result as a real issue and promote to a vulnerability finding."""
    result = security_test_result.objects(id=result_id).first()
    if result is None:
        raise ValueError(f"result {result_id} not found")
    if result.verdict not in REVIEWABLE_VERDICTS:
        raise ValueError(
            f"result verdict is {result.verdict}, only {REVIEWABLE_VERDICTS} can be confirmed"
        )

    if result.related_vuln_id:
        existing = vulnerability_finding.objects(id=result.related_vuln_id).first()
        if existing and existing.status not in (
            vulnerability_finding.FALSE_POSITIVE,
            vulnerability_finding.VERIFIED_FIXED,
        ):
            event = add_review_event(
                result_id,
                result_review_event.CONFIRM,
                reviewer,
                reviewer_role=reviewer_role,
                reason=reason or f"already linked to finding {existing.id}",
                finding_id=existing.id,
            )
            return existing, event

    finding_title = title or result.case_name or f"Confirmed: {result.check_type}"
    finding = vulnerability_finding(
        title=finding_title,
        project_id=result.project_id or "",
        env_id=result.env_id,
        check_type=result.check_type,
        severity=severity or result.severity or "medium",
        confidence=result.confidence,
        status=vulnerability_finding.OPEN,
        result_ids=[result.id],
        run_ids=[result.run_id] if result.run_id else [],
        affected_endpoints=[result.target] if result.target else [],
        evidence_summary=result.evidence_summary or {},
        evidence_ref=result.evidence_ref,
        found_by=reviewer,
    )
    finding.save()

    finding_event(
        finding_id=finding.id,
        event_type=finding_event.CREATED,
        to_status=vulnerability_finding.OPEN,
        actor=reviewer,
        reason=reason or "confirmed from review queue",
        related_run_id=result.run_id,
        related_result_ids=[result.id],
    ).save()

    security_test_result.objects(id=result_id).update(
        set__related_vuln_id=finding.id
    )

    event = add_review_event(
        result_id,
        result_review_event.CONFIRM,
        reviewer,
        reviewer_role=reviewer_role,
        reason=reason,
        finding_id=finding.id,
    )
    logger.info(
        "confirmed result %s -> finding %s by %s", result_id, finding.id, reviewer
    )
    return finding, event


def reject_result(result_id, reviewer, reason=None, reviewer_role=None):
    """Mark a result as false positive."""
    event = add_review_event(
        result_id,
        result_review_event.REJECT,
        reviewer,
        reviewer_role=reviewer_role,
        reason=reason or "false positive",
    )
    return event


def mark_duplicate(result_id, duplicate_of_result_id, reviewer, reason=None):
    event = add_review_event(
        result_id,
        result_review_event.DUPLICATE,
        reviewer,
        reason=reason,
        duplicate_of_result_id=duplicate_of_result_id,
    )
    return event
