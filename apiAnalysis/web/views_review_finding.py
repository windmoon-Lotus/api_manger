"""
Result review queue and vulnerability finding lifecycle routes.

Provides the human review workflow for machine results and the
vulnerability finding management interface.
"""
import logging

from bson import ObjectId
from flask import request, redirect, url_for, session

from . import bp_web
from ..common.decorators import login_check, templated
from ..common.func import is_manager
from ..db.collection import (
    ApiProject,
    security_test_result,
    result_review_event,
    vulnerability_finding,
    security_test_run,
)
from ..tool.result_review import (
    REVIEWABLE_VERDICTS,
    add_review_event,
    confirm_result,
    get_review_events,
    get_review_queue,
    mark_duplicate,
    reject_result,
    review_target_label,
)
from ..tool.vulnerability_lifecycle import (
    add_comment,
    assign_finding,
    finding_summary,
    get_finding,
    get_finding_events,
    list_findings,
    evaluate_finding_retest,
    schedule_finding_retest,
    transition_finding,
)

logger = logging.getLogger(__name__)


@bp_web.route("/review-queue", methods=["GET", "POST"])
@login_check
@templated("/review-queue.html")
def review_queue():
    projects = list(ApiProject.objects(status="active").order_by("name"))
    project_id = request.args.get("project_id") or request.form.get("project_id") or ""
    run_id = request.args.get("run_id") or ""

    if request.method == "POST":
        if not is_manager():
            return {"projects": projects, "error": "权限不足"}, 403
        action = request.form.get("action", "")
        result_id = request.form.get("result_id", "")
        result_ids = request.form.getlist("result_ids")
        reviewer = session.get("username", "unknown")
        try:
            if action == "batch_confirm":
                count = 0
                failed = 0
                for rid in result_ids:
                    try:
                        confirm_result(
                            rid, reviewer,
                            severity=request.form.get("severity", "").strip() or None,
                            reason=request.form.get("reason", "").strip() or "batch confirm",
                        )
                        count += 1
                    except Exception:
                        failed += 1
                        logger.exception("batch review confirmation failed for result %s", rid)
                level = "success" if not failed else "error"
                session["review_notice"] = {
                    "level": level,
                    "text": f"批量确认 {count} 条为漏洞，失败 {failed} 条",
                }
            elif action == "batch_reject":
                count = 0
                failed = 0
                for rid in result_ids:
                    try:
                        reject_result(rid, reviewer, reason=request.form.get("reason", "").strip() or "batch reject")
                        count += 1
                    except Exception:
                        failed += 1
                        logger.exception("batch review rejection failed for result %s", rid)
                level = "success" if not failed else "error"
                session["review_notice"] = {
                    "level": level,
                    "text": f"批量拒绝 {count} 条，失败 {failed} 条",
                }
            elif action == "confirm":
                finding, event = confirm_result(
                    result_id,
                    reviewer,
                    title=request.form.get("title", "").strip() or None,
                    severity=request.form.get("severity", "").strip() or None,
                    reason=request.form.get("reason", "").strip() or None,
                )
                session["review_notice"] = {
                    "level": "success",
                    "text": f"已确认并创建漏洞 #{finding.id}",
                }
            elif action == "reject":
                reject_result(
                    result_id, reviewer,
                    reason=request.form.get("reason", "").strip() or None,
                )
                session["review_notice"] = {"level": "success", "text": "已标记为误报"}
            elif action == "need_more_evidence":
                add_review_event(
                    result_id, result_review_event.NEED_MORE_EVIDENCE, reviewer,
                    reason=request.form.get("reason", "").strip() or None,
                )
                session["review_notice"] = {"level": "success", "text": "已标记为证据不足"}
            elif action == "comment":
                add_review_event(
                    result_id, result_review_event.COMMENT, reviewer,
                    evidence_note=request.form.get("note", "").strip() or None,
                )
                session["review_notice"] = {"level": "success", "text": "评论已添加"}
            else:
                raise ValueError("未知复核操作")
        except Exception as exc:
            logger.exception("review action failed")
            session["review_notice"] = {"level": "error", "text": str(exc)[:200]}
        return redirect(url_for("web.review_queue", project_id=project_id, run_id=run_id))

    notice = session.pop("review_notice", None)
    run_object_id = None
    invalid_run_id = False
    if run_id:
        if ObjectId.is_valid(run_id):
            run_object_id = ObjectId(run_id)
        else:
            invalid_run_id = True
            notice = notice or {"level": "error", "text": "运行 ID 格式无效"}
    results = [] if invalid_run_id else list(get_review_queue(
        project_id=project_id or None, run_id=run_object_id,
    ))
    result_events = {}
    result_targets = {}
    for r in results:
        result_targets[str(r.id)] = review_target_label(r)
        events = list(get_review_events(r.id))
        if events:
            result_events[str(r.id)] = events
    return {
        "projects": projects,
        "project_id": project_id,
        "run_id": run_id,
        "results": results,
        "result_events": result_events,
        "result_targets": result_targets,
        "notice": notice,
        "can_manage": is_manager(),
        "reviewable_verdicts": REVIEWABLE_VERDICTS,
    }


@bp_web.route("/findings", methods=["GET", "POST"])
@login_check
@templated("/findings.html")
def findings_list():
    projects = list(ApiProject.objects(status="active").order_by("name"))
    project_id = request.args.get("project_id") or request.form.get("project_id") or ""

    if request.method == "POST":
        if not is_manager():
            return {"projects": projects, "error": "权限不足"}, 403
        action = request.form.get("action", "")
        finding_id = request.form.get("finding_id", "")
        actor = session.get("username", "unknown")
        try:
            if action == "transition":
                target = request.form.get("target_status", "")
                transition_finding(
                    finding_id, target, actor,
                    reason=request.form.get("reason", "").strip() or None,
                )
                session["finding_notice"] = {"level": "success", "text": f"状态已变更为 {target}"}
            elif action == "assign":
                assign_finding(
                    finding_id,
                    request.form.get("assigned_to", "").strip(),
                    actor,
                )
                session["finding_notice"] = {"level": "success", "text": "已分配"}
            elif action == "comment":
                add_comment(
                    finding_id, actor,
                    request.form.get("note", "").strip(),
                )
                session["finding_notice"] = {"level": "success", "text": "评论已添加"}
            elif action == "schedule_retest":
                run, created = schedule_finding_retest(finding_id, actor)
                session["finding_notice"] = {
                    "level": "success",
                    "text": "复测运行 {}{}".format(
                        run.id, " 已进入队列" if created else " 已存在，未重复创建",
                    ),
                }
            elif action == "evaluate_retest":
                updated, evaluation = evaluate_finding_retest(
                    finding_id,
                    request.form.get("run_id", ""),
                    actor,
                )
                session["finding_notice"] = {
                    "level": "success",
                    "text": "复测判定：{}；当前状态：{}".format(
                        evaluation["decision"], updated.status,
                    ),
                }
            else:
                raise ValueError("未知漏洞操作")
        except (ValueError, Exception) as exc:
            logger.exception("finding action failed")
            session["finding_notice"] = {"level": "error", "text": str(exc)[:200]}
        if request.form.get("return_to") == "detail" and finding_id:
            return redirect(url_for("web.finding_detail", finding_id=finding_id))
        return redirect(url_for("web.findings_list", project_id=project_id))

    status_filter = request.args.get("status") or None
    severity_filter = request.args.get("severity") or None
    findings = list(list_findings(
        project_id=project_id or None,
        status=status_filter,
        severity=severity_filter,
    ))
    summary = finding_summary(project_id or None)
    notice = session.pop("finding_notice", None)

    return {
        "projects": projects,
        "project_id": project_id,
        "findings": findings,
        "summary": summary,
        "status_filter": status_filter or "",
        "severity_filter": severity_filter or "",
        "notice": notice,
        "can_manage": is_manager(),
        "all_statuses": [
            vulnerability_finding.OPEN,
            vulnerability_finding.FIXING,
            vulnerability_finding.FIXED_PENDING_VERIFY,
            vulnerability_finding.VERIFIED_FIXED,
            vulnerability_finding.REOPENED,
            vulnerability_finding.FALSE_POSITIVE,
            vulnerability_finding.ACCEPTED_RISK,
        ],
    }


@bp_web.route("/findings/<finding_id>", methods=["GET"])
@login_check
@templated("/finding-detail.html")
def finding_detail(finding_id):
    finding = get_finding(finding_id)
    if not finding:
        return {"error": "漏洞不存在"}, 404
    events = list(get_finding_events(finding.id))
    results = list(security_test_result.objects(
        id__in=finding.result_ids or []
    )) if finding.result_ids else []
    runs = list(security_test_run.objects(
        id__in=finding.run_ids or [],
    ).order_by("-started_at")) if finding.run_ids else []
    retest_runs = [
        item for item in runs
        if str((item.scope or {}).get("purpose") or "") == "finding_retest"
    ]
    return {
        "finding": finding,
        "events": events,
        "results": results,
        "retest_runs": retest_runs,
        "notice": session.pop("finding_notice", None),
        "can_manage": is_manager(),
    }
