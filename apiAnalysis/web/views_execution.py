from bson import ObjectId
from flask import request, make_response, redirect, url_for, session
from . import bp_web
from ..common.decorators import *
from ..common.func import is_manager
from ..db.collection import *
from ..tool.execution_scheduler import (
    request_execution_cancel,
    resume_execution,
)
from ..tool.lifecycle_view import (
    checkpoint_view,
    execution_result_view,
    execution_run_view,
)
from ._helpers import (
    _bounded_int,
    _lifecycle_csrf_token,
    _lifecycle_csrf_valid,
    _set_lifecycle_notice,
    _lifecycle_return_url,
)


_LIFECYCLE_RUN_STATUSES = (
    security_test_run.PREPARING,
    security_test_run.QUEUED,
    security_test_run.RUNNING,
    security_test_run.CANCEL_REQUESTED,
    security_test_run.CANCELLED,
    security_test_run.PAUSED,
    security_test_run.DONE,
    security_test_run.FAILED,
)


@bp_web.route("/project-executions", methods=["GET", "POST"])
@login_check
@templated("/project-executions.html")
def project_execution_center():
    if request.method == "POST":
        target = _lifecycle_return_url()
        if not is_manager():
            return make_response("Forbidden", 403)
        if not _lifecycle_csrf_valid(request.form.get("csrf_token")):
            _set_lifecycle_notice("操作未执行：页面令牌无效，请刷新后重试。", "error")
            return redirect(target)
        action = str(request.form.get("action") or "")
        try:
            if action in {"cancel_run", "resume_run"}:
                try:
                    run_id = ObjectId(str(request.form.get("run_id") or ""))
                except Exception:
                    raise ValueError("invalid run id") from None
                run = security_test_run.objects(id=run_id, scheduler_managed=True).first()
                expected_status = str(request.form.get("expected_status") or "")
                if not run or (expected_status and run.status != expected_status):
                    raise ValueError("execution state changed")
                if action == "cancel_run":
                    request_execution_cancel(run.id, reason="web_operator_requested")
                    _set_lifecycle_notice("已提交安全取消；不会删除运行或结果。")
                else:
                    if run.status != security_test_run.PAUSED:
                        raise ValueError("only paused runs can resume")
                    resume_execution(run.id)
                    _set_lifecycle_notice("运行已重新排队；worker 会再次执行 adapter 与认证预检。")
            else:
                raise ValueError("unsupported lifecycle action")
        except (ValueError, TypeError):
            _set_lifecycle_notice("操作未执行：目标不存在、状态已变化或参数无效，请刷新后确认。", "warning")
        return redirect(target)

    page = _bounded_int(request.args.get("page"), 0, 0, 100000)
    size = 30
    case_page = _bounded_int(request.args.get("case_page"), 0, 0, 100000)
    case_size = 100
    project_filter = str(request.args.get("project_id") or "")[:100]
    run_status = str(request.args.get("run_status") or "")
    if run_status not in _LIFECYCLE_RUN_STATUSES:
        run_status = ""

    projects = list(ApiProject.objects().order_by("name"))
    project_names = {item.project_id: item.name for item in projects}
    project_cards = []
    for project in projects:
        project_cards.append({
            "project_id": project.project_id,
            "name": project.name,
            "status": project.status,
            "environment_count": ProjectEnvironment.objects(
                project_id=project.project_id, active=True,
            ).count(),
            "asset_count": ProjectAssetLink.objects(project_id=project.project_id).count(),
            "run_count": security_test_run.objects(
                project_id=project.project_id, scheduler_managed=True,
            ).count(),
        })

    run_query = security_test_run.objects(scheduler_managed=True)
    if project_filter:
        run_query = run_query.filter(project_id=project_filter)
    if run_status:
        run_query = run_query.filter(status=run_status)
    run_count = run_query.count()
    run_objects = list(run_query.order_by("-updated_at", "-started_at")[page * size:page * size + size])
    runs = [execution_run_view(item, project_names.get(item.project_id, "")) for item in run_objects]
    execution_status_counts = {
        status: security_test_run.objects(scheduler_managed=True, status=status).count()
        for status in _LIFECYCLE_RUN_STATUSES
    }

    selected_run = None
    selected_run_view = None
    checkpoints = []
    checkpoint_count = 0
    results = []
    result_count = 0
    run_id = str(request.args.get("run_id") or "")
    if run_id:
        try:
            selected_run = security_test_run.objects(
                id=ObjectId(run_id), scheduler_managed=True,
            ).first()
        except Exception:
            selected_run = None
    if selected_run:
        selected_run_view = execution_run_view(
            selected_run, project_names.get(selected_run.project_id, ""),
        )
        checkpoint_query = security_execution_checkpoint.objects(run_id=selected_run.id).order_by("ordinal")
        checkpoint_count = checkpoint_query.count()
        checkpoints = [
            checkpoint_view(item)
            for item in checkpoint_query[case_page * case_size:case_page * case_size + case_size]
        ]
        result_query = security_test_result.objects(run_id=selected_run.id).order_by("ctime")
        result_count = result_query.count()
        results = [
            execution_result_view(item)
            for item in result_query[case_page * case_size:case_page * case_size + case_size]
        ]

    return {
        "projects": projects,
        "project_cards": project_cards,
        "project_filter": project_filter,
        "runs": runs,
        "run_count": run_count,
        "run_status": run_status,
        "run_statuses": _LIFECYCLE_RUN_STATUSES,
        "execution_status_counts": execution_status_counts,
        "selected_run": selected_run_view,
        "checkpoints": checkpoints,
        "checkpoint_count": checkpoint_count,
        "results": results,
        "result_count": result_count,
        "page": page,
        "size": size,
        "case_page": case_page,
        "case_size": case_size,
        "csrf_token": _lifecycle_csrf_token(),
        "can_manage": is_manager(),
        "notice": session.pop("lifecycle_notice", None),
    }
