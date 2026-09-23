"""
Test plan management routes.

Provides CRUD and lifecycle operations for versioned security test plans.
"""
import datetime as dt
import logging
import re

from flask import abort, request, redirect, url_for, session

from . import bp_web
from ._helpers import (
    _lifecycle_csrf_token,
    _lifecycle_csrf_valid,
    _set_lifecycle_notice,
)
from ..common.decorators import login_check, templated
from ..common.func import is_manager
from ..db.collection import (
    ApiProject,
    ProjectAuthProfile,
    ProjectEnvironment,
    raw_data,
    security_test_plan,
)
from ..tool.plan_readiness import assess_plan_readiness
from ..tool.test_plan import plan_pathids
from ..tool.test_plan import (
    activate_plan,
    archive_plan,
    create_next_version,
    create_plan,
    get_plan,
    list_plans,
    schedule_plan_execution,
)

logger = logging.getLogger(__name__)


def _readiness_for_plan(plan):
    """Read metadata only; no authentication resolution or snapshot creation."""
    try:
        pathids = plan_pathids(plan)
    except (ValueError, TypeError, OverflowError, AttributeError):
        pathids = []
    assets = list(raw_data.objects(
        ptah_id__in=pathids, project_id=plan.project_id,
    ).only("ptah_id", "project_id", "env_id", "method")) if pathids else []
    environment = ProjectEnvironment.objects(
        project_id=plan.project_id, env_id=plan.env_id or "",
    ).only("project_id", "env_id", "active").first()
    profile = ProjectAuthProfile.objects(
        profile_id=plan.auth_profile_id, project_id=plan.project_id,
    ).only("project_id", "env_id", "active", "lifecycle").first() if plan.auth_profile_id else None
    return assess_plan_readiness(plan, assets, environment=environment, profile=profile)


def _form_pathids(value):
    values = re.split(r"[\s,;，；]+", str(value or "").strip())
    pathids = []
    for value in values:
        if not value:
            continue
        try:
            pathid = int(value)
        except ValueError:
            raise ValueError("PathId 必须是整数") from None
        if pathid <= 0:
            raise ValueError("PathId 必须大于 0")
        if pathid not in pathids:
            pathids.append(pathid)
    if not pathids:
        raise ValueError("请至少填写一个 PathId")
    return pathids


@bp_web.route("/test-plans", methods=["GET", "POST"])
@login_check
@templated("/test-plans.html")
def test_plans():
    projects = list(ApiProject.objects(status="active").order_by("name"))
    project_id = request.args.get("project_id") or request.form.get("project_id") or ""

    if request.method == "POST":
        if not is_manager():
            abort(403)
        if not _lifecycle_csrf_valid(request.form.get("csrf_token")):
            abort(400)
        action = request.form.get("action", "")
        try:
            if action == "create":
                pathids = _form_pathids(request.form.get("pathids"))
                request_budget = int(
                    request.form.get("request_budget") or len(pathids)
                )
                if not 1 <= request_budget <= 1000:
                    raise ValueError("请求预算必须在 1 到 1000 之间")
                if len(pathids) > request_budget:
                    raise ValueError("PathId 数量不能超过请求预算")
                timeout_seconds = int(
                    request.form.get("request_timeout_seconds") or 15
                )
                if not 1 <= timeout_seconds <= 300:
                    raise ValueError("请求超时必须在 1 到 300 秒之间")
                auth_mode = request.form.get("auth_mode", "inherit")
                auth_profile_id = (
                    request.form.get("auth_profile_id", "").strip() or None
                )
                env_id = request.form.get("env_id", "").strip() or None
                if auth_mode == "account":
                    if not auth_profile_id:
                        raise ValueError("账号认证计划必须选择认证方案")
                    profile = ProjectAuthProfile.objects(
                        profile_id=auth_profile_id,
                        project_id=project_id,
                        active=True,
                    ).first()
                    if profile is None:
                        raise ValueError("认证方案不存在或不属于当前项目")
                    if env_id and str(profile.env_id or "") != env_id:
                        raise ValueError("认证方案与计划环境不一致")
                create_plan(
                    name=request.form.get("name", "").strip(),
                    project_id=project_id,
                    check_type=request.form.get("check_type", "").strip(),
                    env_id=env_id,
                    adapter_id=request.form.get("adapter_id", "").strip() or None,
                    adapter_version="1",
                    auth_mode=auth_mode,
                    auth_profile_id=auth_profile_id,
                    scope={"pathids": pathids},
                    snapshot_filter={"pathids": pathids},
                    execution_policy={
                        "max_workers": 1,
                        "per_host_workers": 1,
                        "min_interval_ms": 100,
                        "request_timeout_seconds": timeout_seconds,
                        "lease_seconds": 60,
                        "transport_error_stop": 1,
                        "rate_limit_stop": 1,
                        "server_error_stop": 1,
                        "max_dispatch_attempts": 1,
                        "allow_mutation": False,
                        "mutation_acknowledged": False,
                    },
                    request_budget=request_budget,
                    description=request.form.get("description", "").strip() or None,
                    created_by=session.get("username", ""),
                )
                session["test_plan_notice"] = {"level": "success", "text": "测试计划已创建"}
            elif action == "activate":
                plan_id = request.form.get("plan_id", "")
                activate_plan(plan_id)
                session["test_plan_notice"] = {"level": "success", "text": "测试计划已激活"}
            elif action == "archive":
                plan_id = request.form.get("plan_id", "")
                archive_plan(plan_id)
                session["test_plan_notice"] = {"level": "success", "text": "测试计划已归档"}
            elif action == "new_version":
                plan_id = request.form.get("plan_id", "")
                create_next_version(plan_id, created_by=session.get("username", ""))
                session["test_plan_notice"] = {"level": "success", "text": "新版本已创建"}
            elif action == "execute":
                plan_id = request.form.get("plan_id", "")
                plan = get_plan(plan_id)
                if plan is None or str(plan.project_id) != project_id:
                    raise ValueError("计划不存在或不属于所选项目")
                readiness = _readiness_for_plan(plan)
                if readiness["status"] == "blocked":
                    session["test_plan_notice"] = {
                        "level": "error", "text": "执行前检查未通过，请按缺项提示补齐。",
                    }
                    return redirect(url_for(
                        "web.test_plans", project_id=project_id, readiness_plan_id=plan_id,
                    ))
                run, created = schedule_plan_execution(
                    plan_id,
                    operator=session.get("username", ""),
                )
                _set_lifecycle_notice(
                    "测试计划已生成全新请求快照并{}：{}。".format(
                        "进入执行队列" if created else "复用已有批次",
                        run.id,
                    )
                )
                return redirect(url_for(
                    "web.project_execution_center",
                    project_id=project_id,
                    run_id=str(run.id),
                ))
            else:
                raise ValueError("不支持的测试计划操作")
        except Exception as exc:
            logger.exception("test plan action failed")
            session["test_plan_notice"] = {"level": "error", "text": str(exc)[:200]}
        return redirect(url_for("web.test_plans", project_id=project_id))

    status_filter = request.args.get("status") or None
    check_type_filter = request.args.get("check_type") or None
    plans = list(list_plans(project_id, status=status_filter, check_type=check_type_filter)) if project_id else []
    environments = list(ProjectEnvironment.objects(project_id=project_id, active=True)) if project_id else []
    auth_profiles = [
        profile for profile in ProjectAuthProfile.objects(
            project_id=project_id,
            active=True,
        ).order_by("env_id", "name")
        if str(profile.lifecycle or "active") == "active"
    ] if project_id else []
    notice = session.pop("test_plan_notice", None)
    readiness = None
    readiness_plan_name = ""
    selected_id = request.args.get("readiness_plan_id", "")
    selected = next((plan for plan in plans if str(plan.id) == selected_id), None)
    if selected is not None:
        readiness = _readiness_for_plan(selected)
        readiness_plan_name = selected.name

    return {
        "projects": projects,
        "project_id": project_id,
        "plans": plans,
        "environments": environments,
        "auth_profiles": auth_profiles,
        "status_filter": status_filter or "",
        "check_type_filter": check_type_filter or "",
        "notice": notice,
        "readiness": readiness,
        "readiness_plan_name": readiness_plan_name,
        "can_manage": is_manager(),
        "csrf_token": _lifecycle_csrf_token(),
        "plan_statuses": [security_test_plan.DRAFT, security_test_plan.ACTIVE, security_test_plan.ARCHIVED],
    }
