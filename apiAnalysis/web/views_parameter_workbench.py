"""Parameter relation workbench, priority and evidence routes."""
import json
import datetime as dt
import logging
import math
import uuid
from collections import Counter as CollectionCounter

from bson import ObjectId
from flask import request, redirect, url_for, session, make_response

from . import bp_web
from ._helpers import (
    _bounded_int,
    _canonical_project_id,
    _elapsed_text,
    _project_endpoints,
    _available_projects,
    _lifecycle_csrf_token,
    _lifecycle_csrf_valid,
    _set_lifecycle_notice,
)
from ..common.decorators import login_check, templated
from ..common.func import is_manager
from ..common.util import get_page, resp_length
from ..conf.conf import *
from ..db.collection import *
from ..tool.parameter_validation import (
    LargeValidationApprovalRequired,
    schedule_validation_batch,
    select_ready_validation_batch,
)
from ..tool.parameter_analysis import (
    cancel_relation_analysis,
    enqueue_relation_analysis,
)
from ..tool.parameter_relation_workbench import (
    MAX_APPROVED_REQUESTS,
    STATUS_LABELS as RELATION_STATUS_LABELS,
    environment_execution_policy,
    host_candidates,
    preprocess_relation,
    preprocess_relations,
    relation_workbench_view,
    refresh_parameter_readiness,
    select_relation_hosts,
    swap_relation_direction,
    sync_relation_experience,
)
from ..tool.request_fixture import save_request_fixture
from ..tool.parameter_identity import (
    NORMALIZATION_VERSION as PARAMETER_NORMALIZATION_VERSION,
    occurrence_alias,
    parameter_identity,
    preferred_parameter_name,
)
from ..tool.parameter_locator import LOCATOR_VERSION, locator_from_path
from ..tool.endpoint_evidence import endpoint_evidence_view
from ..tool.interface_knowledge import (
    TRAFFIC_SOURCES,
    discover_project_relations,
    project_chain_candidates,
)
from ..tool.project_auth import (
    environment_host_names,
    normalize_host,
)

logger = logging.getLogger(__name__)

def _parameter_relations_redirect(project_id, notice="", **overrides):
    keys = (
        "task", "parameter", "page", "size", "env_id", "source_profile_id",
        "consumer_profile_id", "source_host", "consumer_host",
    )
    values = {"project_id": _canonical_project_id(project_id)}
    for key in keys:
        value = overrides.get(key) if key in overrides else request.form.get(key)
        if value not in (None, ""):
            values[key] = value
    if notice:
        values["saved"] = str(notice)[:300]
    return url_for("web.parameter_relations", **values)


def _relation_belongs_to_project(relation, project_id):
    if not relation:
        return False
    if relation.project_id and str(relation.project_id) == str(project_id):
        return True
    pathids = {item.ptah_id for item in _project_endpoints(project_id)}
    return bool(pathids and (relation.req_pathid in pathids or relation.res_pathid in pathids))


def _relation_case_relations(relation, project_id):
    """Return every usable mapping carried by one source/consumer request pair."""
    if not relation:
        return []
    rows = list(parameter_relation.objects(
        project_id=_canonical_project_id(project_id),
        res_pathid=relation.res_pathid,
        req_pathid=relation.req_pathid,
        manual_decision__nin=["rejected", "deleted"],
    ).order_by("parameter", "id"))
    if not rows and _relation_belongs_to_project(relation, project_id):
        rows = [relation]
    return rows


_RELATION_RUN_STATUS = {
    "preparing": ("正在构建案例", "正在冻结接口、字段、Host、账号和请求预算。", "warn"),
    "queued": ("等待后台执行", "请求案例已入队，通常会在 2 秒内被本地执行器领取。", "warn"),
    "running": ("正在发出请求", "后台正在连续完成来源取值、字段注入、消费请求和结果回写。", "info"),
    "paused": ("等待认证恢复", "账号认证上下文不可用，批次已安全暂停，没有继续发送请求。", "bad"),
    "done": ("验证完成", "来源和消费请求均已结束，结论已逐字段回写。", "good"),
    "failed": ("执行失败", "后台执行发生异常，关系不会被误标为已验证。", "bad"),
    "cancel_requested": ("正在停止", "已收到停止请求，正在结束当前安全边界内的工作。", "warn"),
    "cancelled": ("已停止", "批次已停止，未完成字段没有验证结论。", "bad"),
}


def _elapsed_text(started_at, finished_at=None):
    if not started_at:
        return "-"
    seconds = max(0, int(((finished_at or dt.datetime.utcnow()) - started_at).total_seconds()))
    if seconds < 60:
        return "{} 秒".format(seconds)
    minutes, remainder = divmod(seconds, 60)
    if minutes < 60:
        return "{} 分 {} 秒".format(minutes, remainder)
    hours, minutes = divmod(minutes, 60)
    return "{} 小时 {} 分".format(hours, minutes)


def _parameter_validation_run_view(project_id):
    if not project_id:
        return None
    query = security_test_run.objects(
        project_id=project_id,
        scheduler_managed=True,
        adapter_id="parameter_relation_validation",
    )
    active_statuses = ["preparing", "queued", "running", "cancel_requested"]
    run = query.filter(status__in=active_statuses).order_by("-updated_at").first()
    if not run:
        run = query.order_by("-updated_at", "-queued_at").first()
    if not run:
        return None

    scope = dict(run.scope or {})
    relations = list(parameter_relation.objects(last_validation_run_id=run.id).order_by("parameter"))
    if not relations:
        relation_ids = []
        for value in list(scope.get("relation_ids") or []):
            try:
                relation_ids.append(ObjectId(str(value)))
            except Exception:
                continue
        if relation_ids:
            relations = list(parameter_relation.objects(id__in=relation_ids).order_by("parameter"))
    first_relation = relations[0] if relations else None
    source = (
        raw_data.objects(ptah_id=first_relation.res_pathid).only(
            "ptah_id", "method", "path", "domain", "url",
        ).first()
        if first_relation else None
    )
    consumer = (
        raw_data.objects(ptah_id=first_relation.req_pathid).only(
            "ptah_id", "method", "path", "domain", "url",
        ).first()
        if first_relation else None
    )
    checkpoints = list(security_execution_checkpoint.objects(run_id=run.id).order_by("ordinal"))
    checkpoint = checkpoints[0] if checkpoints else None
    progress = dict((checkpoint.outcome_summary if checkpoint else {}) or {})
    results = list(parameter_validation_result.objects(run_id=run.id).order_by("ctime"))
    sample_result = results[0] if results else None
    sample_source = dict((sample_result.source_result if sample_result else {}) or {})
    sample_consumer = dict((sample_result.consumer_result if sample_result else {}) or {})
    approval_stage = str(
        sample_consumer.get("approval_stage")
        or sample_source.get("approval_stage")
        or ""
    )
    remaining_host_count = int(
        sample_consumer.get("remaining_host_count")
        or sample_source.get("remaining_host_count")
        or 0
    )
    untried_host_count = int(
        sample_consumer.get("untried_host_count")
        or sample_source.get("untried_host_count")
        or 0
    )
    sample_status = str(getattr(sample_result, "status", "") or "")
    if sample_status != "host_scope_approval_required":
        if sample_status in {
            "source_request_rejected", "consumer_request_rejected",
            "source_auth_rejected", "consumer_auth_rejected",
            "source_rate_limited", "consumer_rate_limited",
        }:
            untried_host_count = max(
                untried_host_count, remaining_host_count,
            )
        approval_stage = ""
        remaining_host_count = 0
    source_error_summary = dict(sample_source.get("error_summary") or {})
    consumer_error_summary = dict(sample_consumer.get("error_summary") or {})

    def safe_error_hint(summary):
        parts = []
        if summary.get("error_code"):
            parts.append("错误码 {}".format(summary["error_code"]))
        if summary.get("error_fields"):
            parts.append(
                "字段 {}".format("、".join(list(summary["error_fields"])[:8]))
            )
        if summary.get("response_top_level_keys"):
            parts.append(
                "响应字段 {}".format(
                    "、".join(list(summary["response_top_level_keys"])[:8])
                )
            )
        return "；".join(parts)
    status_counts = {}
    case_request_counts = {}
    for result in results:
        result_status = str(result.status or "unknown")
        status_counts[result_status] = status_counts.get(result_status, 0) + 1
        # ``parameter_validation_result.case_key`` is intentionally unique per
        # field mapping.  Request accounting is per source/consumer request
        # case, so group all mappings on the same endpoint pair (or execution
        # result) before taking the maximum request count.
        case_key = str(
            result.execution_result_id
            or "{}:{}".format(
                result.res_pathid
                or getattr(result.relation, "res_pathid", ""),
                result.req_pathid
                or getattr(result.relation, "req_pathid", ""),
            )
        )
        source_requests = int((result.source_result or {}).get("request_count") or 0)
        consumer_requests = int((result.consumer_result or {}).get("request_count") or 0)
        case_request_counts[case_key] = max(
            case_request_counts.get(case_key, 0),
            source_requests,
            consumer_requests,
        )
    result_status_labels = {
        "verified": "关系已验证",
        "mutation_verified": "写入/删除效果已验证",
        "mutation_accepted": "写入请求已被接受",
        "mutation_effect_after_error": "已生效但接口响应异常",
        "partially_verified": "部分字段通过",
        "source_failed": "来源请求失败",
        "source_request_rejected": "来源请求数据被拒绝",
        "source_auth_rejected": "来源认证或角色被拒绝",
        "source_rate_limited": "来源接口限流",
        "consumer_failed": "消费请求失败",
        "consumer_request_rejected": "消费请求数据被拒绝",
        "consumer_auth_rejected": "消费认证或角色被拒绝",
        "consumer_rate_limited": "消费接口限流",
        "value_not_found": "来源响应未找到值",
        "host_scope_approval_required": "需要扩大 Host 范围",
        "request_budget_exhausted": "请求预算用尽",
    }
    result_status_items = [
        {
            "status": status,
            "label": result_status_labels.get(status, status or "未知结论"),
            "count": count,
            "successful": status in {
                "verified", "mutation_verified", "mutation_accepted",
                "mutation_effect_after_error",
            },
        }
        for status, count in sorted(status_counts.items())
    ]

    attempts = []
    request_count = sum(case_request_counts.values())
    if sample_result:
        for role, evidence in (("来源", sample_source), ("消费", sample_consumer)):
            for item in list(evidence.get("attempts") or []):
                attempts.append({
                    "role": role,
                    "host": str(item.get("host") or ""),
                    "status_code": item.get("status_code"),
                    "ok": bool(item.get("ok")),
                    "error_type": str(item.get("error_type") or ""),
                    "elapsed_ms": int(item.get("elapsed_ms") or 0),
                    "error_code": str(item.get("error_code") or ""),
                    "error_fields": list(item.get("error_fields") or [])[:30],
                    "response_top_level_keys": list(
                        item.get("response_top_level_keys") or []
                    )[:60],
                    "request_method": str(
                        item.get("request_method") or ""
                    ).upper()[:20],
                    "request_origin": str(
                        item.get("request_origin") or ""
                    )[:300],
                    "request_path": str(
                        item.get("request_path") or ""
                    )[:500],
                    "request_query_names": [
                        str(value)[:100]
                        for value in list(item.get("request_query_names") or [])
                        if str(value)
                    ][:100],
                    "request_header_names": [
                        str(value)[:100]
                        for value in list(item.get("request_header_names") or [])
                        if str(value)
                    ][:100],
                    "request_cookie_names": [
                        str(value)[:100]
                        for value in list(item.get("request_cookie_names") or [])
                        if str(value)
                    ][:100],
                    "request_auth_header_names": [
                        str(value)[:100]
                        for value in list(
                            item.get("request_auth_header_names") or []
                        )
                        if str(value)
                    ][:100],
                    "request_auth_cookie_names": [
                        str(value)[:100]
                        for value in list(
                            item.get("request_auth_cookie_names") or []
                        )
                        if str(value)
                    ][:100],
                    "request_body_bytes": max(
                        0,
                        min(
                            int(item.get("request_body_bytes") or 0),
                            1_000_000_000,
                        ),
                    ),
                    "request_content_type": str(
                        item.get("request_content_type") or ""
                    )[:120],
                    "request_timeout_seconds": item.get(
                        "request_timeout_seconds",
                    ),
                    "request_allow_redirects": bool(
                        item.get("request_allow_redirects", False)
                    ),
                    "request_tls_verify": bool(
                        item.get("request_tls_verify", True)
                    ),
                    "auth_request_count": max(
                        0, min(int(item.get("auth_request_count") or 0), 100),
                    ),
                })
    if int(scope.get("case_count") or 0) <= 1:
        request_count = max(request_count, int(progress.get("request_count") or 0))
    sample_request_count = max(
        int(sample_source.get("request_count") or 0),
        int(sample_consumer.get("request_count") or 0),
    )
    # Older snapshots only recorded the Hosts that fit inside that run's
    # budget.  Recompute the full currently authorized project scope so the
    # recovery button can freeze one sufficient budget instead of revealing
    # one additional Host per retry.
    if approval_stage in {"source", "consumer"}:
        stage_endpoint = source if approval_stage == "source" else consumer
        stage_profile_id = str(scope.get(
            "source_profile_id" if approval_stage == "source"
            else "consumer_profile_id",
        ) or "")
        stage_profile = ProjectAuthProfile.objects(
            project_id=project_id,
            profile_id=stage_profile_id,
        ).first()
        stage_environment = ProjectEnvironment.objects(
            project_id=project_id,
            env_id=run.env_id,
        ).first()
        stage_evidence = sample_source if approval_stage == "source" else sample_consumer
        attempted_hosts = {
            str(item.get("host") or "")
            for item in list(stage_evidence.get("attempts") or [])
            if item.get("host")
        }
        if stage_endpoint and stage_profile and stage_environment:
            full_host_scope = host_candidates(
                stage_endpoint,
                stage_environment,
                stage_profile,
                str(
                    getattr(
                        first_relation,
                        "selected_source_host"
                        if approval_stage == "source"
                        else "selected_consumer_host",
                        "",
                    )
                    or ""
                ),
            )
            remaining_host_count = max(
                remaining_host_count,
                len({
                    str(item.get("host") or "")
                    for item in full_host_scope
                    if item.get("host")
                } - attempted_hosts),
            )

    status_label, status_detail, tone = _RELATION_RUN_STATUS.get(
        run.status, (run.status or "未知状态", "后台批次状态未知。", "warn"),
    )
    auth_error_detail = str((run.auth_context_summary or {}).get("error_detail") or "")
    if run.status == "running" and progress.get("message"):
        status_detail = str(progress.get("message"))
    elif run.status == "paused" and "SSO_AUTH_HTTP_401" in auth_error_detail:
        status_detail = "认证服务返回 HTTP 401；当前测试账号凭据已失效或不适用于该认证入口。请更新账号后恢复批次。"
    elif run.status == "paused" and auth_error_detail:
        status_detail = "{}（{}）".format(status_detail, auth_error_detail)
    elif run.status in {"paused", "failed"} and run.last_error_type:
        status_detail = "{}（{}）".format(status_detail, run.last_error_type)
    requires_host_approval = bool(
        run.status == "done"
        and status_counts.get("host_scope_approval_required")
    )
    incomplete_statuses = {
        status for status in status_counts
        if status not in {
            "verified", "mutation_verified", "mutation_accepted",
            "mutation_effect_after_error",
        }
    }
    if requires_host_approval:
        stage_label = "来源" if approval_stage == "source" else "消费"
        next_step = (
            "消费接口尚未发送"
            if approval_stage == "source"
            else "关系结论尚未成立"
        )
        status_label = "等待扩大 Host 范围"
        status_detail = (
            "{}阶段已在当前预算内尝试 {} 次，均未取得可用响应；"
            "还有 {} 个项目候选 Host 未尝试，{}。"
            "确认更大请求预算后可重试原接口对；批次编号 {}。"
        ).format(
            stage_label,
            sample_request_count,
            remaining_host_count,
            next_step,
            str(run.id)[-8:],
        )
        tone = "warn"
    elif run.status == "done" and status_counts.get("request_budget_exhausted"):
        status_label = "请求预算已用尽"
        status_detail = (
            "请求在硬预算内停止，未完成的消费请求没有发送，关系也没有标记为已验证；"
            "请提高本接口对预算后重试。批次编号 {}。"
        ).format(str(run.id)[-8:])
        tone = "warn"
    elif run.status == "done" and status_counts.get("source_request_rejected"):
        hint = safe_error_hint(source_error_summary)
        untried_hint = (
            "另有 {} 个授权 Host 因已有明确业务错误而未尝试。".format(
                untried_host_count,
            )
            if untried_host_count else ""
        )
        status_label = "来源请求数据被拒绝"
        status_detail = (
            "来源接口已命中并返回业务参数错误，系统已停止跨 Host，消费接口没有发送。"
            "{}{}请补充或修正来源接口 Fixture；批次编号 {}。"
        ).format(
            "{}；".format(hint) if hint else "",
            untried_hint,
            str(run.id)[-8:],
        )
        tone = "warn"
    elif run.status == "done" and status_counts.get("consumer_request_rejected"):
        hint = safe_error_hint(consumer_error_summary)
        untried_hint = (
            "另有 {} 个授权 Host 因已有明确业务错误而未尝试。".format(
                untried_host_count,
            )
            if untried_host_count else ""
        )
        status_label = "消费请求数据被拒绝"
        status_detail = (
            "来源值已提取，消费接口已命中但拒绝当前请求数据，系统已停止跨 Host。"
            "{}{}请补充或修正消费接口 Fixture；批次编号 {}。"
        ).format(
            "{}；".format(hint) if hint else "",
            untried_hint,
            str(run.id)[-8:],
        )
        tone = "warn"
    elif run.status == "done" and (
        status_counts.get("source_auth_rejected")
        or status_counts.get("consumer_auth_rejected")
    ):
        source_side = bool(status_counts.get("source_auth_rejected"))
        status_label = "{}认证或角色被拒绝".format(
            "来源" if source_side else "消费",
        )
        status_detail = (
            "接口已命中，系统已停止跨 Host。请检查所选登录场景、角色和认证方案；"
            "{}。批次编号 {}。"
        ).format(
            "消费接口没有发送" if source_side else "关系没有标记为已验证",
            str(run.id)[-8:],
        )
        tone = "bad"
    elif run.status == "done" and (
        status_counts.get("source_rate_limited")
        or status_counts.get("consumer_rate_limited")
    ):
        status_label = "接口触发限流"
        status_detail = (
            "系统收到 HTTP 429 后停止跨 Host，未通过关系不会标记为已验证；"
            "请等待限流窗口后重试。批次编号 {}。"
        ).format(str(run.id)[-8:])
        tone = "warn"
    elif run.status == "done" and status_counts.get("source_failed"):
        status_label = "来源接口请求失败"
        status_detail = (
            "预算内的来源 Host 均未返回可用响应，消费接口没有发送；"
            "请根据下方 HTTP 状态或错误类型检查 Host、认证及测试数据。批次编号 {}。"
        ).format(str(run.id)[-8:])
        tone = "bad"
    elif run.status == "done" and status_counts.get("consumer_failed"):
        status_label = "消费接口请求失败"
        status_detail = (
            "来源值已提取，但消费接口未接受；关系没有标记为已验证。"
            "请根据下方 HTTP 状态或错误类型调整 Host 或请求数据。批次编号 {}。"
        ).format(str(run.id)[-8:])
        tone = "bad"
    elif run.status == "done" and status_counts.get("value_not_found"):
        status_label = "来源响应未找到字段值"
        status_detail = (
            "来源接口可达，但响应中没有命中字段定位器；消费接口没有发送。"
            "请检查响应结构、测试数据或字段映射。批次编号 {}。"
        ).format(str(run.id)[-8:])
        tone = "warn"
    elif run.status == "done" and status_counts.get("partially_verified"):
        status_label = "部分字段已验证"
        status_detail = (
            "同一接口对中只有部分字段形成验证结论；未通过字段保留了阶段和错误证据，"
            "不会继承通过结论。批次编号 {}。"
        ).format(str(run.id)[-8:])
        tone = "warn"
    elif run.status == "done" and int(run.failed_cases or 0):
        status_detail = "批次已结束：{} 个接口对完成，{} 个接口对失败；失败项保留请求阶段和错误类型，不会误标为已验证。".format(
            int(run.completed_cases or 0),
            int(run.failed_cases or 0),
        )

    phase = str(progress.get("phase") or "")
    if run.status in {"preparing", "queued"}:
        current_stage = 2
    elif run.status == "running":
        current_stage = {
            "preparing": 2,
            "source_request": 3,
            "source_response": 3,
            "field_extraction": 3,
            "consumer_request": 4,
            "consumer_response": 4,
            "effect_check": 4,
            "writing_results": 5,
        }.get(phase, 3)
    elif run.status == "done":
        current_stage = 6
    else:
        current_stage = 3
    steps = []
    for index, (title, detail) in enumerate((
        ("构建请求案例", "冻结接口、字段映射、Host、账号和预算"),
        ("等待后台执行", "由本地执行器领取持久队列任务"),
        ("来源取值", "请求来源接口并按定位器提取多个字段"),
        ("注入并消费", "保持数据类型，注入一次消费请求"),
        ("判定与回写", "逐字段保存通过、失败和证据"),
    ), start=1):
        if current_stage == 6 or index < current_stage:
            state = "done"
        elif index == current_stage:
            state = "error" if run.status in {"paused", "failed", "cancelled"} else "current"
        else:
            state = "pending"
        steps.append({"index": index, "title": title, "detail": detail, "state": state})
    if run.status == "done" and incomplete_statuses:
        if (
            status_counts.get("source_failed")
            or status_counts.get("source_request_rejected")
            or status_counts.get("source_auth_rejected")
            or status_counts.get("source_rate_limited")
            or status_counts.get("value_not_found")
            or approval_stage == "source"
        ):
            stopped_stage = 3
        else:
            stopped_stage = 4
        for step in steps:
            if step["index"] < stopped_stage:
                step["state"] = "done"
            elif step["index"] == stopped_stage:
                step["state"] = "error"
                step["detail"] = (
                    "该阶段未形成可用结果；具体 HTTP 状态或错误类型见下方尝试记录"
                )
            elif step["index"] == 5:
                step["state"] = "done"
                step["detail"] = "未通过结论及安全证据已保存，未误标为关系成立"
            else:
                step["state"] = "pending"
                step["detail"] = "前一阶段未通过，本阶段未发送请求"

    started_at = run.queued_at or run.started_at or run.updated_at
    finished_at = run.finished_at if run.status in {"done", "failed", "cancelled"} else None
    field_count = len(relations) or len(list(scope.get("relation_ids") or []))
    case_count = int(scope.get("case_count") or run.total_cases or 0)
    consumer_method = str(getattr(consumer, "method", "") or "").upper()
    recommended_retry_budget = max(
        int(scope.get("per_relation_request_budget") or 0) + 1,
        sample_request_count
        + remaining_host_count
        + (1 if approval_stage == "source" else 0)
        + (1 if approval_stage == "consumer" and consumer_method in {"POST", "PUT", "PATCH", "DELETE"} else 0),
    )
    return {
        "id": str(run.id),
        "short_id": str(run.id)[-8:],
        "status": run.status,
        "status_label": status_label,
        "status_detail": status_detail,
        "needs_auth_action": run.status == "paused",
        "tone": tone,
        "active": run.status in active_statuses,
        "active_count": query.filter(status__in=active_statuses).count(),
        "elapsed": _elapsed_text(started_at, finished_at),
        "field_count": field_count,
        "case_count": case_count,
        "request_budget": int(
            scope.get("estimated_requests")
            or (
                int(scope.get("per_relation_request_budget") or 0)
                * max(1, case_count)
            )
            or 0
        ),
        "per_case_request_budget": int(scope.get("per_relation_request_budget") or 0),
        "request_count": request_count,
        "completed_cases": int(run.completed_cases or 0),
        "failed_cases": int(run.failed_cases or 0),
        "skipped_cases": int(run.skipped_cases or 0),
        "source": {
            "pathid": getattr(source, "ptah_id", None),
            "method": str(getattr(source, "method", "") or ""),
            "path": str(getattr(source, "path", "") or ""),
        },
        "consumer": {
            "pathid": getattr(consumer, "ptah_id", None),
            "method": str(getattr(consumer, "method", "") or ""),
            "path": str(getattr(consumer, "path", "") or ""),
        },
        "phase": phase,
        "steps": steps,
        "attempts": attempts,
        "result_count": len(results),
        "result_status_counts": status_counts,
        "result_status_items": result_status_items,
        "requires_host_approval": requires_host_approval,
        "approval_stage": approval_stage,
        "remaining_host_count": remaining_host_count,
        "recommended_retry_budget": recommended_retry_budget,
        "retry_relation_id": str(first_relation.id) if first_relation else "",
        "retry_source_host": str(
            getattr(first_relation, "selected_source_host", "") or ""
        ),
        "retry_consumer_host": str(
            getattr(first_relation, "selected_consumer_host", "") or ""
        ),
        "error_reference": str(run.id)[-8:],
    }

_RELATION_ANALYSIS_STATUS = {
    "queued": (
        "等待后台全量分析",
        "任务已持久化；只读取接口文档、已有样本和项目配置，不发送业务请求。",
        "warn",
    ),
    "running": (
        "正在后台全量分析",
        "正在发现关系并逐条计算方向、字段位置、Host、认证上下文与请求数据就绪度；不发送业务请求。",
        "info",
    ),
    "done": (
        "全量分析完成",
        "项目中的关系均已进入明确的可验证、待数据、待配置或待纠偏状态。",
        "good",
    ),
    "failed": (
        "全量分析失败",
        "后台任务已停止，已完成的关系结果仍然保留；可以按错误编号查看日志后重试。",
        "bad",
    ),
    "cancel_requested": (
        "正在停止全量分析",
        "后台将在当前关系处理结束后停止，不会发送业务请求。",
        "warn",
    ),
    "cancelled": (
        "全量分析已停止",
        "已完成的关系结果仍然保留，重新点击可从新任务继续完整分析。",
        "warn",
    ),
}


def _parameter_analysis_run_view(project_id):
    if not project_id:
        return None
    run = parameter_relation_analysis_run.objects(
        project_id=project_id,
    ).order_by("-updated_at", "-created_at").first()
    if not run:
        return None
    label, detail, tone = _RELATION_ANALYSIS_STATUS.get(
        run.status,
        (run.status or "未知状态", "后台分析状态未知。", "warn"),
    )
    processed = max(0, int(run.processed_relations or 0))
    total = max(0, int(run.total_relations or 0))
    percent = min(100, int(round(processed * 100.0 / total))) if total else 0
    counts = dict(run.status_counts or {})
    result = dict(run.result_summary or {})
    item_errors = int(
        result.get("item_error_count")
        or counts.get("analysis_error")
        or 0
    )
    if run.status == parameter_relation_analysis_run.STATUS_DONE and item_errors:
        tone = "warn"
        detail = "主体分析已完成，但 {} 条关系处理异常；错误编号和服务日志可用于定位，异常项不会被标记为已就绪。".format(
            item_errors,
        )
    elif run.status == parameter_relation_analysis_run.STATUS_FAILED:
        suffix = "（错误编号 {}）".format(run.error_reference) if run.error_reference else ""
        detail = "{}{}".format(detail, suffix)
    return {
        "id": str(run.id),
        "short_id": str(run.id)[-8:],
        "status": run.status,
        "status_label": label,
        "status_detail": detail,
        "tone": tone,
        "active": run.status in parameter_relation_analysis_run.ACTIVE_STATUSES,
        "phase": run.phase or "",
        "processed": processed,
        "total": total,
        "percent": percent,
        "counts": counts,
        "discovery": dict(run.discovery_summary or {}),
        "result": result,
        "item_error_count": item_errors,
        "error_type": run.error_type or "",
        "error_reference": run.error_reference or "",
        "elapsed": _elapsed_text(
            run.started_at or run.created_at,
            run.finished_at if run.status in {
                parameter_relation_analysis_run.STATUS_DONE,
                parameter_relation_analysis_run.STATUS_FAILED,
                parameter_relation_analysis_run.STATUS_CANCELLED,
            } else None,
        ),
    }


def _fixture_json_value(field_name, *, object_only=False, empty_value=None):
    raw = str(request.form.get(field_name) or "").strip()
    if not raw:
        return {} if object_only else empty_value
    try:
        value = json.loads(raw)
    except (TypeError, ValueError) as exc:
        raise ValueError("{} 不是有效 JSON：{}".format(field_name, str(exc)))
    if object_only and not isinstance(value, dict):
        raise ValueError("{} 必须是 JSON 对象".format(field_name))
    return value


@bp_web.route("/parameter-relations", methods=['GET', 'POST'])
@login_check
@templated("/parameter-relations.html")
def parameter_relations():
    if request.method == 'POST':
        project_id = _canonical_project_id(request.form.get("project_id") or "")
        if not is_manager():
            return make_response("Forbidden", 403)
        if not _lifecycle_csrf_valid(request.form.get("csrf_token")):
            return redirect(_parameter_relations_redirect(
                project_id, "操作未执行：页面令牌无效，请刷新后重试。",
            ))
        action = str(request.form.get("action") or "")
        operator = session.get("username") or ""
        context = _parameter_validation_context(
            project_id,
            request.form.get("env_id"),
            request.form.get("source_profile_id"),
            request.form.get("consumer_profile_id"),
            request.form.get("source_host"),
            request.form.get("consumer_host"),
        )
        try:
            if action == "preprocess_project":
                analysis_run, created = enqueue_relation_analysis(
                    project_id,
                    env_id=context["env_id"],
                    source_profile_id=context["source_profile_id"],
                    consumer_profile_id=context["consumer_profile_id"],
                    operator=operator,
                )
                notice = "已{}后台全量分析任务 {}：会扫描全部关系并持续显示进度；该任务不发送业务请求。".format(
                    "创建" if created else "复用正在运行的",
                    str(analysis_run.id)[-8:],
                )
                return redirect(_parameter_relations_redirect(project_id, notice))

            if action == "cancel_relation_analysis":
                try:
                    analysis_run_id = ObjectId(str(request.form.get("analysis_run_id") or ""))
                except Exception as exc:
                    raise ValueError("全量分析任务编号无效") from exc
                if not cancel_relation_analysis(analysis_run_id, project_id=project_id):
                    raise ValueError("全量分析任务不存在、已结束或不属于当前项目")
                return redirect(_parameter_relations_redirect(
                    project_id,
                    "已请求停止后台全量分析；已完成结果会保留，且不会发送业务请求。",
                ))

            if action == "auto_next":
                if not context["ready"]:
                    raise ValueError("请先配置环境、Host 与至少一套测试账号认证方案")
                if not parameter_relation.objects(project_id=project_id).first():
                    discover_project_relations(project_id)
                preprocess_relations(
                    project_id, env_id=context["env_id"], limit=20,
                    source_profile=context["source_profile"],
                    consumer_profile=context["consumer_profile"],
                )
                relation = parameter_relation.objects(
                    project_id=project_id,
                    preprocess_status="auto_ready",
                ).order_by("-machine_confidence", "id").first()
                if not relation:
                    raise ValueError("当前没有可在环境自动预算内验证的关系")
                case_relations = []
                for peer in _relation_case_relations(relation, project_id):
                    peer_view = preprocess_relation(
                        peer,
                        environment=context["environment"],
                        source_profile=context["source_profile"],
                        consumer_profile=context["consumer_profile"],
                        persist=True,
                    )
                    if peer_view["status"] not in {
                            "needs_context", "needs_data", "needs_correction",
                            "policy_blocked", "rejected", "running"}:
                        case_relations.append(peer)
                if not case_relations:
                    raise ValueError("该接口对仍缺少测试数据或存在未消歧字段")
                run, created = schedule_validation_batch(
                    case_relations, context["source_profile"], context["consumer_profile"],
                    context["environment"],
                    source_host=relation.selected_source_host or context["source_host"],
                    consumer_host=relation.selected_consumer_host or context["consumer_host"],
                    operator=operator,
                    approved_large_run=False,
                    retention_days=7,
                )
                notice = "已{} 1 个后台验证批次：该接口对的 {} 个字段共用 1 个请求案例，后台将依次请求来源接口、提取并注入字段、请求消费接口，再逐字段回写；最多 {} 次请求。".format(
                    "创建" if created else "复用已有", len(case_relations),
                    int((getattr(run, "scope", {}) or {}).get("estimated_requests") or relation.estimated_requests or 0),
                )
                return redirect(_parameter_relations_redirect(
                    project_id, notice, parameter=relation.parameter,
                ))

            if action == "validate_ready_batch":
                if not context["ready"]:
                    raise ValueError("请先配置环境、Host 与至少一套测试账号认证方案")
                if str(request.form.get("confirm_preview") or "") != "1":
                    raise ValueError("请先预览本次将执行的接口对，再确认创建批次")
                active_validation = security_test_run.objects(
                    project_id=project_id,
                    adapter_id="parameter_relation_validation",
                    scheduler_managed=True,
                    status__in=[
                        security_test_run.PREPARING,
                        security_test_run.QUEUED,
                        security_test_run.RUNNING,
                        security_test_run.CANCEL_REQUESTED,
                    ],
                ).first()
                if active_validation:
                    raise ValueError("当前已有关系验证批次在执行，请等待完成后再创建下一批")
                approved_large_run = str(
                    request.form.get("approve_large_run") or "",
                ) == "1"
                include_mutations = str(
                    request.form.get("include_mutations") or "",
                ) == "1"
                selection = select_ready_validation_batch(
                    project_id,
                    context["source_profile"],
                    context["consumer_profile"],
                    context["environment"],
                    total_request_budget=request.form.get("total_request_budget"),
                    include_mutations=include_mutations,
                    approved_large_run=approved_large_run,
                )
                preview_pair_keys = [
                    value for value in str(
                        request.form.get("preview_pair_keys") or "",
                    ).split(",")
                    if value
                ]
                selected_pair_keys = [
                    str(item.get("pair_key") or "")
                    for item in selection["pairs"]
                ]
                if selection["relations"] and (
                    not preview_pair_keys
                    or preview_pair_keys != selected_pair_keys
                ):
                    raise ValueError(
                        "可执行关系范围已发生变化，请重新预览后再确认"
                    )
                if not selection["relations"]:
                    if not selection["available_pair_count"]:
                        raise ValueError("当前没有已完成预处理且可执行的接口对，请先运行后台全量分析")
                    if selection.get("skipped_source_blocked_pair_count"):
                        raise ValueError(
                            "当前接口对的来源请求已有明确的 Fixture 或认证问题；"
                            "请先按关系卡片提示修复来源接口"
                        )
                    if selection["skipped_mutation_pair_count"]:
                        raise ValueError("当前就绪接口对均为写入/删除；如确需执行，请勾选写操作确认")
                    raise ValueError("当前总请求预算无法容纳任何就绪接口对")
                run, created = schedule_validation_batch(
                    selection["relations"],
                    context["source_profile"],
                    context["consumer_profile"],
                    context["environment"],
                    source_host="",
                    consumer_host="",
                    operator=operator,
                    approved_large_run=approved_large_run,
                    per_relation_request_budget=selection["per_case_request_budget"],
                    retention_days=7,
                )
                notice = "已{}批量验证：{} 个接口对、{} 个字段，总请求硬上限 {}（每对最多 {}）；其中只读 {} 对、写/删 {} 对。失败会逐接口对保留阶段、HTTP 状态或错误类型。".format(
                    "创建" if created else "复用已有",
                    selection["pair_count"],
                    selection["field_count"],
                    selection["reserved_requests"],
                    selection["per_case_request_budget"],
                    selection["read_pair_count"],
                    selection["mutation_pair_count"],
                )
                return redirect(_parameter_relations_redirect(project_id, notice))

            if action == "resume_validation_run":
                try:
                    validation_run = security_test_run.objects(
                        id=ObjectId(str(request.form.get("run_id") or "")),
                        project_id=project_id,
                        adapter_id="parameter_relation_validation",
                        scheduler_managed=True,
                    ).first()
                except Exception:
                    validation_run = None
                if not validation_run:
                    raise ValueError("验证批次不存在或不属于当前项目")
                if validation_run.status != security_test_run.PAUSED:
                    raise ValueError("只有等待认证恢复的批次可以重新尝试")
                auth_summary = dict(validation_run.auth_context_summary or {})
                if (
                    validation_run.dependency_type == "auth_profile"
                    or str(validation_run.last_error_type or "").startswith("AccountContext")
                    or str(auth_summary.get("error_type") or "").startswith("AccountContext")
                    or "SSO_AUTH" in str(auth_summary.get("error_detail") or "")
                ):
                    return redirect(url_for(
                        "web.project_auth",
                        project_id=validation_run.project_id,
                        env_id=validation_run.env_id,
                        resume_run_id=str(validation_run.id),
                    ))
                resume_execution(validation_run.id)
                notice = "批次已重新入队；后台会先刷新 Token/Cookie，再继续原接口对，不会创建重复案例。"
                return redirect(_parameter_relations_redirect(project_id, notice))

            relation = parameter_relation.objects(id=request.form.get("relation_id")).first()
            if not _relation_belongs_to_project(relation, project_id):
                raise ValueError("参数关系不存在或不属于当前项目")

            if action == "swap_direction":
                peers = _relation_case_relations(relation, project_id)
                for peer in peers:
                    swap_relation_direction(peer, operator=operator)
                    peer.discovery_source = "manual_override"
                    peer.stale_reason = "manual_direction_changed"
                    peer.preprocess_status = "stale"
                    peer.save()
                    preprocess_relation(
                        peer,
                        environment=context["environment"],
                        source_profile=context["source_profile"],
                        consumer_profile=context["consumer_profile"],
                        persist=True,
                        allow_direction_fix=False,
                    )
                notice = "已交换该接口对的上下游；{} 条字段映射作为人工覆盖保留，等待重新验证。".format(len(peers))
            elif action == "save_mapping":
                source_parameter = str(request.form.get("source_parameter") or "").strip()
                target_parameter = str(request.form.get("target_parameter") or "").strip()
                source_position = str(request.form.get("source_position") or "body").strip().lower()
                target_position = str(request.form.get("target_position") or "body").strip().lower()
                allowed_positions = {"query", "path", "header", "cookie", "body", "form"}
                if not source_parameter or not target_parameter:
                    raise ValueError("来源字段和消费字段不能为空")
                if source_position not in allowed_positions or target_position not in allowed_positions:
                    raise ValueError("字段位置无效")
                relation.source_parameter = source_parameter
                relation.target_parameter = target_parameter
                relation.source_position = source_position
                relation.target_position = target_position
                relation.source_locator = locator_from_path(
                    source_parameter, direction="response", position=source_position,
                )
                relation.target_locator = locator_from_path(
                    target_parameter, direction="request", position=target_position,
                )
                relation.locator_version = LOCATOR_VERSION
                relation.location_status = "resolved"
                relation.discovery_source = "manual_override"
                relation.verified = False
                relation.manual_decision = "stale"
                relation.stale_reason = "manual_mapping_changed"
                relation.preprocess_status = "stale"
                relation.reason_codes = list(dict.fromkeys(
                    list(relation.reason_codes or []) + ["MANUAL_MAPPING_OVERRIDE"],
                ))
                relation.manual_note = str(request.form.get("manual_note") or relation.manual_note or "")[:500]
                relation.modificator = operator
                relation.mtime = dt.datetime.utcnow()
                relation.save()
                preprocess_relation(
                    relation,
                    environment=context["environment"],
                    source_profile=context["source_profile"],
                    consumer_profile=context["consumer_profile"],
                    persist=True,
                    allow_direction_fix=False,
                )
                notice = "字段映射已保存为人工覆盖；自动发现不会改回，重新验证通过后转为可信。"
            elif action == "delete_relation":
                if str(request.form.get("confirm_delete") or "") != "yes":
                    raise ValueError("请先确认删除")
                relation.manual_decision = "deleted"
                relation.discovery_source = "manual_tombstone"
                relation.preprocess_status = "deleted"
                relation.stale_reason = "deleted_by_user"
                relation.verified = False
                relation.manual_note = str(request.form.get("manual_note") or relation.manual_note or "用户删除关系")[:500]
                relation.modificator = operator
                relation.mtime = dt.datetime.utcnow()
                relation.save()
                notice = "关系已删除并留下抑制标记；后续重新导入不会自动恢复。"
            elif action == "save_fixture":
                side = str(request.form.get("fixture_side") or "").strip().lower()
                if side not in {"source", "consumer"}:
                    raise ValueError("测试数据所属接口无效")
                profile = (
                    context["source_profile"] if side == "source"
                    else context["consumer_profile"]
                )
                if not context["environment"] or not profile:
                    raise ValueError("请先选择环境和对应的测试账号认证方案")
                pathid = relation.res_pathid if side == "source" else relation.req_pathid
                save_request_fixture(
                    project_id, context["environment"].env_id, pathid,
                    profile_id=profile.profile_id,
                    query=_fixture_json_value("fixture_query_json", object_only=True),
                    headers=_fixture_json_value("fixture_headers_json", object_only=True),
                    path_params=_fixture_json_value("fixture_path_json", object_only=True),
                    body=_fixture_json_value("fixture_body_json", empty_value=None),
                    note=str(request.form.get("fixture_note") or "")[:500],
                    operator=operator,
                )
                peers = _relation_case_relations(relation, project_id)
                for peer in peers:
                    if peer.manual_decision == "needs_data":
                        peer.manual_decision = ""
                        peer.save()
                    preprocess_relation(
                        peer,
                        environment=context["environment"],
                        source_profile=context["source_profile"],
                        consumer_profile=context["consumer_profile"],
                        persist=True,
                    )
                notice = "已保存{}接口测试数据；该接口对的 {} 个参数已重新预处理。".format(
                    "来源" if side == "source" else "消费", len(peers),
                )
            elif action in {"save_hosts", "validate_relation", "approve_validate"}:
                if not context["ready"]:
                    raise ValueError("请先配置环境、Host 与至少一套测试账号认证方案")
                row_source_host = request.form.get("row_source_host") or context["source_host"]
                row_consumer_host = request.form.get("row_consumer_host") or context["consumer_host"]
                case_relations = []
                view = None
                for peer in _relation_case_relations(relation, project_id):
                    select_relation_hosts(
                        peer, context["environment"], context["source_profile"],
                        context["consumer_profile"], row_source_host, row_consumer_host,
                    )
                    peer_view = preprocess_relation(
                        peer,
                        environment=context["environment"],
                        source_profile=context["source_profile"],
                        consumer_profile=context["consumer_profile"],
                        persist=True,
                    )
                    if str(peer.id) == str(relation.id):
                        view = peer_view
                    if (
                        peer.res_pathid == relation.res_pathid
                        and peer.req_pathid == relation.req_pathid
                        and peer_view["status"] not in {
                            "needs_context", "needs_data", "needs_correction",
                            "policy_blocked", "rejected", "running",
                        }
                    ):
                        case_relations.append(peer)
                view = view or preprocess_relation(
                    relation,
                    environment=context["environment"],
                    source_profile=context["source_profile"],
                    consumer_profile=context["consumer_profile"],
                    persist=True,
                )
                if action == "save_hosts":
                    notice = "Host 已保存，该接口对全部参数的机器结论已重新计算。"
                else:
                    if view["status"] in {
                            "needs_context", "needs_data", "needs_correction",
                            "policy_blocked", "rejected", "running"}:
                        raise ValueError(view["conclusion_detail"])
                    if not case_relations:
                        raise ValueError("该接口对没有可执行的参数映射")
                    run, created = schedule_validation_batch(
                        case_relations, context["source_profile"], context["consumer_profile"],
                        context["environment"],
                        source_host=relation.selected_source_host,
                        consumer_host=relation.selected_consumer_host,
                        operator=operator,
                        approved_large_run=action == "approve_validate",
                        per_relation_request_budget=(
                            _bounded_int(
                                request.form.get("request_budget"),
                                environment_execution_policy(context["environment"])["auto_request_limit"],
                                1,
                                environment_execution_policy(context["environment"])["approved_request_limit"],
                            ) if action == "approve_validate" else 0
                        ),
                        retention_days=7,
                    )
                    maximum_requests = int((getattr(run, "scope", {}) or {}).get(
                        "per_relation_request_budget",
                    ) or relation.estimated_requests or 0)
                    notice = "已{}接口对验证，{} 个参数共用一次来源/消费请求，预计最多 {} 次请求；结果分别回写。".format(
                        "创建" if created else "复用", len(case_relations), maximum_requests,
                    )
            elif action == "save_manual":
                decision = str(request.form.get("manual_decision") or "")
                if decision not in {"", "trusted", "rejected", "needs_data", "stale", "reset"}:
                    raise ValueError("人工结论无效")
                relation.manual_decision = "" if decision == "reset" else (decision or relation.manual_decision)
                relation.manual_note = str(request.form.get("manual_note") or "")[:500]
                if decision == "trusted":
                    relation.confirmed_schema_fingerprint = relation.schema_fingerprint
                    relation.stale_reason = ""
                elif decision == "reset":
                    relation.stale_reason = ""
                    if relation.discovery_source == "manual_override":
                        relation.discovery_source = "project_schema_and_traffic"
                relation.modificator = operator
                relation.mtime = dt.datetime.utcnow()
                relation.save()
                preprocess_relation(
                    relation,
                    environment=context["environment"],
                    source_profile=context["source_profile"],
                    consumer_profile=context["consumer_profile"],
                    persist=True,
                )
                relation.reload()
                sync_relation_experience(relation, operator=operator)
                notice = "人工纠偏已保存，并同步到参数经验。"
            else:
                raise ValueError("不支持的参数关系操作")
            return redirect(_parameter_relations_redirect(project_id, notice))
        except (ValueError, LargeValidationApprovalRequired) as exc:
            return redirect(_parameter_relations_redirect(project_id, "未执行：{}".format(str(exc))))
        except Exception:
            error_reference = uuid.uuid4().hex[:12]
            logger.exception(
                "parameter relation workbench action failed ref=%s action=%s project=%s",
                error_reference,
                action,
                project_id,
            )
            return redirect(_parameter_relations_redirect(
                project_id,
                "操作失败（错误编号 {}）：未创建或继续请求批次。请刷新后重试；若持续出现，请按编号查看服务日志。".format(
                    error_reference,
                ),
            ))

    page = _bounded_int(request.args.get('page'), 0, 0, 100000)
    size = _bounded_int(request.args.get('size'), 20, 1, 100)
    form = request.args
    projects = _available_projects()
    project_id = _canonical_project_id(form.get("project_id") or "")
    if not project_id and projects:
        project_id = projects[0]["id"]
    validation_context = _parameter_validation_context(
        project_id,
        form.get("env_id"), form.get("source_profile_id"),
        form.get("consumer_profile_id"), form.get("source_host"),
        form.get("consumer_host"),
    )
    project_pathids = {item.ptah_id for item in _project_endpoints(project_id)}
    base_raw = {"manual_decision": {"$ne": "deleted"}}
    if form.get('parameter'):
        base_raw['parameter'] = {'$regex': form.get('parameter'), '$options': 'i'}
    if project_id:
        base_raw['project_id'] = project_id
    elif project_pathids:
        base_raw['$or'] = [
            {'req_pathid': {'$in': list(project_pathids)}},
            {'res_pathid': {'$in': list(project_pathids)}},
        ]
    task = str(form.get("task") or "")
    raw = dict(base_raw)
    if task:
        raw["preprocess_status"] = task
    objects = parameter_relation.objects(__raw__=raw).order_by(
        '-machine_confidence', '-last_preprocessed_at', '-id',
    )
    # One source/consumer endpoint pair is one user task.  Multiple field
    # mappings on that pair are rendered and executed together instead of
    # duplicating the same request editor once per parameter.
    grouped = {}
    for relation in objects:
        grouped.setdefault((relation.res_pathid, relation.req_pathid), relation)
    grouped_rows = list(grouped.values())
    count = len(grouped_rows)
    hits = grouped_rows[page * size: page * size + size]
    views = []
    evidence_cache = {}
    inspect_pair = str(form.get("inspect_pair") or "")
    for relation in hits:
        pair_key = "{}:{}".format(relation.res_pathid, relation.req_pathid)
        detail_loaded = pair_key == inspect_pair or count == 1
        if detail_loaded:
            # Expanding one card recomputes account-specific request readiness
            # and loads its full endpoint evidence.  The list itself remains a
            # fast projection over persisted preprocessing results.
            view = preprocess_relation(
                relation,
                environment=validation_context["environment"],
                source_profile=validation_context["source_profile"],
                consumer_profile=validation_context["consumer_profile"],
                persist=False,
                allow_direction_fix=False,
                update_readiness=False,
            )
            highlight_names = tuple(sorted(set(view.get("pair_parameters") or [])))
            for side in ("source", "consumer"):
                pathid = (view.get(side) or {}).get("pathid")
                cache_key = (pathid, highlight_names)
                if cache_key not in evidence_cache:
                    evidence_cache[cache_key] = endpoint_evidence_view(
                        pathid, highlight_names=highlight_names, sample_limit=2,
                    )
                view["{}_detail".format(side)] = evidence_cache[cache_key]
        else:
            summary = dict(relation.preprocess_summary or {})
            view = relation_workbench_view(
                relation,
                environment=validation_context["environment"],
                source_profile=validation_context["source_profile"],
                consumer_profile=validation_context["consumer_profile"],
                source_input=dict(summary.get("source_input") or {}),
                consumer_input=dict(summary.get("consumer_input") or {}),
            )
        view["pair_key"] = pair_key
        view["detail_loaded"] = detail_loaded
        view["detail_url"] = url_for(
            "web.parameter_relations",
            project_id=project_id,
            env_id=validation_context["env_id"],
            source_profile_id=validation_context["source_profile_id"],
            consumer_profile_id=validation_context["consumer_profile_id"],
            source_host=validation_context["source_host"],
            consumer_host=validation_context["consumer_host"],
            task=form.get("task") or "",
            parameter=form.get("parameter") or "",
            size=size,
            page=page,
            inspect_pair=pair_key,
        ) + "#pair-{}".format(pair_key.replace(":", "-"))
        views.append(view)

    total = parameter_relation.objects(__raw__=base_raw).count()
    total_pairs = len({
        (relation.res_pathid, relation.req_pathid)
        for relation in parameter_relation.objects(__raw__=base_raw).only(
            "res_pathid", "req_pathid",
        )
    })
    queue_order = [
        "auto_ready", "running", "verified", "trusted", "accepted", "needs_context",
        "needs_data", "automatic_failed", "needs_correction", "approval_required",
        "policy_blocked", "stale", "rejected", "pending",
    ]
    queue_counts = {}
    for status in queue_order:
        query = dict(base_raw)
        query["preprocess_status"] = status
        queue_counts[status] = parameter_relation.objects(__raw__=query).count()
    validation_run = _parameter_validation_run_view(project_id)
    analysis_run = _parameter_analysis_run_view(project_id)
    ready_pairs = {
        (row.res_pathid, row.req_pathid)
        for row in parameter_relation.objects(
            project_id=project_id,
            preprocess_status="auto_ready",
            manual_decision__nin=["rejected", "deleted"],
        ).only("res_pathid", "req_pathid")
    } if project_id else set()
    approval_pairs = {
        (row.res_pathid, row.req_pathid)
        for row in parameter_relation.objects(
            project_id=project_id,
            preprocess_status="approval_required",
            manual_decision__nin=["rejected", "deleted"],
        ).only("res_pathid", "req_pathid")
    } if project_id else set()
    ready_consumer_ids = sorted({pair[1] for pair in ready_pairs})
    ready_methods = {
        int(endpoint.ptah_id): str(endpoint.method or "").upper()
        for endpoint in raw_data.objects(
            project_id=project_id,
            ptah_id__in=ready_consumer_ids,
        ).only("ptah_id", "method")
    } if ready_consumer_ids else {}
    ready_mutation_pairs = sum(
        1 for _source_pathid, consumer_pathid in ready_pairs
        if ready_methods.get(consumer_pathid) in {"POST", "PUT", "PATCH", "DELETE"}
    )
    ready_read_pairs = sum(
        1 for _source_pathid, consumer_pathid in ready_pairs
        if ready_methods.get(consumer_pathid) in {"GET", "HEAD", "OPTIONS"}
    )
    execution_policy = environment_execution_policy(validation_context["environment"])
    if validation_run:
        validation_run["recommended_retry_budget"] = min(
            int(validation_run.get("recommended_retry_budget") or 1),
            int(execution_policy["approved_request_limit"]),
        )
    default_batch_budget = min(
        30,
        int(execution_policy["auto_request_limit"]),
    )
    preview_requested = str(form.get("preview_batch") or "") == "1"
    preview_budget = str(
        form.get("total_request_budget") or default_batch_budget
    )
    preview_include_mutations = str(
        form.get("include_mutations") or ""
    ) == "1"
    preview_approved_large_run = str(
        form.get("approve_large_run") or ""
    ) == "1"
    batch_selection_preview = None
    batch_preview_error = ""
    if preview_requested:
        if not validation_context["ready"]:
            batch_preview_error = "请先配置环境、Host 与至少一套测试账号认证方案"
        else:
            try:
                batch_selection_preview = select_ready_validation_batch(
                    project_id,
                    validation_context["source_profile"],
                    validation_context["consumer_profile"],
                    validation_context["environment"],
                    total_request_budget=preview_budget,
                    include_mutations=preview_include_mutations,
                    approved_large_run=preview_approved_large_run,
                )
                if not batch_selection_preview["relations"]:
                    if not batch_selection_preview["available_pair_count"]:
                        batch_preview_error = "当前没有可自动执行的接口对"
                    elif batch_selection_preview.get(
                        "skipped_source_blocked_pair_count"
                    ):
                        batch_preview_error = (
                            "当前接口对的来源请求已有明确的 Fixture 或认证问题"
                        )
                    elif batch_selection_preview["skipped_mutation_pair_count"]:
                        batch_preview_error = "当前可选接口对均为写入/删除，请明确勾选写操作后重新预览"
                    else:
                        batch_preview_error = "当前总请求预算无法容纳任何就绪接口对"
                    batch_selection_preview = None
                else:
                    batch_selection_preview["pair_keys_csv"] = ",".join(
                        str(item.get("pair_key") or "")
                        for item in batch_selection_preview["pairs"]
                    )
            except (LargeValidationApprovalRequired, ValueError) as exc:
                batch_preview_error = str(exc)
    stats = {
        "total": total,
        "pairs": total_pairs,
        "machine_ready": queue_counts.get("auto_ready", 0),
        "ready_pairs": len(ready_pairs),
        "ready_read_pairs": ready_read_pairs,
        "ready_mutation_pairs": ready_mutation_pairs,
        "approval_pairs": len(approval_pairs),
        "active_batches": validation_run.get("active_count", 0) if validation_run else 0,
        "analysis_active": bool(analysis_run and analysis_run.get("active")),
        "validation_blocked": bool(validation_run and validation_run.get("needs_auth_action")),
        "running": queue_counts.get("running", 0),
        "verified": queue_counts.get("verified", 0),
        "human_correction": queue_counts.get("needs_correction", 0),
        "stale": queue_counts.get("stale", 0),
        "needs_context": (
            queue_counts.get("needs_context", 0)
            + queue_counts.get("needs_data", 0)
            + queue_counts.get("policy_blocked", 0)
        ),
        "approval": queue_counts.get("approval_required", 0),
    }
    return {
        'form': form,
        'projects': projects,
        'page': page,
        'size': size,
        'count': count,
        'hits': views,
        'stats': stats,
        'queue_tabs': [
            {"key": "", "label": "全部字段映射", "count": total},
        ] + [
            {"key": status, "label": RELATION_STATUS_LABELS.get(status, status), "count": queue_counts.get(status, 0)}
            for status in queue_order if queue_counts.get(status, 0)
        ],
        'hit': get_page(page, size, count),
        'saved': request.args.get("saved") or "",
        'project_id': project_id,
        'validation_context': validation_context,
        'validation_run': validation_run,
        'analysis_run': analysis_run,
        'batch_selection_preview': batch_selection_preview,
        'batch_preview_error': batch_preview_error,
        'batch_preview': {
            "ready_pairs": len(ready_pairs),
            "read_pairs": ready_read_pairs,
            "mutation_pairs": ready_mutation_pairs,
            "approval_pairs": len(approval_pairs),
            "default_budget": default_batch_budget,
            "default_pair_capacity": default_batch_budget // 3,
            "requested_budget": preview_budget,
            "preview_requested": preview_requested,
            "preview_include_mutations": preview_include_mutations,
            "preview_approved_large_run": preview_approved_large_run,
        },
        'execution_policy': execution_policy,
        'csrf_token': _lifecycle_csrf_token(),
        'can_manage': is_manager(),
    }


def _status_count(rows):
    counts = {}
    for row in rows:
        counts[row.status] = counts.get(row.status, 0) + 1
    return counts


PARAM_AUTH_NAMES = {
    "authorization", "cookie", "token", "access_token", "accesstoken",
    "refresh_token", "session", "sessionid", "sid", "csrf", "xsrf",
    "sign", "signature", "nonce", "timestamp", "ts",
}
PARAM_TENANT_NAMES = {
    "entid", "ent_id", "enterpriseid", "enterprise_id", "tenantid",
    "tenant_id", "orgid", "org_id", "departmentid", "department_id",
    "department_ids", "deptid", "dept_id", "companyid", "company_id",
}
PARAM_OWNER_NAMES = {
    "userid", "user_id", "uid", "account", "accountid", "account_id",
    "ownerid", "owner_id", "memberid", "member_id", "entuserid",
}
PARAM_PAGING_NAMES = {
    "page", "pageindex", "pagenum", "pagesize", "size", "limit",
    "offset", "start", "count", "sort", "order", "keyword", "search", "q",
}
PARAM_CONFIG_NAMES = {
    "type", "status", "state", "version", "module", "mode", "config",
    "enabled", "enable", "switch", "level", "name", "title", "remark",
}

PARAM_ROLE_OPTIONS = [
    {"key": "auth_context", "label": "鉴权/会话上下文"},
    {"key": "tenant_scope", "label": "租户/组织范围"},
    {"key": "owner_identity", "label": "用户/所有者身份"},
    {"key": "resource_identifier", "label": "资源标识"},
    {"key": "business_config", "label": "业务配置/状态"},
    {"key": "pagination_filter", "label": "分页/过滤条件"},
    {"key": "unknown", "label": "待判断"},
]
PARAM_ROLE_LABELS = {item["key"]: item["label"] for item in PARAM_ROLE_OPTIONS}
PARAM_CANDIDATE_ROLE_MAP = {
    "resource_id": "resource_identifier",
    "tenant_id": "tenant_scope",
    "owner_id": "owner_identity",
}

PARAM_REUSE_OPTIONS = [
    {"key": "reusable", "label": "可复用"},
    {"key": "conditional", "label": "有条件复用"},
    {"key": "single_use", "label": "单次使用"},
    {"key": "do_not_reuse", "label": "不复用"},
    {"key": "unknown", "label": "待判断"},
]
PARAM_REUSE_LABELS = {item["key"]: item["label"] for item in PARAM_REUSE_OPTIONS}

PARAM_CHAIN_OPTIONS = [
    {"key": "can_build_chain", "label": "可用于构链"},
    {"key": "needs_verify", "label": "需验证后构链"},
    {"key": "do_not_use", "label": "不参与构链"},
    {"key": "unknown", "label": "待判断"},
]
PARAM_CHAIN_LABELS = {item["key"]: item["label"] for item in PARAM_CHAIN_OPTIONS}

PARAM_VALIDATION_OPTIONS = [
    {"key": "verified", "label": "已验证"},
    {"key": "needs_verify", "label": "待验证"},
    {"key": "needs_data", "label": "待补数据"},
    {"key": "conflict", "label": "验证冲突"},
    {"key": "ignored", "label": "忽略"},
]
PARAM_VALIDATION_LABELS = {item["key"]: item["label"] for item in PARAM_VALIDATION_OPTIONS}

PARAM_SCOPE_OPTIONS = [
    {"key": "project", "label": "项目级"},
    {"key": "host", "label": "Host 级"},
    {"key": "path_prefix", "label": "路径前缀"},
    {"key": "interface_group", "label": "接口组"},
    {"key": "single_interface", "label": "单接口"},
]
PARAM_SCOPE_LABELS = {item["key"]: item["label"] for item in PARAM_SCOPE_OPTIONS}


def _option_label(options, key):
    labels = {item["key"]: item["label"] for item in options}
    return labels.get(key or "", key or "待判断")


def _param_leaf(name):
    return str(name or "").split(".")[-1].strip().lower()


def _parameter_family_match(name, family):
    value = str(name or "").lower().replace("-", "_")
    padded = "_{}_".format(value.strip("_"))
    return any(
        padded == "_{}_".format(str(token).strip("_").lower())
        or "_{}_".format(str(token).strip("_").lower()) in padded
        for token in family
        if token
    )


def _project_id_from_endpoint(endpoint):
    meta = endpoint.source_meta or {}
    value = meta.get("apifox_project_id") or meta.get("project_id") or meta.get("projectId") or ""
    return str(value or "")


def _canonical_project_id(project_id):
    """Resolve a stable ApiProject id while accepting legacy source ids."""
    value = str(project_id or "").strip()
    if not value:
        return ""
    if ApiProject.objects(project_id=value, status=ApiProject.ACTIVE).first():
        return value
    binding = ProjectSourceBinding.objects(
        source_type="apifox", source_id=value, active=True,
    ).first()
    return str(binding.project_id or value) if binding else value


def _project_source_ids(project_id):
    stable_id = _canonical_project_id(project_id)
    values = []
    if stable_id:
        for binding in ProjectSourceBinding.objects(
                project_id=stable_id, source_type="apifox", active=True):
            source_id = str(binding.source_id or "")
            if source_id and source_id not in values:
                values.append(source_id)
    raw_value = str(project_id or "").strip()
    if raw_value and raw_value != stable_id and raw_value not in values:
        values.append(raw_value)
    return values


def _available_projects():
    rows = []
    for project in ApiProject.objects(status=ApiProject.ACTIVE).order_by("name", "project_id"):
        source_ids = _project_source_ids(project.project_id)
        count = raw_data.objects(project_id=project.project_id).count()
        if not count and source_ids:
            typed_ids = []
            for source_id in source_ids:
                typed_ids.extend([source_id, int(source_id) if source_id.isdigit() else source_id])
            count = raw_data.objects(
                source="apifox", source_meta__apifox_project_id__in=typed_ids,
            ).count()
        rows.append({
            "id": project.project_id,
            "name": project.name or project.project_id,
            "source_ids": source_ids,
            "count": count,
        })
    if rows:
        return rows

    # Compatibility fallback for databases that have not run project-context
    # migration yet. New writes still resolve to a stable project when one is
    # available.
    projects = {}
    for row in raw_data.objects(source="apifox").only("source_meta").limit(5000):
        project_id = _project_id_from_endpoint(row)
        if not project_id:
            continue
        projects.setdefault(project_id, 0)
        projects[project_id] += 1
    return [
        {"id": key, "name": "Apifox {}".format(key), "source_ids": [key], "count": value}
        for key, value in sorted(projects.items(), key=lambda item: item[0])
    ]


def _parameter_rule_assessment(parameter, docs, relations, candidates):
    low = _param_leaf(parameter)
    full = str(parameter or "").lower().replace("-", "_")
    reasons = []
    score = 10.0
    role = "unknown"
    if _parameter_family_match(full, PARAM_AUTH_NAMES):
        role, score = "auth_context", 95.0
        reasons.append("鉴权/会话类名称")
    elif _parameter_family_match(full, PARAM_TENANT_NAMES):
        role, score = "tenant_scope", 88.0
        reasons.append("租户/组织/部门类名称")
    elif _parameter_family_match(full, PARAM_OWNER_NAMES):
        role, score = "owner_identity", 84.0
        reasons.append("用户/所有者身份类名称")
    elif low.endswith("ids") or low.endswith("id") or full.endswith("_ids") or full.endswith("_id"):
        role, score = "resource_identifier", 76.0
        reasons.append("资源标识类后缀")
    elif low in PARAM_CONFIG_NAMES:
        role, score = "business_config", 55.0
        reasons.append("业务配置/状态类名称")
    elif low in PARAM_PAGING_NAMES:
        role, score = "pagination_filter", 25.0
        reasons.append("分页/过滤类参数")
    if docs:
        score += min(8.0, len(docs) * 1.5)
        reasons.append("文档出现 {} 次".format(len(docs)))
    if relations:
        score += min(10.0, len(relations) * 2.0)
        reasons.append("关系候选 {} 条".format(len(relations)))
    if candidates:
        best = max(candidates, key=lambda item: item.role_confidence or 0)
        if best.role and best.role != "unknown":
            candidate_role = best.manual_role or best.role
            role = PARAM_CANDIDATE_ROLE_MAP.get(candidate_role, candidate_role)
            score = max(score, float(best.role_confidence or 0) * 100)
            reasons.append("已有安全参数候选 {}".format(role))
    return {
        "role": role,
        "weight": round(min(100.0, max(0.0, score)), 2),
        "reasons": reasons or ["暂无强信号"],
    }


def _parameter_meaning_summary(item, review=None, experience=None):
    if experience and experience.business_meaning:
        return experience.business_meaning
    if review and review.manual_note:
        return review.manual_note
    for doc in item.sample_docs or []:
        desc = doc.get("description") or doc.get("endpoint_description")
        if desc:
            return str(desc)[:160]
    if item.rule_reasons:
        return "；".join(item.rule_reasons[:3])
    return "待人工确认参数含义"


def _parameter_next_action(item, experience=None):
    status = experience.process_status if experience and experience.id else ""
    if status in ["trusted", "reusable", "rejected"]:
        return "已归档，按经验复用"
    if status == "conflict":
        return "查看冲突并拆分/纠偏"
    if item.relation_count:
        return "进入参数中心验证关系"
    if item.request_doc_count and not item.response_doc_count:
        return "补来源样本或响应证据"
    return "人工确认含义和范围"


def _find_parameter_experience(project_id, parameter, group_key=""):
    project_id = _canonical_project_id(project_id)
    parameter = str(parameter or "")
    group_key = str(group_key or parameter)
    experience = parameter_experience.objects(
        project_id=project_id,
        parameter=parameter,
        group_key=group_key,
    ).first()
    if experience:
        return experience
    existing = parameter_experience.objects(project_id=project_id, parameter=parameter).order_by("-mtime").first()
    if existing and not existing.group_key:
        existing.group_key = group_key
        return existing
    return parameter_experience(
        project_id=project_id,
        parameter=parameter,
        group_key=group_key,
        ctime=dt.datetime.utcnow(),
    )


def _selected_parameters_from_form(form):
    values = form.getlist("selected_params")
    if not values and form.get("parameters"):
        values = [form.get("parameters")]
    selected = []
    for value in values:
        for item in str(value or "").split("||"):
            item = item.strip()
            if item and item not in selected:
                selected.append(item)
    return selected


def _parameter_priority_rows(project_id="", q="", page=0, limit=100, *,
                             importance="", usage="", role="", readiness="",
                             relation="", experience_status="", sort="combined"):
    project_id = _canonical_project_id(project_id)
    page = max(0, int(page or 0))
    limit = max(1, int(limit or 100))
    all_items = list(parameter_priority_item.objects(
        project_id=project_id,
    ))
    project_has_traffic = any(int(item.usage_count or 0) > 0 for item in all_items)
    items = all_items
    if q:
        needle = str(q).lower()
        items = [
            item for item in items
            if needle in " ".join(str(value or "") for value in (
                [item.parameter, item.canonical_key]
                + list(item.aliases or [])
                + list(item.raw_paths or [])
            )).lower()
        ]
    names = sorted({
        name
        for item in items
        for name in (
            [item.parameter, item.canonical_key]
            + list(item.aliases or [])
            + list(item.raw_paths or [])
        )
        if name
    })
    reviews_by_param = {}
    experiences_by_param = {}
    if names:
        for review in parameter_priority_review.objects(
                project_id=str(project_id or ""), parameter__in=names).order_by("-mtime"):
            reviews_by_param.setdefault(review.parameter, review)
        for experience in parameter_experience.objects(project_id=str(project_id or ""), parameter__in=names).order_by("-mtime"):
            experiences_by_param.setdefault(experience.parameter, experience)
    groups = {}
    for item in items:
        lookup_names = [item.parameter] + list(item.aliases or []) + list(item.raw_paths or [])
        review = next((reviews_by_param.get(name) for name in lookup_names if reviews_by_param.get(name)), None)
        experience = next((
            experiences_by_param.get(name) for name in lookup_names
            if experiences_by_param.get(name)
        ), None)
        group_key = experience.group_key if experience and experience.group_key else item.parameter
        group = groups.setdefault(group_key, {
            "items": [],
            "reviews": [],
            "experiences": [],
            "parameters": [],
            "aliases": set(),
            "raw_paths": set(),
            "canonical_keys": set(),
        })
        group["items"].append(item)
        if review:
            group["reviews"].append(review)
        if experience:
            group["experiences"].append(experience)
        group["parameters"].append(item.parameter)
        group["aliases"].update(item.aliases or [])
        group["raw_paths"].update(item.raw_paths or [])
        if item.canonical_key:
            group["canonical_keys"].add(item.canonical_key)

    rows = []
    for group_key, group in groups.items():
        group_items = group["items"]
        item = max(group_items, key=lambda value: float(value.rule_weight or 0))
        review = group["reviews"][0] if group["reviews"] else None
        experience = group["experiences"][0] if group["experiences"] else None
        final_weight = review.manual_weight if review and review.manual_weight is not None else item.rule_weight
        final_role = (
            experience.role if experience and experience.role and experience.role != "unknown"
            else review.manual_role if review and review.manual_role
            else item.rule_role
        )
        all_reasons = []
        sample_docs = []
        for member in group_items:
            for reason in member.rule_reasons or []:
                if reason not in all_reasons:
                    all_reasons.append(reason)
            sample_docs.extend(member.sample_docs or [])
        usage_count = sum(int(member.usage_count or 0) for member in group_items)
        usage_score = max(float(member.usage_score or 0) for member in group_items)
        usage_sources = CollectionCounter()
        last_observed_at = None
        for member in group_items:
            usage_sources.update(dict(member.usage_sources or {}))
            if member.last_observed_at and (
                    not last_observed_at or member.last_observed_at > last_observed_at):
                last_observed_at = member.last_observed_at
        composite_score = (
            round(float(final_weight or 0) * 0.7 + usage_score * 0.3, 1)
            if project_has_traffic else round(float(final_weight or 0), 1)
        )
        row = {
            "parameter": group_key,
            "parameters": group["parameters"],
            "canonical_keys": sorted(group["canonical_keys"]),
            "aliases": sorted(
                (set(group["parameters"]) | group["aliases"]) - {group_key}
            ),
            "raw_paths": sorted(group["raw_paths"]),
            "selected_value": "||".join(group["parameters"]),
            "is_group": bool(
                len(group["parameters"]) > 1
                or group["aliases"]
                or any(path != group_key for path in group["raw_paths"])
            ),
            "normalization_version": item.normalization_version or "legacy",
            "rule": {
                "role": item.rule_role,
                "weight": item.rule_weight,
                "reasons": all_reasons,
            },
            "review": review,
            "experience": experience,
            "experience_status_label": _option_label(PARAM_PROCESS_STATUSES, experience.process_status) if experience else "",
            "final_weight": final_weight,
            "usage_count": usage_count,
            "usage_score": round(usage_score, 1),
            "usage_sources": dict(usage_sources),
            "last_observed_at": last_observed_at,
            "project_has_traffic": project_has_traffic,
            "composite_score": composite_score,
            "final_role": final_role,
            "final_role_label": _option_label(PARAM_ROLE_OPTIONS, final_role),
            "meaning_summary": _parameter_meaning_summary(item, review=review, experience=experience),
            "next_action": _parameter_next_action(item, experience=experience),
            "doc_count": sum(member.doc_count or 0 for member in group_items),
            "request_doc_count": sum(member.request_doc_count or 0 for member in group_items),
            "response_doc_count": sum(member.response_doc_count or 0 for member in group_items),
            "relation_count": sum(member.relation_count or 0 for member in group_items),
            "candidate_count": sum(member.candidate_count or 0 for member in group_items),
            "endpoint_count": sum(member.endpoint_count or 0 for member in group_items),
            "readiness_score": max(float(member.readiness_score or 0) for member in group_items),
            "readiness_status": item.readiness_status or "unknown",
            "readiness_reasons": list(item.readiness_reasons or []),
            "work_priority": max(float(member.work_priority or 0) for member in group_items),
            "sample_docs": sample_docs[:5],
            "mtime": item.mtime,
        }
        row["usage_label"] = (
            "高频" if usage_score >= 70 else
            "常用" if usage_score >= 25 else
            "已观察" if usage_count > 0 else
            "未观察"
        )
        rows.append(row)

    def matches(row):
        weight = float(row["final_weight"] or 0)
        if importance == "high" and weight < 80:
            return False
        if importance == "medium" and not 55 <= weight < 80:
            return False
        if importance == "low" and weight >= 55:
            return False
        if usage == "high" and float(row["usage_score"] or 0) < 70:
            return False
        if usage == "active" and not 25 <= float(row["usage_score"] or 0) < 70:
            return False
        if usage == "observed" and int(row["usage_count"] or 0) <= 0:
            return False
        if usage == "unobserved" and int(row["usage_count"] or 0) > 0:
            return False
        if role and row["final_role"] != role:
            return False
        score = float(row["readiness_score"] or 0)
        if readiness == "ready" and score < 80:
            return False
        if readiness == "partial" and not 40 <= score < 80:
            return False
        if readiness == "blocked" and score >= 40:
            return False
        if relation == "related" and int(row["relation_count"] or 0) <= 0:
            return False
        if relation == "unrelated" and int(row["relation_count"] or 0) > 0:
            return False
        if experience_status:
            current = row["experience"].process_status if row["experience"] else "unreviewed"
            if current != experience_status:
                return False
        return True

    rows = [row for row in rows if matches(row)]
    if sort == "importance":
        rows.sort(key=lambda row: (-float(row["final_weight"] or 0), row["parameter"]))
    elif sort == "usage":
        rows.sort(key=lambda row: (-int(row["usage_count"] or 0), -float(row["usage_score"] or 0), row["parameter"]))
    elif sort == "readiness":
        rows.sort(key=lambda row: (-float(row["readiness_score"] or 0), -float(row["composite_score"] or 0), row["parameter"]))
    elif sort == "work":
        rows.sort(key=lambda row: (-float(row["work_priority"] or 0), -float(row["composite_score"] or 0), row["parameter"]))
    elif sort == "recent":
        rows.sort(key=lambda row: (row["mtime"] or dt.datetime.min, row["parameter"]), reverse=True)
    elif sort == "name":
        rows.sort(key=lambda row: row["parameter"].lower())
    else:
        rows.sort(key=lambda row: (-float(row["composite_score"] or 0), -float(row["final_weight"] or 0), row["parameter"]))
    total = len(rows)
    start = page * limit
    return rows[start:start + limit], total


def _param_doc_row(param_doc, role):
    """Project one request/response parameter occurrence for the priority UI."""
    endpoint = param_doc.raw_data
    meta = (endpoint.source_meta or {}) if endpoint else {}
    return {
        "role": role,
        "parameter": param_doc.parameter,
        "display_path": getattr(param_doc, "display_path", "") or param_doc.parameter,
        "schema_path": getattr(param_doc, "schema_path", "") or "",
        "canonical_name": getattr(param_doc, "canonical_name", "") or "",
        "position": param_doc.position,
        "type": param_doc.type,
        "required": getattr(param_doc, "required", None),
        "description": param_doc.des,
        "values": list(param_doc.value or [])[:5],
        "source_meta": param_doc.source_meta or {},
        "pathid": endpoint.ptah_id if endpoint else None,
        "method": endpoint.method if endpoint else "",
        "path": endpoint.path if endpoint else "",
        "domain": endpoint.domain if endpoint else "",
        "endpoint_description": endpoint.des if endpoint else "",
        "apifox_endpoint_id": meta.get("apifox_endpoint_id"),
        "apifox_server_id": meta.get("apifox_server_id"),
        "apifox_name": meta.get("name"),
        "apifox_status": meta.get("status"),
    }


def _build_parameter_priority_items(project_id=""):
    project_id = _canonical_project_id(project_id)
    endpoints = _project_endpoints(project_id)
    pathids = {item.ptah_id for item in endpoints}
    param_map = {}

    def add_occurrence(doc, role):
        raw_name = str(doc.parameter or "")
        identity = parameter_identity(raw_name, getattr(doc, "canonical_name", ""))
        if not raw_name or not identity:
            return
        entry = param_map.setdefault(identity, {
            "canonical_key": identity,
            "docs": [],
            "req_docs": [],
            "res_docs": [],
            "alias_counts": CollectionCounter(),
            "raw_paths": set(),
            "pathids": set(),
        })
        entry["docs"].append(doc)
        entry["{}_docs".format(role)].append(doc)
        alias = occurrence_alias(raw_name, getattr(doc, "canonical_name", ""))
        if alias:
            entry["alias_counts"][alias] += 1
        entry["raw_paths"].add(raw_name)
        if getattr(doc, "raw_data", None) and getattr(doc.raw_data, "ptah_id", None) is not None:
            entry["pathids"].add(int(doc.raw_data.ptah_id))

    for doc in req_data.objects(raw_data__in=endpoints).select_related(max_depth=1) if endpoints else []:
        add_occurrence(doc, "req")
    for doc in res_data.objects(raw_data__in=endpoints).select_related(max_depth=1) if endpoints else []:
        add_occurrence(doc, "res")

    pathid_list = list(pathids)
    relations_by_param = {}
    candidates_by_param = {}
    if param_map:
        relation_query = {}
        if pathid_list:
            relation_query["$or"] = [
                {"req_pathid": {"$in": pathid_list}},
                {"res_pathid": {"$in": pathid_list}},
            ]
        elif project_id:
            relation_query["project_id"] = project_id
        for rel in parameter_relation.objects(__raw__=relation_query):
            identity = parameter_identity(rel.parameter)
            if identity in param_map:
                relations_by_param.setdefault(identity, []).append(rel)
        if pathid_list:
            for candidate in idor_parameter_candidate.objects(pathid__in=pathid_list):
                identity = parameter_identity(candidate.parameter)
                if identity in param_map:
                    candidates_by_param.setdefault(identity, []).append(candidate)

    usage_by_path = {}
    if pathid_list:
        for sample in request_sample.objects(pathid__in=pathid_list).only(
                "pathid", "source", "hit_count", "last_seen"):
            source = str(sample.source or "").strip().lower()
            if source not in TRAFFIC_SOURCES:
                continue
            info = usage_by_path.setdefault(int(sample.pathid), {
                "hits": 0, "sources": CollectionCounter(), "last_seen": None,
            })
            hits = max(1, int(sample.hit_count or 0))
            info["hits"] += hits
            info["sources"][source or "traffic"] += hits
            if sample.last_seen and (not info["last_seen"] or sample.last_seen > info["last_seen"]):
                info["last_seen"] = sample.last_seen

    entry_usage = {}
    for identity, entry in param_map.items():
        hits = 0
        sources = CollectionCounter()
        last_seen = None
        for pathid in entry["pathids"]:
            info = usage_by_path.get(pathid) or {}
            hits += int(info.get("hits") or 0)
            sources.update(info.get("sources") or {})
            observed = info.get("last_seen")
            if observed and (not last_seen or observed > last_seen):
                last_seen = observed
        entry_usage[identity] = {"hits": hits, "sources": dict(sources), "last_seen": last_seen}
    max_usage = max((item["hits"] for item in entry_usage.values()), default=0)

    now = dt.datetime.utcnow()
    built = 0
    selected_names = []
    for identity, entry in sorted(param_map.items()):
        name = preferred_parameter_name(identity, entry["alias_counts"])
        aliases = sorted(set(entry["alias_counts"]) - {name})
        raw_paths = sorted(entry["raw_paths"])
        relations = relations_by_param.get(identity, [])
        candidates = candidates_by_param.get(identity, [])
        rule = _parameter_rule_assessment(name, entry["docs"], relations, candidates)
        usage = entry_usage.get(identity) or {"hits": 0, "sources": {}, "last_seen": None}
        usage_score = (
            100.0 * math.log1p(usage["hits"]) / math.log1p(max_usage)
            if max_usage > 0 else 0.0
        )
        sample_docs = []
        entry_pathids = set()
        seen_samples = set()
        for role, docs in (("request", entry["req_docs"]), ("response", entry["res_docs"])):
            for doc in docs:
                row = _param_doc_row(doc, role)
                if row.get("pathid"):
                    entry_pathids.add(row.get("pathid"))
                sample_key = (role, row.get("parameter"), row.get("pathid"))
                if sample_key not in seen_samples and len(sample_docs) < 5:
                    sample_docs.append(row)
                    seen_samples.add(sample_key)
        item = parameter_priority_item.objects(project_id=project_id, parameter=name).first()
        if not item:
            item = parameter_priority_item.objects(
                project_id=project_id, canonical_key=identity,
            ).first()
        if not item:
            item = parameter_priority_item(project_id=project_id, parameter=name, ctime=now)
        item.parameter = name
        item.canonical_key = identity
        item.aliases = aliases
        item.raw_paths = raw_paths
        item.normalization_version = PARAMETER_NORMALIZATION_VERSION
        item.rule_role = rule["role"]
        item.rule_weight = rule["weight"]
        item.rule_reasons = rule["reasons"]
        item.doc_count = len(entry["docs"])
        item.request_doc_count = len(entry["req_docs"])
        item.response_doc_count = len(entry["res_docs"])
        item.endpoint_count = len(entry_pathids)
        item.relation_count = len(relations)
        item.candidate_count = len(candidates)
        item.usage_count = int(usage["hits"])
        item.usage_score = round(usage_score, 2)
        item.composite_score = round(
            rule["weight"] * 0.7 + usage_score * 0.3, 2,
        ) if max_usage > 0 else float(rule["weight"])
        item.usage_sources = dict(usage["sources"])
        item.last_observed_at = usage["last_seen"]
        item.sample_docs = sample_docs[:5]
        item.mtime = now
        item.save()
        refresh_parameter_readiness(project_id, name, relations=relations)
        selected_names.append(name)
        built += 1
    if selected_names:
        parameter_priority_item.objects(project_id=project_id, parameter__nin=selected_names).delete()
    else:
        parameter_priority_item.objects(project_id=project_id).delete()
    return built


@bp_web.route("/parameter-priority", methods=["GET", "POST"])
@login_check
@templated("/parameter-priority.html")
def parameter_priority():
    if request.method == "POST":
        action = request.form.get("action") or "review"
        project_id = _canonical_project_id(request.form.get("project_id") or "")
        redirect_filters = {
            key: request.form.get(key) or ""
            for key in (
                "q", "importance", "usage", "role", "readiness",
                "relation", "experience_status", "sort", "limit",
            )
        }
        if action == "refresh":
            built = _build_parameter_priority_items(project_id=project_id)
            return redirect(url_for(
                "web.parameter_priority", project_id=project_id, refreshed=built,
                **redirect_filters
            ))
        if action in {"batch_experience", "merge_experience"}:
            selected = _selected_parameters_from_form(request.form)
            batch_role = request.form.get("batch_role") or ""
            batch_status = request.form.get("batch_status") or ""
            batch_reuse = request.form.get("batch_reuse_policy") or ""
            batch_chain = request.form.get("batch_chain_policy") or ""
            batch_note = request.form.get("batch_note") or ""
            batch_group_key = (request.form.get("batch_group_key") or "").strip()
            batch_business_meaning = (request.form.get("batch_business_meaning") or "").strip()
            if action == "merge_experience" and not batch_group_key:
                batch_group_key = selected[0] if selected else ""
            saved_count = 0
            for parameter in selected:
                item = parameter_priority_item.objects(project_id=str(project_id or ""), parameter=parameter).first()
                group_key = batch_group_key or parameter
                if action == "merge_experience":
                    parameter_experience.objects(
                        project_id=str(project_id or ""), parameter=parameter,
                        group_key__ne=group_key,
                    ).delete()
                experience = _find_parameter_experience(project_id, parameter, group_key=group_key)
                if not experience.role or experience.role == "unknown":
                    experience.role = item.rule_role if item else "unknown"
                if batch_role:
                    experience.role = batch_role
                if batch_status:
                    experience.process_status = batch_status
                if batch_reuse:
                    experience.reuse_policy = batch_reuse
                if batch_chain:
                    experience.chain_policy = batch_chain
                if batch_business_meaning:
                    experience.business_meaning = batch_business_meaning
                if batch_note:
                    experience.manual_note = batch_note
                experience.reviewer = session.get("username") or ""
                experience.mtime = dt.datetime.utcnow()
                experience.save()
                saved_count += 1
            return redirect(url_for(
                "web.parameter_priority",
                project_id=project_id,
                q=redirect_filters["q"],
                importance=redirect_filters["importance"],
                usage=redirect_filters["usage"],
                role=redirect_filters["role"],
                readiness=redirect_filters["readiness"],
                relation=redirect_filters["relation"],
                experience_status=redirect_filters["experience_status"],
                sort=redirect_filters["sort"],
                page=request.form.get("page") or 0,
                limit=redirect_filters["limit"] or 50,
                saved=("merge {}".format(saved_count) if action == "merge_experience" else "batch {}".format(saved_count)),
            ))
        if action == "quick_feedback":
            parameter = request.form.get("parameter") or ""
            selected = _selected_parameters_from_form(request.form) or ([parameter] if parameter else [])
            if selected:
                review = parameter_priority_review.objects(project_id=project_id, parameter=parameter).first()
                if not review:
                    review = parameter_priority_review(project_id=project_id, parameter=parameter, ctime=dt.datetime.utcnow())
                review.manual_role = request.form.get("manual_role") or review.manual_role
                try:
                    review.manual_weight = float(request.form.get("manual_weight")) if request.form.get("manual_weight") not in [None, ""] else review.manual_weight
                except Exception:
                    pass
                review.manual_note = request.form.get("manual_note") or ""
                review.reviewer = session.get("username") or ""
                review.mtime = dt.datetime.utcnow()
                review.save()

                group_key = (request.form.get("group_key") or parameter).strip()
                for selected_parameter in selected:
                    parameter_experience.objects(
                        project_id=str(project_id or ""), parameter=selected_parameter,
                        group_key__ne=group_key,
                    ).delete()
                    experience = _find_parameter_experience(project_id, selected_parameter, group_key=group_key)
                    if request.form.get("process_status"):
                        experience.process_status = request.form.get("process_status")
                    if request.form.get("manual_role"):
                        experience.role = request.form.get("manual_role")
                    for form_key, field_name in (
                        ("scope_type", "scope_type"),
                        ("scope_value", "scope_value"),
                        ("business_meaning", "business_meaning"),
                        ("reuse_policy", "reuse_policy"),
                        ("chain_policy", "chain_policy"),
                        ("validation_policy", "validation_policy"),
                        ("manual_note", "manual_note"),
                    ):
                        if form_key in request.form:
                            setattr(experience, field_name, request.form.get(form_key) or "")
                    if request.form.get("confidence") not in (None, ""):
                        try:
                            experience.confidence = max(
                                0.0, min(1.0, float(request.form.get("confidence"))),
                            )
                        except (TypeError, ValueError):
                            pass
                    experience.reviewer = session.get("username") or ""
                    experience.mtime = dt.datetime.utcnow()
                    experience.save()
            return redirect(url_for(
                "web.parameter_priority",
                project_id=project_id,
                q=redirect_filters["q"] or parameter,
                importance=redirect_filters["importance"],
                usage=redirect_filters["usage"],
                role=redirect_filters["role"],
                readiness=redirect_filters["readiness"],
                relation=redirect_filters["relation"],
                experience_status=redirect_filters["experience_status"],
                sort=redirect_filters["sort"],
                page=request.form.get("page") or 0,
                limit=redirect_filters["limit"] or 50,
                saved="feedback",
            ))
        parameter = request.form.get("parameter") or ""
        if parameter:
            review = parameter_priority_review.objects(project_id=project_id, parameter=parameter).first()
            if not review:
                review = parameter_priority_review(project_id=project_id, parameter=parameter, ctime=dt.datetime.utcnow())
            review.manual_role = request.form.get("manual_role") or review.manual_role
            try:
                review.manual_weight = float(request.form.get("manual_weight")) if request.form.get("manual_weight") not in [None, ""] else review.manual_weight
            except Exception:
                pass
            review.manual_note = request.form.get("manual_note") or ""
            review.reviewer = session.get("username") or ""
            review.mtime = dt.datetime.utcnow()
            review.save()
        return redirect(url_for(
            "web.parameter_priority", project_id=project_id,
            q=redirect_filters["q"] or parameter, saved="1",
            importance=redirect_filters["importance"], usage=redirect_filters["usage"],
            role=redirect_filters["role"], readiness=redirect_filters["readiness"],
            relation=redirect_filters["relation"],
            experience_status=redirect_filters["experience_status"],
            sort=redirect_filters["sort"], limit=redirect_filters["limit"] or 50,
        ))

    project_id = _canonical_project_id(request.args.get("project_id") or "")
    q = request.args.get("q") or ""
    importance = request.args.get("importance") or ""
    usage = request.args.get("usage") or ""
    role = request.args.get("role") or ""
    readiness = request.args.get("readiness") or ""
    relation_filter = request.args.get("relation") or ""
    experience_status = request.args.get("experience_status") or ""
    sort = request.args.get("sort") or "combined"
    page = max(0, int(request.args.get("page") or 0))
    limit = max(1, min(int(request.args.get("limit") or 50), 200))
    projects = _available_projects()
    if not project_id and projects:
        project_id = projects[0]["id"]
    rows, filtered_count = _parameter_priority_rows(
        project_id=project_id, q=q, page=page, limit=limit,
        importance=importance, usage=usage, role=role, readiness=readiness,
        relation=relation_filter, experience_status=experience_status, sort=sort,
    )
    for row in rows:
        row["focused"] = bool(q and any(
            str(q).lower() == str(value).lower()
            for value in [row.get("parameter")] + list(row.get("aliases") or [])
            + list(row.get("raw_paths") or [])
        ))
    item_query = {"project_id": str(project_id or "")}
    total_items = parameter_priority_item.objects(**item_query).count()
    high_items = parameter_priority_item.objects(project_id=str(project_id or ""), rule_weight__gte=80).count()
    auth_items = parameter_priority_item.objects(project_id=str(project_id or ""), rule_role="auth_context").count()
    identity_items = parameter_priority_item.objects(project_id=str(project_id or ""), rule_role__in=["tenant_scope", "owner_identity"]).count()
    latest_item = parameter_priority_item.objects(project_id=str(project_id or "")).order_by("-mtime").first()
    experience_count = parameter_experience.objects(project_id=str(project_id or "")).count()
    review_count = parameter_priority_review.objects(project_id=str(project_id or "")).count()
    observed_items = parameter_priority_item.objects(
        project_id=str(project_id or ""), usage_count__gt=0,
    ).count()
    stats = {
        "parameters": total_items,
        "high": high_items,
        "auth": auth_items,
        "identity": identity_items,
        "reviewed": max(experience_count, review_count),
        "observed": observed_items,
        "latest_refresh": latest_item.mtime if latest_item else None,
    }
    return {
        "form": request.args,
        "projects": projects,
        "project_id": project_id,
        "rows": rows,
        "stats": stats,
        "role_options": PARAM_ROLE_OPTIONS,
        "status_options": PARAM_PROCESS_STATUSES,
        "reuse_options": PARAM_REUSE_OPTIONS,
        "chain_options": PARAM_CHAIN_OPTIONS,
        "validation_options": PARAM_VALIDATION_OPTIONS,
        "scope_options": PARAM_SCOPE_OPTIONS,
        "page": page,
        "limit": limit,
        "filtered_count": filtered_count,
        "range_start": page * limit + 1 if filtered_count else 0,
        "range_end": min((page + 1) * limit, filtered_count),
        "has_prev": page > 0,
        "has_next": (page + 1) * limit < filtered_count,
        "saved": request.args.get("saved") or "",
        "refreshed": request.args.get("refreshed") or "",
        "can_manage": is_manager(),
        "filters": {
            "importance": importance, "usage": usage, "role": role,
            "readiness": readiness, "relation": relation_filter,
            "experience_status": experience_status, "sort": sort,
        },
    }


@bp_web.route("/parameter-evidence", methods=["GET"])
@login_check
@templated("/_parameter-evidence.html")
def parameter_evidence():
    project_id = _canonical_project_id(request.args.get("project_id") or "")
    parameter = str(request.args.get("parameter") or "").strip()
    rows, _ = _parameter_priority_rows(
        project_id=project_id, q=parameter, page=0, limit=20,
    )
    row = next((item for item in rows if item.get("parameter") == parameter), rows[0] if rows else None)
    if not row:
        return {"row": None, "endpoints": []}
    names = tuple(sorted(set(
        list(row.get("parameters") or [])
        + list(row.get("aliases") or [])
        + list(row.get("raw_paths") or [])
        + list(row.get("canonical_keys") or [])
    )))
    endpoints = []
    seen_pathids = set()
    for sample_doc in row.get("sample_docs") or []:
        pathid = sample_doc.get("pathid")
        if not pathid or pathid in seen_pathids:
            continue
        seen_pathids.add(pathid)
        detail = endpoint_evidence_view(
            pathid, highlight_names=names, sample_limit=3,
        )
        if detail:
            endpoints.append(detail)
    return {"row": row, "endpoints": endpoints}


PARAM_PROCESS_STATUSES = [
    {"key": "needs_review", "label": "待确认含义"},
    {"key": "needs_split", "label": "待拆分/归并"},
    {"key": "needs_data", "label": "待补样本"},
    {"key": "needs_verify", "label": "待验证"},
    {"key": "conflict", "label": "验证冲突"},
    {"key": "trusted", "label": "已可信"},
    {"key": "reusable", "label": "可复用"},
    {"key": "rejected", "label": "已排除"},
]


def _parameter_validation_context(project_id, env_id="", source_profile_id="",
                                  consumer_profile_id="", source_host="",
                                  consumer_host=""):
    project_id = _canonical_project_id(project_id)
    environments = list(ProjectEnvironment.objects(
        project_id=project_id, active=True,
    ).order_by("env_id")) if project_id else []
    selected_environment = next(
        (item for item in environments if item.env_id == str(env_id or "")),
        environments[0] if environments else None,
    )
    env_id = selected_environment.env_id if selected_environment else ""
    profiles = list(ProjectAuthProfile.objects(
        project_id=project_id, env_id=env_id, active=True,
    ).order_by("-is_default", "name")) if env_id else []

    def selected(profile_id):
        explicit = next((item for item in profiles if item.profile_id == profile_id), None)
        if explicit:
            return explicit
        return next((item for item in profiles if item.is_default), profiles[0] if profiles else None)

    source_profile = selected(str(source_profile_id or ""))
    consumer_profile = selected(str(consumer_profile_id or ""))
    hosts = environment_host_names(selected_environment)
    default_host = normalize_host(
        selected_environment.default_host if selected_environment else "",
    ) or (hosts[0] if hosts else "")
    source_host = normalize_host(source_host) or default_host
    consumer_host = normalize_host(consumer_host) or default_host
    if hosts and source_host not in hosts:
        source_host = default_host
    if hosts and consumer_host not in hosts:
        consumer_host = default_host
    return {
        "environments": environments,
        "environment": selected_environment,
        "env_id": env_id,
        "profiles": profiles,
        "source_profile": source_profile,
        "consumer_profile": consumer_profile,
        "source_profile_id": source_profile.profile_id if source_profile else "",
        "consumer_profile_id": consumer_profile.profile_id if consumer_profile else "",
        "hosts": hosts,
        "source_host": source_host,
        "consumer_host": consumer_host,
        "ready": bool(selected_environment and source_profile and consumer_profile and hosts),
    }
