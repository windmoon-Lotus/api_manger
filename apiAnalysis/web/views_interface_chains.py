import json
import datetime as dt
from flask import request, make_response, redirect, url_for, session
from . import bp_web
from ..common.decorators import *
from ..common.func import is_manager
from ..db.collection import *
from ..tool.interface_knowledge import project_chain_candidates
from ._helpers import (
    _bounded_int,
    _lifecycle_csrf_token,
    _lifecycle_csrf_valid,
    _canonical_project_id,
    _available_projects,
)


def _chain_feedback_blocker_class(reasons, status):
    text = " ".join(str(item or "") for item in (reasons or [])).lower()
    if status == "runnable":
        return "validated_runnable"
    if "token_verify_fail" in text or "authorization_required" in text:
        return "auth_context"
    if "api_not_implemented" in text or "route_not_found" in text or "http_404" in text:
        return "route_or_host"
    if "empty_body" in text or "not_found" in text or "no_business_data" in text:
        return "business_data"
    if "invalid" in text or "params_error" in text or "type mismatch" in text or "parameter" in text:
        return "body_or_params"
    if "http_5" in text:
        return "server_or_host"
    return "other"


def _chain_strategy_label(strategy):
    labels = {
        "list_detail_update_restore": "列表 -> 详情 -> 更新/恢复",
        "create_detail_update_delete": "创建 -> 详情 -> 更新/删除",
        "list_detail_readonly": "列表 -> 详情只读",
    }
    return labels.get(strategy or "", strategy or "未识别链路")


def _chain_action_label(action):
    labels = {
        "list": "列表",
        "detail": "详情",
        "create": "创建",
        "update": "更新",
        "delete": "删除",
        "submit": "提交",
        "task_list": "任务列表",
        "task_detail": "任务详情",
        "task_create": "任务创建",
        "task_update": "任务更新",
        "task_action": "任务动作",
        "auth_action": "认证动作",
        "readonly_action_alias": "只读动作",
    }
    return labels.get(action or "", action or "接口")


def _chain_function_label(chain):
    resource = chain.get("resource") or chain.get("family") or "资源"
    strategy = chain.get("strategy") or chain.get("fixture_strategy") or ""
    action_names = [_chain_action_label(action) for action in chain.get("actions") or []]
    if action_names:
        return "{}：{}，覆盖 {}".format(resource, _chain_strategy_label(strategy), " / ".join(action_names))
    return "{}：{}".format(resource, _chain_strategy_label(strategy))


def _chain_reason_lines(chain, validation, blocker):
    lines = []
    if validation.get("status") == "runnable":
        lines.append("自动复验已返回 2xx，可以作为可运行链路候选。")
    elif blocker == "auth_context":
        lines.append("复验主要卡在认证上下文，需补 token/cookie/account 上下文后再判断链路质量。")
    elif blocker == "route_or_host":
        lines.append("复验命中 404 或 host/route 问题，需先确认接口域名、环境或路径是否正确。")
    elif blocker == "business_data":
        lines.append("复验缺业务样本或响应体证据，需人工补充可用业务数据。")
    elif blocker == "body_or_params":
        lines.append("复验提示参数类型、路径参数或 body 构造问题，优先回到参数经验页修正。")
    elif blocker == "server_or_host":
        lines.append("复验出现 5xx 或服务侧异常，建议延后或更换环境复测。")
    else:
        lines.append("自动化证据不足，需要人工复核接口含义和参数来源。")

    link_count = len(chain.get("links") or [])
    if link_count:
        lines.append("发现 {} 条参数/ID 传递关系，可用于串联接口。".format(link_count))
    else:
        lines.append("没有发现明确的参数/ID 传递关系，容易产生无效串联。")

    primary = chain.get("primary") or {}
    if primary:
        lines.append("主链接口包含：{}。".format("、".join("{}({})".format(_chain_action_label(k), v.get("pathid")) for k, v in primary.items())))

    host_counts = chain.get("host_context_counts") or {}
    if host_counts:
        lines.append("host 探活分布：{}。".format(", ".join("{}={}".format(k, v) for k, v in host_counts.items())))

    for reason in validation.get("reasons") or []:
        lines.append("复验原因：{}".format(reason))
    return lines


def _chain_task_bucket(chain, validation, blocker, feedback, shared_primary):
    if feedback and feedback.decision:
        if feedback.decision == "trusted":
            return "archived", "已归档", "已归档为可信经验，后续自动化可直接复用。"
        if feedback.decision == "ignore":
            return "ignored", "已忽略", "人工已判定为误判或不处理，默认不进入后续复验。"
        if feedback.decision == "stale":
            return "stale", "待纠偏", "人工标记经验可能过期，需要重新复验或修正。"
        return feedback.decision, "已反馈", "已有人工作出判断，等待自动化复验闭环。"
    if validation.get("status") == "runnable":
        return "ready_archive", "可归档", "自动复验可跑，建议人工确认业务含义后归档。"
    if shared_primary:
        return "dedupe_review", "共用接口复用", "这条链含共用接口，基础可达性/认证/host 结果应复用，避免重复测试。"
    if blocker == "auth_context":
        return "needs_auth", "补认证上下文", "先补 token/cookie/account，再复验链路。"
    if blocker == "business_data":
        return "needs_data", "补业务数据", "先补可用业务样本，再判断链路是否真实可达。"
    if blocker == "body_or_params":
        return "needs_params", "修参数经验", "先到参数经验页修正路径参数、body 或字段映射。"
    if blocker == "route_or_host":
        return "needs_route", "查 host/路由", "先确认接口域名、环境和路径是否匹配。"
    if blocker == "server_or_host":
        return "retry_later", "延后复验", "服务异常或 host 不稳定，建议更换环境或延后复测。"
    return "manual_review", "人工复核", "自动化证据不足，需要人工判断链路是否有价值。"


def _chain_endpoint_view(endpoint, endpoint_usage=None):
    endpoint = endpoint or {}
    host_context = endpoint.get("host_context") or {}
    key = "{} {}".format(endpoint.get("method") or "", endpoint.get("path") or "")
    usage = endpoint_usage.get(key) if endpoint_usage else None
    hosts = []
    if host_context.get("host"):
        hosts.append(host_context.get("host"))
    return {
        "pathid": endpoint.get("pathid"),
        "method": endpoint.get("method") or "",
        "path": endpoint.get("path") or "",
        "name": (endpoint.get("name") or "").strip(),
        "role": _chain_action_label(endpoint.get("action")),
        "hosts": hosts,
        "shared": bool(usage and len(usage.get("families") or []) > 1),
    }


def _chain_endpoint_views(chain, endpoint_usage):
    primary = []
    for endpoint in (chain.get("primary") or {}).values():
        primary.append(_chain_endpoint_view(endpoint, endpoint_usage))

    seen = {item.get("pathid") for item in primary if item.get("pathid") is not None}
    all_items = list(primary)
    for endpoint in chain.get("endpoints") or []:
        pathid = endpoint.get("pathid")
        if pathid in seen:
            continue
        seen.add(pathid)
        all_items.append(_chain_endpoint_view(endpoint, endpoint_usage))
    return primary, all_items


def _chain_decision_label(feedback):
    if not feedback or not feedback.decision:
        return "待人工判断"
    labels = {
        "trusted": "已归档可信",
        "blocked": "已阻断",
        "needs_data": "待补数据",
        "ignore": "已忽略",
        "stale": "待纠偏",
    }
    return labels.get(feedback.decision, feedback.decision)


def _chain_next_action_level(task_bucket):
    if task_bucket in ("ready_archive", "archived"):
        return "good"
    if task_bucket in ("blocked", "ignore"):
        return "bad"
    return "warn"


def _empty_chain_queue_counts():
    keys = [
        "ready_archive",
        "needs_auth",
        "needs_data",
        "needs_params",
        "needs_route",
        "dedupe_review",
        "manual_review",
        "archived",
        "stale",
        "ignored",
        "retry_later",
    ]
    return {key: 0 for key in keys}


def _relation_reason_text(row):
    return " ".join(str(item or "") for item in (row.reason_codes or []))


def _endpoint_context(pathid):
    if pathid is None:
        return {}
    endpoint = raw_data.objects(ptah_id=pathid).first()
    if not endpoint:
        return {"pathid": pathid}
    meta = endpoint.source_meta or {}
    return {
        "pathid": endpoint.ptah_id,
        "method": endpoint.method,
        "path": endpoint.path,
        "url": endpoint.url,
        "domain": endpoint.domain,
        "description": endpoint.des,
        "source": endpoint.source,
        "apifox_endpoint_id": meta.get("apifox_endpoint_id"),
        "apifox_server_id": meta.get("apifox_server_id"),
        "apifox_name": meta.get("name"),
        "apifox_status": meta.get("status"),
    }


def _param_doc_row(param_doc, role):
    endpoint = param_doc.raw_data
    meta = endpoint.source_meta or {} if endpoint else {}
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
    }


def _parameter_context(row):
    parameter = row.parameter
    consumer = _endpoint_context(row.req_pathid)
    provider = _endpoint_context(row.res_pathid)
    req_docs = [_param_doc_row(item, "request") for item in req_data.objects(parameter=parameter)[:30]]
    res_docs = [_param_doc_row(item, "response") for item in res_data.objects(parameter=parameter)[:30]]
    related_pathids = {row.req_pathid, row.res_pathid}
    related_relations = []
    for rel in parameter_relation.objects(parameter=parameter)[:30]:
        related_pathids.add(rel.req_pathid)
        related_pathids.add(rel.res_pathid)
        related_relations.append({
            "req_pathid": rel.req_pathid,
            "res_pathid": rel.res_pathid,
            "relation": rel.relation,
            "verified": rel.verified,
            "reason_codes": rel.reason_codes or [],
        })
    for doc in req_docs + res_docs:
        if doc.get("pathid") is not None:
            related_pathids.add(doc.get("pathid"))
    endpoints = []
    host_candidates = {}
    for pathid in sorted(pid for pid in related_pathids if pid is not None):
        ctx = _endpoint_context(pathid)
        if not ctx:
            continue
        endpoints.append(ctx)
        host_key = ctx.get("domain") or ctx.get("apifox_server_id") or ""
        if host_key:
            host_candidates.setdefault(host_key, {
                "domain": ctx.get("domain"),
                "server_id": ctx.get("apifox_server_id"),
                "pathids": [],
            })["pathids"].append(pathid)
    return {
        "consumer": consumer,
        "provider": provider,
        "req_docs": req_docs,
        "res_docs": res_docs,
        "related_relations": related_relations,
        "related_endpoints": endpoints,
        "host_candidates": list(host_candidates.values()),
        "has_doc": bool(req_docs or res_docs),
    }


def _relation_task_bucket(row):
    if row.manual_decision == "trusted":
        return "trusted", "可信复用", "已归档为可信参数经验，可进入链路构造。"
    if row.manual_decision == "rejected":
        return "rejected", "已驳回", "人工已判定为误判，不应继续复用。"
    if row.manual_decision == "stale":
        return "stale", "待纠偏", "经验可能过期，需要重新验证。"
    if row.feedback_status == "conflict":
        return "conflict", "复验冲突", "自动复验与人工经验冲突，需要优先处理。"

    text = _relation_reason_text(row)
    if "UPSTREAM_HTTP_404" in text:
        return "needs_route", "查路由/host", "上游接口 404，先确认接口路径、环境或候选 host；多个 host 需要逐个验证后再定性。"
    if "UPSTREAM_BUSINESS_ERROR" in text:
        return "needs_data", "补业务数据", "上游业务失败，先补可用业务样本。"
    if "UPSTREAM_STATUS_204" in text:
        return "needs_evidence", "缺响应证据", "上游无响应体，缺少可提取参数的证据。"
    if not row.verified:
        return "needs_verify", "待复验", "尚未验证，确认前不要直接进入稳定经验。"
    return "ready_archive", "可归档", "已验证，建议人工确认业务语义后归档。"


def _empty_relation_queue_counts():
    keys = [
        "ready_archive",
        "needs_verify",
        "needs_data",
        "needs_evidence",
        "needs_route",
        "conflict",
        "trusted",
        "rejected",
        "stale",
    ]
    return {key: 0 for key in keys}


def _chain_endpoint_usage(chains):
    usage = {}
    for chain in chains:
        family = chain.get("family") or ""
        endpoints = {}
        for endpoint in chain.get("endpoints") or []:
            endpoints[endpoint.get("pathid")] = endpoint
        for endpoint in (chain.get("primary") or {}).values():
            endpoints[endpoint.get("pathid")] = endpoint
        for pathid, endpoint in endpoints.items():
            method = endpoint.get("method") or ""
            path = endpoint.get("path") or ""
            if not method and not path:
                continue
            key = "{} {}".format(method, path)
            item = usage.setdefault(key, {
                "key": key,
                "pathid": pathid,
                "method": method,
                "path": path,
                "name": endpoint.get("name"),
                "pathids": set(),
                "families": set(),
                "actions": set(),
            })
            if pathid is not None:
                item["pathids"].add(pathid)
            item["families"].add(family)
            if endpoint.get("action"):
                item["actions"].add(endpoint.get("action"))
    shared = []
    for item in usage.values():
        if len(item["families"]) > 1:
            item["pathids"] = sorted(item["pathids"])
            item["pathid"] = item["pathids"][0] if item["pathids"] else item.get("pathid")
            item["families"] = sorted(item["families"])
            item["actions"] = sorted(item["actions"])
            item["family_count"] = len(item["families"])
            item["endpoint"] = item["key"]
            item["count"] = item["family_count"]
            shared.append(item)
    shared.sort(key=lambda item: (-item["family_count"], item["method"], item["path"]))
    return usage, shared


@bp_web.route("/interface-chains", methods=['GET', 'POST'])
@login_check
@templated("/interface-chains.html")
def interface_chains():
    projects = _available_projects()
    project_id = _canonical_project_id(request.values.get("project_id") or "")
    if not project_id and projects:
        project_id = projects[0]["id"]
    live = project_chain_candidates(project_id)
    all_rows = list(live.get("rows") or [])
    source_version = "live-project-v2"

    if request.method == 'POST':
        form = request.form
        chain_key = str(form.get("chain_key") or "")
        valid_keys = {item["key"] for item in all_rows}
        saved = "0"
        if not is_manager():
            return make_response("Forbidden", 403)
        if not _lifecycle_csrf_valid(form.get("csrf_token")):
            saved = "csrf"
        elif chain_key in valid_keys:
            feedback = interface_chain_feedback.objects(
                project_id=project_id, env_id="", family=chain_key,
            ).first()
            if not feedback:
                feedback = interface_chain_feedback(
                    project_id=project_id, env_id="", family=chain_key,
                    ctime=dt.datetime.utcnow(),
                )
            feedback.strategy = str(form.get("strategy") or feedback.strategy or "")
            feedback.evidence_tier = str(form.get("origin") or feedback.evidence_tier or "")
            feedback.decision = str(form.get("decision") or feedback.decision or "")
            feedback.blocker_class = str(form.get("blocker_class") or feedback.blocker_class or "")
            try:
                feedback.confidence = max(0.0, min(1.0, float(form.get("confidence"))))
            except (TypeError, ValueError):
                feedback.confidence = None
            feedback.note = str(form.get("note") or "")[:500]
            feedback.missing_data = str(form.get("missing_data") or "")[:500]
            feedback.source_file = source_version
            feedback.manual_by = session.get("username") or ""
            feedback.mtime = dt.datetime.utcnow()
            feedback.save()
            saved = "1"
        return redirect(url_for(
            "web.interface_chains", project_id=project_id,
            q=form.get("q") or "", origin=form.get("filter_origin") or "",
            readiness=form.get("filter_readiness") or "",
            decision=form.get("filter_decision") or "", sort=form.get("sort") or "confidence",
            page=form.get("page") or 0, limit=form.get("limit") or 20,
            saved=saved,
        ))

    feedback_query = interface_chain_feedback.objects(project_id=project_id, env_id="")
    feedback_by_key = {row.family: row for row in feedback_query}
    q = str(request.args.get("q") or "").strip().lower()
    origin = str(request.args.get("origin") or "")
    readiness = str(request.args.get("readiness") or "")
    decision = str(request.args.get("decision") or "")
    sort = str(request.args.get("sort") or "confidence")
    page = _bounded_int(request.args.get("page"), 0, 0, 100000)
    limit = _bounded_int(request.args.get("limit"), 20, 1, 100)
    rows = []
    for row in all_rows:
        item = dict(row)
        feedback = feedback_by_key.get(item["key"])
        item["feedback"] = feedback
        item["manual_decision"] = feedback.decision if feedback else ""
        item["display_confidence"] = round(
            float(feedback.confidence) * 100, 1,
        ) if feedback and feedback.confidence is not None else item["confidence"]
        if q and q not in json.dumps(item, ensure_ascii=False, default=str).lower():
            continue
        if origin and item["origin"] != origin:
            continue
        if readiness and item["readiness"] != readiness:
            continue
        if decision and item["manual_decision"] != decision:
            continue
        rows.append(item)
    if sort == "traffic":
        rows.sort(key=lambda item: (-int(item["traffic_hits"] or 0), -float(item["display_confidence"] or 0), item["family"]))
    elif sort == "name":
        rows.sort(key=lambda item: item["family"])
    elif sort == "endpoints":
        rows.sort(key=lambda item: (-int(item["endpoint_count"] or 0), -float(item["display_confidence"] or 0), item["family"]))
    else:
        rows.sort(key=lambda item: (-float(item["display_confidence"] or 0), item["family"]))
    filtered_count = len(rows)
    rows = rows[page * limit:(page + 1) * limit]

    stats = dict(live.get("stats") or {})
    stats.update({
        "shown": len(rows),
        "filtered": filtered_count,
        "feedback": feedback_query.count(),
        "trusted": feedback_query.filter(decision="trusted").count(),
        "needs_data": feedback_query.filter(decision="needs_data").count(),
    })
    decision_options = [
        ("trusted", "归档可信"), ("needs_data", "待补数据"),
        ("blocked", "不应成链"), ("stale", "结构已过期"), ("ignore", "忽略候选"),
    ]
    blocker_options = [
        ("", "无阻塞"), ("auth_context", "缺认证上下文"),
        ("route_or_host", "缺 Host / 路由"), ("business_data", "缺业务数据"),
        ("body_or_params", "参数 / 请求体问题"), ("relation", "字段关系未验证"),
        ("other", "其他"),
    ]
    return {
        "form": request.args,
        "projects": projects,
        "project_id": project_id,
        "rows": rows,
        "stats": stats,
        "filters": {
            "q": q, "origin": origin, "readiness": readiness,
            "decision": decision, "sort": sort,
        },
        "page": page,
        "limit": limit,
        "filtered_count": filtered_count,
        "has_prev": page > 0,
        "has_next": (page + 1) * limit < filtered_count,
        "decision_options": decision_options,
        "blocker_options": blocker_options,
        "readiness_labels": {
            "verified": "关系已验证", "relation_ready": "关系可执行",
            "document_ready": "文档已成链", "traffic_review": "流量待归组",
            "needs_relation": "缺字段关系",
        },
        "action_labels": {
            "list": "列表", "create": "创建", "detail": "详情",
            "update": "更新", "delete": "删除", "submit": "提交", "other": "其他",
        },
        "saved": request.args.get("saved") or "",
        "csrf_token": _lifecycle_csrf_token(),
        "can_manage": is_manager(),
    }
