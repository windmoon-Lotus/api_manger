import time
import json
from pathlib import Path
from flask import request, make_response, redirect, url_for, session
from werkzeug.utils import secure_filename
from mongoengine.errors import NotUniqueError
from . import bp_web
from ..common.decorators import *
from ..common.func import is_manager
from ..conf.conf import *
from ..conf.data_paths import private_upload_dir
from ..db.collection import *
from ..tool.lifecycle_view import (
    data_source_view,
    import_run_view,
    routing_decision_view,
    source_binding_view,
)
from ..project_context import (
    ensure_source_binding,
)
from ..tool.data_source_routing import (
    assign_observation_project,
    deactivate_source_binding,
    ignore_observation,
)
from ..import_pipeline import ImportRequest, execute_import
from ._helpers import (
    _bounded_int,
    _lifecycle_csrf_token,
    _lifecycle_csrf_valid,
)


def _latest_routing_decisions_page(decision_filter, offset, size):
    match = None
    if decision_filter in {ObservationRoutingDecision.ASSIGNED,
                           ObservationRoutingDecision.AMBIGUOUS,
                           ObservationRoutingDecision.UNASSIGNED,
                           ObservationRoutingDecision.IGNORED}:
        match = {"decision": decision_filter}
    elif decision_filter != "all":
        match = {"decision": {"$in": [
            ObservationRoutingDecision.AMBIGUOUS,
            ObservationRoutingDecision.UNASSIGNED,
        ]}}
    row_pipeline = []
    if match:
        row_pipeline.append({"$match": match})
    row_pipeline.extend([
        {"$sort": {"ctime": -1, "_id": -1}},
        {"$skip": int(offset)},
        {"$limit": int(size)},
    ])
    count_pipeline = []
    if match:
        count_pipeline.append({"$match": match})
    count_pipeline.append({"$count": "count"})
    pipeline = [
        {"$sort": {"ctime": -1, "_id": -1}},
        {"$group": {"_id": "$observation_id", "doc": {"$first": "$$ROOT"}}},
        {"$replaceRoot": {"newRoot": "$doc"}},
        {"$facet": {
            "rows": row_pipeline,
            "filtered_total": count_pipeline,
            "status_counts": [
                {"$group": {"_id": "$decision", "count": {"$sum": 1}}},
            ],
        }},
    ]
    values = list(ObservationRoutingDecision._get_collection().aggregate(pipeline))
    value = values[0] if values else {}
    totals = value.get("filtered_total") or []
    status_counts = {
        str(item.get("_id") or ""): int(item.get("count") or 0)
        for item in value.get("status_counts") or []
    }
    return value.get("rows") or [], (totals[0].get("count", 0) if totals else 0), status_counts


def _data_source_return_url():
    values = {}
    for key in (
            "view", "source_type", "import_status", "routing_decision",
            "import_page", "route_page"):
        value = request.form.get("return_" + key)
        if value not in (None, ""):
            values[key] = value
    return url_for("web.data_source_center", **values)


def _set_data_source_notice(text, level="success", view=""):
    session["data_source_notice"] = {
        "text": str(text or "")[:500],
        "level": level if level in {"success", "warning", "error"} else "warning",
        "view": view if view in {"sources", "imports", "routing"} else "",
    }


def _source_run_summaries():
    rows = ImportRun._get_collection().aggregate([
        {"$match": {"data_source_id": {"$nin": ["", None]}}},
        {"$group": {
            "_id": "$data_source_id",
            "count": {"$sum": 1},
            "failed": {
                "$sum": {
                    "$cond": [{"$eq": ["$status", ImportRun.FAILED]}, 1, 0],
                },
            },
            "last_started_at": {"$max": "$started_at"},
        }},
    ])
    return {str(row.get("_id") or ""): row for row in rows}


def _source_observation_summaries():
    rows = RequestObservation._get_collection().aggregate([
        {"$match": {"data_source_id": {"$nin": ["", None]}}},
        {"$group": {
            "_id": "$data_source_id",
            "count": {"$sum": 1},
            "last_captured_at": {"$max": "$captured_at"},
        }},
    ])
    return {str(row.get("_id") or ""): row for row in rows}


def _open_routing_groups(source_names):
    pipeline = [
        {"$sort": {"ctime": -1, "_id": -1}},
        {"$group": {
            "_id": "$observation_id",
            "doc": {"$first": "$$ROOT"},
        }},
        {"$replaceRoot": {"newRoot": "$doc"}},
        {"$match": {"decision": {"$in": [
            ObservationRoutingDecision.UNASSIGNED,
            ObservationRoutingDecision.AMBIGUOUS,
        ]}}},
        {"$lookup": {
            "from": RequestObservation._get_collection_name(),
            "localField": "observation_id",
            "foreignField": "observation_id",
            "as": "observation",
        }},
        {"$unwind": "$observation"},
        {"$group": {
            "_id": {
                "data_source_id": "$observation.data_source_id",
                "domain": "$observation.domain",
            },
            "count": {"$sum": 1},
            "methods": {"$addToSet": "$observation.method"},
            "oldest_at": {"$min": "$observation.captured_at"},
            "newest_at": {"$max": "$observation.captured_at"},
        }},
        {"$sort": {"count": -1, "_id.domain": 1}},
        {"$limit": 100},
    ]
    rows = []
    for item in ObservationRoutingDecision._get_collection().aggregate(
            pipeline):
        identity = item.get("_id") or {}
        data_source_id = str(identity.get("data_source_id") or "")
        domain = str(identity.get("domain") or "")
        rows.append({
            "data_source_id": data_source_id,
            "source_name": source_names.get(data_source_id, ""),
            "domain": domain,
            "count": int(item.get("count") or 0),
            "methods": sorted(
                str(value) for value in item.get("methods") or [] if value
            ),
            "oldest_at": str(item.get("oldest_at") or ""),
            "newest_at": str(item.get("newest_at") or ""),
            "batch_safe": bool(data_source_id and domain),
        })
    return rows


def _open_group_decisions(data_source_id, domain, maximum=500):
    observations = list(
        RequestObservation.objects(
            data_source_id=str(data_source_id or ""),
            domain=str(domain or ""),
        ).only("observation_id")
    )
    if len(observations) > maximum:
        raise ValueError(
            "group contains more than {} observations".format(maximum),
        )
    rows = []
    for observation in observations:
        latest = ObservationRoutingDecision.objects(
            observation_id=observation.observation_id,
        ).order_by("-ctime", "-id").first()
        if latest and latest.decision in {
            ObservationRoutingDecision.UNASSIGNED,
            ObservationRoutingDecision.AMBIGUOUS,
        }:
            rows.append(latest)
    return rows


def _project_environment_options(projects):
    project_ids = [item.project_id for item in projects]
    environments = list(
        ProjectEnvironment.objects(
            project_id__in=project_ids,
            active=True,
        ).order_by("project_id", "name", "env_id")
    )
    grouped = {}
    for environment in environments:
        grouped.setdefault(environment.project_id, []).append(environment)
    options = []
    for project in projects:
        project_envs = grouped.get(project.project_id) or []
        if not project_envs:
            options.append({
                "value": "{}|".format(project.project_id),
                "project_id": project.project_id,
                "project_name": project.name,
                "env_id": "",
                "env_name": "未指定环境",
            })
            continue
        for environment in project_envs:
            options.append({
                "value": "{}|{}".format(
                    project.project_id, environment.env_id,
                ),
                "project_id": project.project_id,
                "project_name": project.name,
                "env_id": environment.env_id,
                "env_name": environment.name or environment.env_id,
            })
    return options


def _parse_project_environment(value):
    project_id, separator, env_id = str(value or "").partition("|")
    if not separator:
        project_id = str(value or "")
        env_id = ""
    return project_id.strip(), env_id.strip()


def _execute_data_source_import(form):
    fmt = str(form.get("format") or "").strip().lower()
    if fmt not in {"har", "openapi", "postman"}:
        raise ValueError("请选择 HAR、OpenAPI 或 Postman 格式")
    source_file = request.files.get("source_file")
    if not source_file or not source_file.filename:
        raise ValueError("请选择需要导入的文件")
    safe_name = secure_filename(source_file.filename)
    if not safe_name:
        safe_name = "import-{}.json".format(int(time.time()))
    project_id, env_id = _parse_project_environment(form.get("project_environment"))
    if fmt in {"openapi", "postman"} and not project_id:
        raise ValueError("OpenAPI 和 Postman 必须选择项目与环境")

    saved_path = private_upload_dir(create=True) / "{}_{}".format(int(time.time()), safe_name)
    source_file.save(str(saved_path))
    source_name = str(form.get("source_name") or "").strip() or Path(safe_name).stem
    outcome = execute_import(ImportRequest(
        source_type=fmt,
        source_path=str(saved_path),
        project_id=project_id,
        env_id=env_id,
        source_id=str(form.get("source_key") or "").strip() or source_name,
        source_name=source_name,
        base_url=str(form.get("base_url") or "").strip(),
        run_parameters=form.get("run_parameters") == "1",
    ))
    return outcome.run, outcome.summary


@bp_web.route("/data-sources", methods=["GET", "POST"])
@login_check
@templated("/data-sources.html")
def data_source_center():
    if request.method == "POST":
        target = _data_source_return_url()
        if not is_manager():
            return make_response("Forbidden", 403)
        if not _lifecycle_csrf_valid(request.form.get("csrf_token")):
            _set_data_source_notice(
                "操作未执行：页面令牌无效，请刷新后重试。",
                "error",
            )
            return redirect(target)
        action = str(request.form.get("action") or "")
        try:
            if action == "import_source":
                run, summary = _execute_data_source_import(request.form)
                _set_data_source_notice(
                    "导入完成：{} 个项目资产，{} 条待路由/已路由观察；未发送任何业务请求。".format(
                        int(summary.get("asset_count") or 0),
                        int(summary.get("observation_count") or 0),
                    ),
                    "success",
                    "imports",
                )
                target = url_for(
                    "web.data_source_center",
                    view="imports",
                    import_run_id=run.import_run_id,
                )
            elif action == "bind_source":
                project_id, env_id = _parse_project_environment(
                    request.form.get("project_environment"),
                )
                ensure_source_binding(
                    str(request.form.get("data_source_id") or ""),
                    project_id,
                    env_id=env_id,
                )
                _set_data_source_notice(
                    "来源绑定已保存；后续导入与流量可以使用该项目边界。",
                    "success",
                    "sources",
                )
            elif action == "deactivate_source_binding":
                deactivate_source_binding(
                    str(request.form.get("binding_id") or ""),
                    expected_data_source_id=str(
                        request.form.get("data_source_id") or "",
                    ),
                    manual_by=session.get("username") or "",
                )
                _set_data_source_notice(
                    "来源绑定已停用；历史导入与路由证据仍然保留。",
                    "success",
                    "sources",
                )
            elif action == "assign_routing_group":
                data_source_id = str(
                    request.form.get("data_source_id") or "",
                )
                domain = str(request.form.get("domain") or "")[:255]
                if not data_source_id or not domain:
                    raise ValueError(
                        "批量归属要求同一数据源与明确 Host",
                    )
                project_id, env_id = _parse_project_environment(
                    request.form.get("project_environment"),
                )
                decisions = _open_group_decisions(
                    data_source_id,
                    domain,
                )
                if not decisions:
                    raise ValueError(
                        "该分组已没有待处理观察",
                    )
                expected_count = _bounded_int(
                    request.form.get("expected_count"),
                    -1,
                    -1,
                    500,
                )
                if expected_count != len(decisions):
                    raise ValueError(
                        "待处理数量已变化，请刷新后重新确认",
                    )
                for decision in decisions:
                    assign_observation_project(
                        decision.observation_id,
                        project_id,
                        env_id=env_id,
                        expected_decision_id=str(decision.id),
                        manual_by=session.get("username") or "",
                        teach_future=(
                            request.form.get("teach_future") == "1"
                        ),
                    )
                _set_data_source_notice(
                    "批量路由完成：同一来源与 Host 的 {} 条观察已归属；未发送业务请求。".format(
                        len(decisions),
                    ),
                    "success",
                    "routing",
                )
            elif action == "assign_observation":
                project_id, env_id = _parse_project_environment(
                    request.form.get("project_environment"),
                )
                _, summary = assign_observation_project(
                    str(request.form.get("observation_id") or ""),
                    project_id,
                    env_id=env_id,
                    expected_decision_id=str(
                        request.form.get("expected_decision_id") or "",
                    ),
                    manual_by=session.get("username") or "",
                    teach_future=request.form.get("teach_future") == "1",
                    override_final=(
                        request.form.get("override_final") == "1"
                    ),
                )
                detail = (
                    "并已补齐现有样本归属"
                    if summary.get("sample_promoted")
                    else "历史观察仅保存结构；后续同接口流量会形成真实样本"
                )
                _set_data_source_notice(
                    "路由确认完成，{}。".format(detail),
                    "success",
                    "routing",
                )
            elif action == "ignore_observation":
                ignore_observation(
                    str(request.form.get("observation_id") or ""),
                    expected_decision_id=str(
                        request.form.get("expected_decision_id") or "",
                    ),
                    manual_by=session.get("username") or "",
                    reason=str(
                        request.form.get("ignore_reason")
                        or "manual_non_business_traffic"
                    ),
                    override_final=(
                        request.form.get("override_final") == "1"
                    ),
                )
                _set_data_source_notice(
                    "该观察已标记为非业务流量，不会进入项目接口知识。",
                    "success",
                    "routing",
                )
            else:
                raise ValueError("unsupported data-source action")
        except (ValueError, TypeError, NotUniqueError) as exc:
            _set_data_source_notice(
                "操作未执行：{}".format(str(exc)[:320]),
                "warning",
            )
        except Exception:
            logger.exception("data source center action failed")
            _set_data_source_notice(
                "操作失败：导入内容或本地数据状态异常，请查看失败批次。",
                "error",
            )
        return redirect(target)

    notice = session.pop("data_source_notice", None)
    requested_view = str(
        request.args.get("view")
        or (notice or {}).get("view")
        or "sources"
    )
    if requested_view not in {"sources", "imports", "routing"}:
        requested_view = "sources"
    source_type_filter = str(request.args.get("source_type") or "")
    import_status = str(request.args.get("import_status") or "")
    if import_status not in {"", ImportRun.RUNNING, ImportRun.DONE, ImportRun.FAILED}:
        import_status = ""
    routing_filter = str(request.args.get("routing_decision") or "open")
    valid_routing_filters = {
        "open", "all",
        ObservationRoutingDecision.ASSIGNED,
        ObservationRoutingDecision.AMBIGUOUS,
        ObservationRoutingDecision.UNASSIGNED,
        ObservationRoutingDecision.IGNORED,
    }
    if routing_filter not in valid_routing_filters:
        routing_filter = "open"
    import_page = _bounded_int(
        request.args.get("import_page"), 0, 0, 100000,
    )
    route_page = _bounded_int(
        request.args.get("route_page"), 0, 0, 100000,
    )
    import_size = 30
    route_size = 20

    projects = list(
        ApiProject.objects(status=ApiProject.ACTIVE).order_by("name")
    )
    project_names = {item.project_id: item.name for item in projects}
    environment_options = _project_environment_options(projects)

    source_query = DataSource.objects(lifecycle=DataSource.ACTIVE)
    if source_type_filter:
        source_query = source_query.filter(source_type=source_type_filter)
    sources = list(source_query.order_by("-mtime", "name")[:300])
    source_ids = [item.data_source_id for item in sources]
    source_names = {
        item.data_source_id: item.name for item in sources
    }
    all_source_names = {
        item.data_source_id: item.name
        for item in DataSource.objects.only("data_source_id", "name")
    }
    binding_groups = {}
    for binding in ProjectSourceBinding.objects(
            data_source_id__in=source_ids, active=True):
        binding_groups.setdefault(binding.data_source_id, []).append(
            source_binding_view(
                binding,
                project_names.get(binding.project_id, ""),
            )
        )
    run_summaries = _source_run_summaries()
    observation_summaries = _source_observation_summaries()
    source_rows = [
        data_source_view(
            source,
            binding_groups.get(source.data_source_id, []),
            run_summaries.get(source.data_source_id, {}),
            observation_summaries.get(source.data_source_id, {}),
        )
        for source in sources
    ]

    import_query = ImportRun.objects()
    if source_type_filter:
        import_query = import_query.filter(source_type=source_type_filter)
    if import_status:
        import_query = import_query.filter(status=import_status)
    import_count = import_query.count()
    import_rows = [
        import_run_view(
            item,
            all_source_names.get(item.data_source_id, ""),
            project_names,
        )
        for item in import_query.order_by("-started_at")[
            import_page * import_size:(import_page + 1) * import_size
        ]
    ]

    routing_rows, routing_count, routing_status_counts = (
        _latest_routing_decisions_page(
            routing_filter,
            route_page * route_size,
            route_size,
        )
    )
    observation_ids = [
        str(item.get("observation_id") or "") for item in routing_rows
    ]
    observations = {
        item.observation_id: item
        for item in RequestObservation.objects(
            observation_id__in=observation_ids,
        )
    }
    routing = []
    for item in routing_rows:
        observation = observations.get(
            str(item.get("observation_id") or ""),
        )
        view = routing_decision_view(
            item, observation, project_names,
        )
        view["source_name"] = all_source_names.get(
            view.get("data_source_id"), "",
        )
        routing.append(view)
    routing_groups = _open_routing_groups(all_source_names)

    stats = {
        "source_count": DataSource.objects(
            lifecycle=DataSource.ACTIVE,
        ).count(),
        "import_count": ImportRun.objects.count(),
        "pending_routing_count": (
            int(routing_status_counts.get(
                ObservationRoutingDecision.UNASSIGNED, 0,
            ))
            + int(routing_status_counts.get(
                ObservationRoutingDecision.AMBIGUOUS, 0,
            ))
        ),
        "assigned_count": int(routing_status_counts.get(
            ObservationRoutingDecision.ASSIGNED, 0,
        )),
        "legacy_unscoped_asset_count": raw_data.objects(
            project_id__in=["", None],
        ).count(),
        "legacy_unscoped_sample_count": request_sample.objects(
            project_id__in=["", None],
        ).count(),
    }
    return {
        "view": requested_view,
        "notice": notice,
        "can_manage": is_manager(),
        "csrf_token": _lifecycle_csrf_token(),
        "stats": stats,
        "source_rows": source_rows,
        "source_type_filter": source_type_filter,
        "source_types": sorted({
            item for item in DataSource.objects.distinct("source_type") if item
        } | {"har", "openapi", "postman", "apifox", "workspace"}),
        "import_rows": import_rows,
        "import_count": import_count,
        "import_status": import_status,
        "import_page": import_page,
        "import_size": import_size,
        "routing": routing,
        "routing_groups": routing_groups,
        "routing_count": routing_count,
        "routing_filter": routing_filter,
        "routing_status_counts": routing_status_counts,
        "route_page": route_page,
        "route_size": route_size,
        "projects": projects,
        "environment_options": environment_options,
    }
