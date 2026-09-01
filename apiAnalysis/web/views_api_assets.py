"""Interface inventory UI.

Replay actions only enqueue immutable snapshots.  The Web process never sends
target requests and never turns a status mismatch directly into a finding.
"""
from flask import request, session

from . import bp_web
from ..common.decorators import login_check, templated
from ..common.util import get_page
from ..db.collection import raw_data
from ..tool.execution_contract import ExecutionContext, create_execution_snapshot
from ..tool.execution_scheduler import ExecutionPolicy, enqueue_snapshot_batch


SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


def _queue_selected_replays(rows, form):
    grouped = {}
    skipped = []
    for row in rows:
        project_id = str(row.project_id or "")
        env_id = str(row.env_id or "")
        method = str(row.method or "").upper()
        if not project_id:
            skipped.append("{}:missing_project".format(row.ptah_id))
            continue
        if method not in SAFE_METHODS:
            skipped.append("{}:mutation_requires_plan".format(row.ptah_id))
            continue
        grouped.setdefault((project_id, env_id), []).append(row)

    run_ids = []
    queued_cases = 0
    for (project_id, env_id), grouped_rows in grouped.items():
        context = ExecutionContext(
            project_id=project_id,
            env_id=env_id,
            auth_mode="anonymous",
            adapter_id="snapshot_batch",
            adapter_version="1",
        )
        snapshots = []
        for row in grouped_rows:
            snapshot = create_execution_snapshot(
                row.ptah_id,
                context,
                source="interface_manager_queue",
            )
            if snapshot:
                snapshots.append(snapshot)
            else:
                skipped.append("{}:snapshot_unavailable".format(row.ptah_id))
        if not snapshots:
            continue
        run, _created = enqueue_snapshot_batch(
            name="interface replay {}".format(project_id),
            check_type="baseline_replay",
            context=context,
            snapshot_ids=[item.id for item in snapshots],
            policy=ExecutionPolicy(),
            scope={
                "source": "interface_manager",
                "note": str(form.get("replay_note") or "").strip(),
            },
            operator=str(session.get("username") or ""),
        )
        run_ids.append(str(run.id))
        queued_cases += len(snapshots)
    return {
        "queued_cases": queued_cases,
        "run_ids": run_ids,
        "skipped": skipped,
    }


@bp_web.route("/rawdata", methods=["GET", "POST"])
@login_check
@templated("/rawdata.html")
def rawdata():
    page = int(request.args.get("page")) if request.args.get("page") else 0
    size = int(request.args.get("size")) if request.args.get("size") else 50
    form = request.values
    result = ""
    result_level = ""

    if request.method == "POST":
        op_action = str(form.get("op_action") or "").strip()

        if op_action == "single_update" and form.get("raw_id"):
            obj = raw_data.objects(pk=form.get("raw_id")).first()
            update_fields = {
                key: form.get(key)
                for key in ("action", "rule", "des", "tags", "modificator")
                if key in form
            }
            if obj and update_fields:
                for key, value in update_fields.items():
                    setattr(obj, key, value)
                obj.save()
                result = "单条接口已更新 / Single API updated."
                result_level = "success"

        elif op_action in {"batch_update", "batch_replay_verify"}:
            selected_ids = [item for item in form.getlist("raw_ids") if item]
            if not selected_ids:
                result = "请先勾选接口 / Please select API rows first."
                result_level = "warning"
            else:
                selected_rows = list(raw_data.objects(pk__in=selected_ids))
                if op_action == "batch_update":
                    field_map = {
                        "batch_action": "action",
                        "batch_rule": "rule",
                        "batch_des": "des",
                        "batch_tags": "tags",
                        "batch_modificator": "modificator",
                    }
                    update_fields = {
                        target: form.get(source)
                        for source, target in field_map.items()
                        if form.get(source) is not None and str(form.get(source)).strip()
                    }
                    if not update_fields:
                        result = "批量更新未执行：至少填写一个字段。"
                        result_level = "warning"
                    else:
                        for row in selected_rows:
                            for key, value in update_fields.items():
                                setattr(row, key, value)
                            row.save()
                        result = "批量更新完成：{} 条。".format(len(selected_rows))
                        result_level = "success"

                elif op_action == "batch_replay_verify":
                    queued = _queue_selected_replays(selected_rows, form)
                    result = (
                        "已排队 {} 个复测用例，运行批次 {} 个，跳过 {} 个；"
                        "结果由独立 worker 写入复核队列。"
                    ).format(
                        queued["queued_cases"],
                        len(queued["run_ids"]),
                        len(queued["skipped"]),
                    )
                    result_level = (
                        "success"
                        if queued["queued_cases"] and not queued["skipped"]
                        else "warning"
                    )

    query = {}
    if form.get("pathid"):
        try:
            query["ptah_id"] = int(form.get("pathid"))
        except (TypeError, ValueError):
            pass
    if form.get("filter_action"):
        query["action"] = form.get("filter_action")
    if form.get("filter_path"):
        query["path__regex"] = form.get("filter_path")
    objects = raw_data.objects(__raw__=query).order_by("-ptah_id")
    count = objects.count()
    hits = objects[page * size:page * size + size]

    return {
        "form": form,
        "page": page,
        "size": size,
        "count": count,
        "hits": hits,
        "hit": get_page(page, size, count),
        "result": result,
        "result_level": result_level,
    }
