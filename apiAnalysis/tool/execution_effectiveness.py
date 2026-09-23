"""Read-only, conservative result accounting; never promotes a verdict."""
from collections import Counter


_ACTIONS = {
    "baseline_blocked_or_unscreened": ("正常请求基线未通过", "先用资源所属账号跑通正常请求，再进行变体测试。"),
    "adapter_judge_required": ("当前执行器只有重放能力", "选择具有业务判断逻辑的测试流程；请求成功不能证明安全。"),
    "invalid_or_missing_business_parameters": ("业务参数缺失或无效", "补充真实业务样本和参数来源，再重试。"),
    "test_environment_route_or_fixture_unavailable": ("环境路由或测试数据不可用", "核对所选环境和接口路径，并准备属于测试账号的资源。"),
    "before_readback_unavailable": ("执行前读回不可用", "先跑通资源详情读取，确认资源归属和当前状态。"),
    "unique_restore_payload_unavailable": ("恢复数据不完整", "补齐可唯一恢复原状态的数据，再运行写操作。"),
    "authenticated_request_rejected": ("认证请求被拒绝", "核对产品认证方案和账号权限，再验证正常请求。"),
    "same_business_error": ("正常请求和测试请求均返回业务错误", "先修正正常请求，避免用相同错误判断权限隔离。"),
    "server_error": ("服务端错误", "确认正常请求和服务状态后再测试。"),
    "mutation_not_sent": ("写操作未发送", "查看本次预检缺项；预检结束不代表写操作完成。"),
}


def summarize_effectiveness(rows):
    """Consume full-run projected metadata, never raw requests or responses.

    Count exact verdicts rather than trusting legacy outcome_class=pass.
    Counts describe recorded machine output, not verified vulnerabilities or
    distinct endpoint coverage. Each blocking reason counts once per result.
    """
    counts = Counter()
    reasons = Counter()
    for row in rows:
        verdict = row.get("verdict")
        category = {
            "no_vuln": "machine_pass", "potential_vuln": "candidate",
            "not_evaluable": "not_evaluable", "error": "error",
            "need_review": "review", "review": "review",
        }.get(verdict, "other")
        counts[category] += 1
        if category in {"not_evaluable", "error", "review"}:
            codes = row.get("reason_codes") or []
            if not isinstance(codes, (list, tuple)):
                codes = []
            known = {code for code in codes if isinstance(code, str) and code in _ACTIONS}
            reasons.update(known or {"other"})
    total = sum(counts.values())
    return {
        "total": total,
        **{key: counts[key] for key in (
            "machine_pass", "candidate", "not_evaluable", "error", "review", "other",
        )},
        "undetermined_percent": round(100 * (counts["not_evaluable"] + counts["error"]) / total, 1) if total else None,
        "actions": [{
            "count": count,
            "message": _ACTIONS.get(code, ("其他待排查原因", "查看下方结果及对应证据，补齐缺项后复测。"))[0],
            "action": _ACTIONS.get(code, ("其他待排查原因", "查看下方结果及对应证据，补齐缺项后复测。"))[1],
        } for code, count in reasons.most_common(5)],
    }
