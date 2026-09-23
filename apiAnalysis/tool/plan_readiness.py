"""Pure metadata preflight for the generic test-plan entry point."""
from .test_plan import plan_pathids


def assess_plan_readiness(plan, assets, environment=None, profile=None):
    blockers, warnings = [], []

    def issue(code, message, action, warning=False):
        (warnings if warning else blockers).append(dict(code=code, message=message, action=action))

    scope = getattr(plan, "scope", None) or {}
    if not isinstance(scope, dict):
        scope = {}
        issue("invalid_scope", "计划范围格式无效", "创建下一版本并重新选择接口。")
    if getattr(plan, "adapter_id", "") == "rule_plan_draft_only" or scope.get("execution_allowed") is False:
        issue("draft_only", "规则草稿不能直接执行", "先补齐业务样本和验证方式，通过草稿验证流程生成执行计划。")
    if getattr(plan, "status", "") != "active":
        issue("inactive", "计划尚未激活或已归档", "确认配置后激活可执行计划；规则草稿需要单独转换。")
    try:
        pathids = plan_pathids(plan)
    except (ValueError, TypeError, OverflowError, AttributeError):
        pathids = []
        issue("invalid_scope", "接口范围或请求预算无效", "填写有效接口编号，并确保预算覆盖全部接口。")
    project = getattr(plan, "project_id", "")
    env = getattr(plan, "env_id", "")
    if not project or not env or environment is None or not getattr(environment, "active", False) or (
        getattr(environment, "project_id", "") != project or getattr(environment, "env_id", "") != env
    ):
        issue("environment_unavailable", "缺少匹配的有效环境", "在项目环境与认证中启用环境，并绑定当前计划。")
    mode = getattr(plan, "auth_mode", None) or "inherit"
    adapter = getattr(plan, "adapter_id", None) or (
        "authenticated_snapshot_batch" if mode == "account" else "snapshot_batch"
    )
    supported = {"snapshot_batch": {"anonymous", "inherit"}, "authenticated_snapshot_batch": {"account"}}
    if adapter not in supported:
        issue("specialized_adapter", "当前计划需要专用执行流程", "使用对应的授权矩阵、参数验证或写操作生命周期入口。")
    elif mode not in supported[adapter] or str(getattr(plan, "adapter_version", None) or "1") != "1":
        issue("adapter_mismatch", "执行方式与认证模式或版本不匹配", "账号模式选择认证重放，匿名模式选择普通重放，并使用支持的版本。")
    if mode == "account" and (
        not getattr(plan, "auth_profile_id", None) or profile is None
        or not getattr(profile, "active", False)
        or getattr(profile, "lifecycle", "active") != "active"
        or getattr(profile, "project_id", "") != project
        or getattr(profile, "env_id", "") != env
    ):
        issue("profile_unavailable", "缺少匹配的有效认证方案", "在项目环境与认证中配置本环境的测试账号认证方案。")
    asset_index = {getattr(asset, "ptah_id", None): asset for asset in assets}
    for pathid in pathids:
        asset = asset_index.get(pathid)
        if asset is None or getattr(asset, "project_id", "") != project:
            issue("asset_unavailable", "接口 {} 不属于当前项目或不存在".format(pathid), "在接口资产中核对项目归属，重新选择接口。")
            continue
        if getattr(asset, "env_id", None) and asset.env_id != env:
            issue("asset_environment_mismatch", "接口 {} 的环境与计划不一致".format(pathid), "选择相同环境的资产和计划。")
        if str(getattr(asset, "method", "")).upper() not in {"GET", "HEAD", "OPTIONS"}:
            issue("mutation_unsupported", "接口 {} 不是普通只读请求".format(pathid), "通过具备读回和清理能力的专用流程测试写操作。")
    if adapter in supported and not (mode == "anonymous" and getattr(plan, "check_type", "") in {"unauth_access", "anonymous_access"}):
        issue("judge_required", "普通重放不会自动形成安全结论", "先验证正常请求；安全结论需要具备业务判断逻辑的专用测试流程。", True)
    issue("live_baseline_unverified", "真实认证和正常业务基线尚未由本检查验证", "执行正常请求并检查业务内容和资源归属后，再开展安全测试。", True)
    return {"status": "blocked" if blockers else "preflight_only", "blockers": blockers,
            "warnings": warnings, "pathids": pathids, "count": len(pathids)}
