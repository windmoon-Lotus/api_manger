"""
Versioned test plan lifecycle.

Plans are project-scoped, immutable once activated. Edits create a new
version. Plans reference adapter/auth/scope configuration and produce
request snapshots that feed into security_test_run via the scheduler.
"""
import datetime
import hashlib
import json
import logging
from urllib.parse import urlsplit

from bson import ObjectId

from ..db.collection import raw_data, security_test_plan

logger = logging.getLogger(__name__)
MAX_PLAN_REQUEST_BUDGET = 1000


def plan_content_sha256(plan):
    """Hash only executable plan content, excluding lifecycle timestamps/state."""
    payload = {
        "name": str(plan.name or ""),
        "project_id": str(plan.project_id or ""),
        "env_id": str(plan.env_id or ""),
        "version": int(plan.version or 0),
        "check_type": str(plan.check_type or ""),
        "adapter_id": str(plan.adapter_id or ""),
        "adapter_version": str(plan.adapter_version or ""),
        "auth_mode": str(plan.auth_mode or ""),
        "auth_profile_id": str(plan.auth_profile_id or ""),
        "scope": dict(plan.scope or {}),
        "execution_policy": dict(plan.execution_policy or {}),
        "snapshot_filter": dict(plan.snapshot_filter or {}),
        "request_budget": plan.request_budget,
    }
    encoded = json.dumps(
        payload, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def plan_pathids(plan):
    """Return the explicit, bounded endpoint scope for one plan version."""
    scope = dict(plan.scope or {})
    snapshot_filter = dict(plan.snapshot_filter or {})
    raw_values = scope.get("pathids") or snapshot_filter.get("pathids") or []
    if isinstance(raw_values, (str, int)):
        raw_values = [raw_values]
    if not isinstance(raw_values, (list, tuple, set)):
        raise ValueError("plan pathids must be a list")
    pathids = []
    for raw_value in raw_values:
        try:
            pathid = int(raw_value)
        except (TypeError, ValueError):
            raise ValueError("plan contains an invalid pathid") from None
        if pathid <= 0:
            raise ValueError("plan contains an invalid pathid")
        if pathid not in pathids:
            pathids.append(pathid)
    if not pathids:
        raise ValueError("plan requires an explicit pathid scope")
    budget = int(plan.request_budget or len(pathids))
    if not 1 <= budget <= MAX_PLAN_REQUEST_BUDGET:
        raise ValueError("plan request budget must be between 1 and 1000")
    if len(pathids) > budget:
        raise ValueError("plan pathid scope exceeds its request budget")
    return pathids


def _normalized_origin(value):
    parsed = urlsplit(str(value or "").strip())
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return ""
    return "{}://{}".format(parsed.scheme.lower(), parsed.netloc.lower())


def schedule_plan_execution(plan_id, *, operator="", run_name=""):
    """Create fresh immutable snapshots and enqueue one active plan version."""
    from .execution_contract import ExecutionContext, create_execution_snapshot
    from .execution_scheduler import ExecutionPolicy, enqueue_snapshot_batch
    from .project_auth import find_auth_profile, profile_context_fields

    plan = get_plan(plan_id)
    if plan is None:
        raise ValueError("test plan not found")
    if (
        str(plan.adapter_id or "") == "rule_plan_draft_only"
        or dict(plan.scope or {}).get("execution_allowed") is False
    ):
        raise ValueError("rule-generated analysis drafts are not executable")
    if plan.status != security_test_plan.ACTIVE:
        raise ValueError("only an active test plan can execute")

    pathids = plan_pathids(plan)
    auth_mode = str(plan.auth_mode or "inherit")
    adapter_id = str(plan.adapter_id or "") or (
        "authenticated_snapshot_batch"
        if auth_mode == "account"
        else "snapshot_batch"
    )
    context_fields = {}
    if auth_mode == "account":
        if not plan.auth_profile_id:
            raise ValueError("account plan requires an auth profile")
        profile = find_auth_profile(
            str(plan.auth_profile_id),
            project_id=str(plan.project_id),
            env_id=str(plan.env_id or ""),
        )
        if profile is None:
            raise ValueError("plan auth profile is unavailable")
        context_fields = profile_context_fields(profile)

    context = ExecutionContext(
        project_id=str(plan.project_id or ""),
        env_id=str(plan.env_id or context_fields.get("env_id") or ""),
        account_id=str(context_fields.get("account_id") or ""),
        auth_mode=auth_mode,
        auth_provider_id=str(context_fields.get("auth_provider_id") or ""),
        auth_context_ref=str(context_fields.get("auth_context_ref") or ""),
        auth_profile_revision_id=str(
            context_fields.get("auth_profile_revision_id") or ""
        ),
        auth_realm_revision_id=str(
            context_fields.get("auth_realm_revision_id") or ""
        ),
        auth_adapter_version_id=str(
            context_fields.get("auth_adapter_version_id") or ""
        ),
        adapter_id=adapter_id,
        adapter_version=str(plan.adapter_version or "1"),
        plan_version=str(plan.version or ""),
        plan_sha256=plan_content_sha256(plan),
    )
    context.validate()
    policy = ExecutionPolicy.from_dict(plan.execution_policy or {})

    target_origins = {
        _normalized_origin(item)
        for item in (dict(plan.scope or {}).get("target_origins") or [])
        if _normalized_origin(item)
    }
    snapshot_ids = []
    for pathid in pathids:
        asset = raw_data.objects(ptah_id=pathid).first()
        if asset is None or str(asset.project_id or "") != context.project_id:
            raise ValueError("plan pathid does not belong to its project: {}".format(pathid))
        snapshot = create_execution_snapshot(
            pathid, context, source="test_plan_web",
        )
        if snapshot is None:
            raise ValueError("could not compose plan pathid: {}".format(pathid))
        snapshot_origin = _normalized_origin(snapshot.url)
        if target_origins and snapshot_origin not in target_origins:
            raise ValueError(
                "composed request is outside the plan target origins: {}".format(pathid)
            )
        snapshot_ids.append(snapshot.id)

    scope = dict(plan.scope or {})
    scope.update({
        "plan_id": str(plan.id),
        "plan_version": int(plan.version or 0),
        "request_budget": int(plan.request_budget or len(pathids)),
    })
    effective_name = run_name or "{} · v{} · {}".format(
        plan.name,
        plan.version,
        datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
    )
    return enqueue_snapshot_batch(
        name=effective_name,
        check_type=str(plan.check_type or adapter_id),
        context=context,
        snapshot_ids=snapshot_ids,
        policy=policy,
        scope=scope,
        operator=operator,
    )


def create_plan(
    name,
    project_id,
    check_type,
    env_id=None,
    adapter_id=None,
    adapter_version=None,
    auth_mode="inherit",
    auth_profile_id=None,
    scope=None,
    execution_policy=None,
    snapshot_filter=None,
    request_budget=None,
    description=None,
    created_by=None,
):
    plan = security_test_plan(
        name=name,
        project_id=project_id,
        check_type=check_type,
        env_id=env_id,
        adapter_id=adapter_id,
        adapter_version=adapter_version,
        auth_mode=auth_mode,
        auth_profile_id=auth_profile_id,
        scope=scope or {},
        execution_policy=execution_policy or {},
        snapshot_filter=snapshot_filter or {},
        request_budget=request_budget,
        description=description,
        created_by=created_by,
        version=1,
        status=security_test_plan.DRAFT,
    )
    plan.save()
    logger.info("created test plan %s (%s) for project %s", plan.id, name, project_id)
    return plan


def create_next_version(plan_id, created_by=None, **overrides):
    """Create a new draft version from an existing plan."""
    source = security_test_plan.objects(id=plan_id).first()
    if source is None:
        raise ValueError(f"plan {plan_id} not found")

    latest = (
        security_test_plan.objects(
            project_id=source.project_id, name=source.name
        )
        .order_by("-version")
        .first()
    )
    next_version = (latest.version + 1) if latest else 1

    data = {
        "name": source.name,
        "project_id": source.project_id,
        "env_id": source.env_id,
        "check_type": source.check_type,
        "adapter_id": source.adapter_id,
        "adapter_version": source.adapter_version,
        "auth_mode": source.auth_mode,
        "auth_profile_id": source.auth_profile_id,
        "scope": source.scope,
        "execution_policy": source.execution_policy,
        "snapshot_filter": source.snapshot_filter,
        "request_budget": source.request_budget,
        "description": source.description,
        "parent_plan_id": source.id,
        "version": next_version,
        "status": security_test_plan.DRAFT,
        "created_by": created_by,
    }
    data.update({k: v for k, v in overrides.items() if v is not None})

    plan = security_test_plan(**data)
    plan.save()
    logger.info(
        "created plan version %d of %s (%s)", next_version, source.name, plan.id
    )
    return plan


def activate_plan(plan_id):
    plan = security_test_plan.objects(id=plan_id).first()
    if plan is None:
        raise ValueError(f"plan {plan_id} not found")
    if plan.status != security_test_plan.DRAFT:
        raise ValueError(f"plan {plan_id} is {plan.status}, only draft can be activated")

    security_test_plan.objects(
        project_id=plan.project_id,
        name=plan.name,
        status=security_test_plan.ACTIVE,
    ).update(set__status=security_test_plan.ARCHIVED, set__updated_at=datetime.datetime.utcnow())

    plan.status = security_test_plan.ACTIVE
    plan.updated_at = datetime.datetime.utcnow()
    plan.save()
    logger.info("activated plan %s (%s v%d)", plan.id, plan.name, plan.version)
    return plan


def archive_plan(plan_id):
    plan = security_test_plan.objects(id=plan_id).first()
    if plan is None:
        raise ValueError(f"plan {plan_id} not found")
    plan.status = security_test_plan.ARCHIVED
    plan.updated_at = datetime.datetime.utcnow()
    plan.save()
    return plan


def list_plans(project_id, status=None, check_type=None):
    qs = security_test_plan.objects(project_id=project_id)
    if status:
        qs = qs.filter(status=status)
    if check_type:
        qs = qs.filter(check_type=check_type)
    return qs.order_by("-ctime")


def get_plan(plan_id):
    return security_test_plan.objects(id=plan_id).first()


def get_active_plan(project_id, name):
    return security_test_plan.objects(
        project_id=project_id,
        name=name,
        status=security_test_plan.ACTIVE,
    ).first()
