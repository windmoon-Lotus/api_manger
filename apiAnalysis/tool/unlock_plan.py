"""Blocked-plan steps whose readiness is unlocked by observed facts.

Motivation
----------
Gaps such as "the enterprise tree is not unlocked" or "no high-privilege account
is available" were tracked as static missing items.  Every report then re-argued
the same precondition, and when the precondition was finally satisfied nothing
downstream advanced automatically.  This module models those gaps as steps with
dependencies, so a newly recorded fact unlocks the next step on its own.

Division of labour (see docs/deterministic_vs_model_boundary.md)
---------------------------------------------------------------
``status`` is a manual lifecycle and is stored.  Readiness is *derived* from
facts by :func:`evaluate_steps` and is never stored as a conclusion.  No model
output participates in either.

Conservative by construction
----------------------------
A fact that is ``unknown`` blocks exactly like one that is ``unsatisfied``.
Satisfaction is only ever recorded with evidence, so a missing precondition can
never be mistaken for a satisfied one.
"""

import datetime as dt
from typing import Any, Dict, Iterable, List, Optional, Sequence

from apiAnalysis.db.collection import precondition_fact, unlock_step


# Facts referenced by the default plan.  Keys are stable identifiers so a
# re-seeded plan never forks the dependency graph.
FACT_SQL_USERID_CONCATENATED = "sqli.userid_concatenated_into_sql"
FACT_ENTERPRISE_OWNER_ACCOUNT = "account.enterprise_owner_available"
FACT_ENTERPRISE_CONTEXT_TOKEN = "enterprise.context_token_minted"
FACT_HIGH_PRIVILEGE_ACCOUNT = "account.high_privilege_available"
FACT_GRPC_BODY_SAMPLE = "sample.grpc_write_body_captured"

SERVES_ENTERPRISE_TREE = "enterprise_tree"
SERVES_VERTICAL_PRIVILEGE = "vertical_privilege"
SERVES_GRPC_WRITE = "grpc_write"
SERVES_SQLI_INJECTION = "sqli_injection"

FACT_TITLES = {
    FACT_SQL_USERID_CONCATENATED: "某 userid 参数已被证明直接拼进 SQL",
    FACT_ENTERPRISE_OWNER_ACCOUNT: "存在可用的企业 owner 账号",
    FACT_ENTERPRISE_CONTEXT_TOKEN: "已铸出 enterprise-context token",
    FACT_HIGH_PRIVILEGE_ACCOUNT: "存在高权限/运营账号上下文",
    FACT_GRPC_BODY_SAMPLE: "已采到 gRPC 写接口的真实 body 样本",
}


def default_plan() -> List[Dict[str, Any]]:
    """The seed dependency graph, as plain data so it is testable and reviewable."""
    return [
        {
            "step_key": "sqli.prove_userid_concatenation",
            "title": "证明 userid 类参数直接拼接进 SQL",
            "serves": SERVES_SQLI_INJECTION,
            "requires_fact_keys": [],
            "produces_fact_keys": [FACT_SQL_USERID_CONCATENATED],
            "priority": 10,
        },
        {
            "step_key": "sqli.sibling_family_probe",
            "title": "对同族接口做注入探测",
            "serves": SERVES_SQLI_INJECTION,
            "detail": "依赖身份暴露型 fact；同族接口此前均因前置规则未测。",
            "requires_fact_keys": [FACT_SQL_USERID_CONCATENATED],
            "produces_fact_keys": [],
            "priority": 20,
        },
        {
            "step_key": "account.obtain_enterprise_owner",
            "title": "取得企业 owner 账号",
            "serves": SERVES_ENTERPRISE_TREE,
            "requires_fact_keys": [],
            "produces_fact_keys": [FACT_ENTERPRISE_OWNER_ACCOUNT],
            "priority": 30,
        },
        {
            "step_key": "enterprise.mint_context_token",
            "title": "铸造 enterprise-context token",
            "serves": SERVES_ENTERPRISE_TREE,
            "detail": "空返回要回看响应体，别读成无权限。",
            "requires_fact_keys": [FACT_ENTERPRISE_OWNER_ACCOUNT],
            "produces_fact_keys": [FACT_ENTERPRISE_CONTEXT_TOKEN],
            "priority": 40,
        },
        {
            "step_key": "enterprise.read_org_tree",
            "title": "企业树读面（组织/通讯录/部门/成员）",
            "serves": SERVES_ENTERPRISE_TREE,
            "requires_fact_keys": [FACT_ENTERPRISE_CONTEXT_TOKEN],
            "produces_fact_keys": [],
            "priority": 50,
        },
        {
            "step_key": "enterprise.write_org_tree",
            "title": "企业树写面（受控、可逆）",
            "serves": SERVES_ENTERPRISE_TREE,
            "requires_fact_keys": [FACT_ENTERPRISE_CONTEXT_TOKEN],
            "produces_fact_keys": [],
            "priority": 60,
        },
        {
            "step_key": "account.obtain_high_privilege",
            "title": "取得高权限/运营账号",
            "serves": SERVES_VERTICAL_PRIVILEGE,
            "requires_fact_keys": [],
            "produces_fact_keys": [FACT_HIGH_PRIVILEGE_ACCOUNT],
            "priority": 70,
        },
        {
            "step_key": "authz.vertical_privilege_sweep",
            "title": "普通用户调管理接口（垂直越权）",
            "serves": SERVES_VERTICAL_PRIVILEGE,
            "requires_fact_keys": [FACT_HIGH_PRIVILEGE_ACCOUNT],
            "produces_fact_keys": [],
            "priority": 80,
        },
        {
            "step_key": "sample.capture_grpc_write_body",
            "title": "采集 gRPC 写接口真实 body 样本",
            "serves": SERVES_GRPC_WRITE,
            "detail": "文档无 body schema，只能从真实流量构造。",
            "requires_fact_keys": [],
            "produces_fact_keys": [FACT_GRPC_BODY_SAMPLE],
            "priority": 90,
        },
        {
            "step_key": "write.grpc_schema_write_sweep",
            "title": "gRPC 空 schema 写面探测",
            "serves": SERVES_GRPC_WRITE,
            "requires_fact_keys": [FACT_GRPC_BODY_SAMPLE],
            "produces_fact_keys": [],
            "priority": 100,
        },
    ]


def _satisfied_keys(facts: Iterable[Any]) -> set:
    return {
        str(getattr(fact, "fact_key", "") or "")
        for fact in facts
        if str(getattr(fact, "state", "") or "") == precondition_fact.SATISFIED
    }


def evaluate_steps(steps: Sequence[Any], facts: Sequence[Any]) -> List[Dict[str, Any]]:
    """Derive readiness for every step from the facts that are satisfied.

    Pure function: no database, no model output.  ``blocked_by`` lists the
    required facts that are not satisfied, so a blocked step always says what it
    is waiting for.

    Two integrity signals are reported because they are invisible otherwise:

    * ``precondition_lost`` — the step is already done or in progress, yet one
      of its preconditions is no longer satisfied.  The earlier work may now be
      invalid.
    * ``inconsistent`` — a step produces a fact that another step requires, but
      the producer is abandoned, so the dependent can never become ready.
    """
    satisfied = _satisfied_keys(facts)
    by_key = {
        str(getattr(step, "step_key", "") or ""): step for step in steps
    }
    produced_by: Dict[str, str] = {}
    for step in steps:
        for produced in (getattr(step, "produces_fact_keys", None) or []):
            produced_by.setdefault(str(produced), str(getattr(step, "step_key", "") or ""))

    evaluated: List[Dict[str, Any]] = []
    for step in steps:
        step_key = str(getattr(step, "step_key", "") or "")
        status = str(getattr(step, "status", "") or unlock_step.PENDING)
        required = [str(key) for key in (getattr(step, "requires_fact_keys", None) or [])]
        missing = sorted(key for key in required if key not in satisfied)

        if status in unlock_step.TERMINAL:
            readiness = status
        elif status == unlock_step.IN_PROGRESS:
            readiness = unlock_step.IN_PROGRESS
        elif missing:
            readiness = unlock_step.BLOCKED
        else:
            readiness = unlock_step.READY

        produces = [str(key) for key in (getattr(step, "produces_fact_keys", None) or [])]
        downstream = sorted(
            str(getattr(other, "step_key", "") or "")
            for other in steps
            if str(getattr(other, "step_key", "") or "") != step_key
            and str(getattr(other, "status", "") or "") not in unlock_step.TERMINAL
            and set(str(key) for key in (getattr(other, "requires_fact_keys", None) or []))
            & set(produces)
        )

        lost = missing if (status in unlock_step.TERMINAL or status == unlock_step.IN_PROGRESS) else []
        blocked_producers = sorted(
            produced_by[key] for key in required
            if key in produced_by
            and str(getattr(by_key.get(produced_by[key]), "status", "") or "")
            == unlock_step.ABANDONED
        )

        evaluated.append({
            "step_key": step_key,
            "title": str(getattr(step, "title", "") or ""),
            "serves": str(getattr(step, "serves", "") or ""),
            "priority": getattr(step, "priority", None),
            "status": status,
            "readiness": readiness,
            "requires_fact_keys": required,
            "blocked_by": missing,
            "produces_fact_keys": produces,
            "downstream_count": len(downstream),
            "downstream_step_keys": downstream,
            "precondition_lost": lost,
            "deadlocked_by_abandoned": blocked_producers,
        })

    evaluated.sort(key=lambda item: (
        item["priority"] if item["priority"] is not None else 100,
        item["step_key"],
    ))
    return evaluated


def ready_steps(steps: Sequence[Any], facts: Sequence[Any]) -> List[Dict[str, Any]]:
    """Steps whose preconditions are met and which are not terminal."""
    return [
        item for item in evaluate_steps(steps, facts)
        if item["readiness"] == unlock_step.READY
    ]


def blocking_summary(steps: Sequence[Any], facts: Sequence[Any]) -> Dict[str, Any]:
    """Which unmet facts block the most steps, and which steps are already runnable."""
    evaluated = evaluate_steps(steps, facts)
    by_fact: Dict[str, List[str]] = {}
    for item in evaluated:
        if item["readiness"] != unlock_step.BLOCKED:
            continue
        for fact_key in item["blocked_by"]:
            by_fact.setdefault(fact_key, []).append(item["step_key"])
    by_fact = {
        key: sorted(step_keys)
        for key, step_keys in sorted(by_fact.items(), key=lambda pair: (-len(pair[1]), pair[0]))
    }
    return {
        "total_steps": len(evaluated),
        "ready": [item["step_key"] for item in evaluated if item["readiness"] == unlock_step.READY],
        "blocked": [item["step_key"] for item in evaluated if item["readiness"] == unlock_step.BLOCKED],
        "done": [item["step_key"] for item in evaluated if item["readiness"] == unlock_step.DONE],
        "blocked_by_fact": by_fact,
        "precondition_lost": [
            item["step_key"] for item in evaluated if item["precondition_lost"]
        ],
        "deadlocked_by_abandoned": [
            item["step_key"] for item in evaluated if item["deadlocked_by_abandoned"]
        ],
    }


def record_fact(*, fact_key: str, state: str, project_id: str = "", env_id: str = "",
                title: str = "", value_summary: Dict[str, Any] = None,
                evidence_ref: str = "", evidence_trace_ids: Sequence[Any] = None,
                satisfied_by_run_id: Any = None, note: str = "",
                manual_confirmation: bool = False) -> precondition_fact:
    """Record one precondition's state with its evidence.

    Upserts per (project, env, fact_key) so re-recording updates the state
    without forking the dependency graph.

    A fact may only be marked ``satisfied`` with evidence attached -- a trace
    id, an evidence reference, or the run that observed it.  Readiness is
    derived from ``state`` alone, so an unevidenced ``satisfied`` would unlock
    downstream steps on the strength of an assertion.  When there genuinely is
    evidence but it cannot be referenced here, pass
    ``manual_confirmation=True`` to record it anyway; the flag is stored in the
    note so the shortcut is visible to whoever reviews the plan later.
    """
    if state not in (precondition_fact.SATISFIED, precondition_fact.UNSATISFIED,
                     precondition_fact.UNKNOWN):
        raise ValueError(
            "state must be one of satisfied/unsatisfied/unknown, got {!r}".format(state)
        )
    has_evidence = bool(
        str(evidence_ref or "").strip()
        or list(evidence_trace_ids or [])
        or satisfied_by_run_id
    )
    if state == precondition_fact.SATISFIED and not has_evidence:
        if not manual_confirmation:
            raise ValueError(
                "refusing to mark {!r} satisfied without evidence: pass "
                "evidence_ref, evidence_trace_ids or satisfied_by_run_id, or "
                "set manual_confirmation=True to record it explicitly".format(fact_key)
            )
        note = " ".join(part for part in (
            str(note or ""), "manual_confirmation=no_referenced_evidence",
        ) if part).strip()
    now = dt.datetime.utcnow()
    satisfied_at = now if state == precondition_fact.SATISFIED else None
    updates = dict(
        set__title=str(title or FACT_TITLES.get(fact_key, "")),
        set__state=state,
        set__value_summary=dict(value_summary or {}),
        set__evidence_ref=str(evidence_ref or ""),
        set__evidence_trace_ids=list(evidence_trace_ids or []),
        set__note=str(note or ""),
        set__updated_at=now,
        set__satisfied_at=satisfied_at,
    )
    if satisfied_by_run_id:
        updates["set__satisfied_by_run_id"] = satisfied_by_run_id
    precondition_fact.objects(
        project_id=str(project_id or ""), env_id=str(env_id or ""), fact_key=str(fact_key)
    ).update_one(upsert=True, **updates)
    return precondition_fact.objects(
        project_id=str(project_id or ""), env_id=str(env_id or ""), fact_key=str(fact_key)
    ).first()


def list_facts(*, project_id: str = "", env_id: str = "") -> List[precondition_fact]:
    return list(precondition_fact.objects(
        project_id=str(project_id or ""), env_id=str(env_id or "")
    ).order_by("fact_key"))


def list_steps(*, project_id: str = "", env_id: str = "") -> List[unlock_step]:
    return list(unlock_step.objects(
        project_id=str(project_id or ""), env_id=str(env_id or "")
    ).order_by("priority", "step_key"))


def seed_default_plan(*, project_id: str = "", env_id: str = "") -> Dict[str, int]:
    """Create missing steps and facts for one project/environment.

    Idempotent: existing step keys are left untouched, so a re-seed never
    overwrites manual status progress.
    """
    now = dt.datetime.utcnow()
    created_steps = 0
    for entry in default_plan():
        plan_step = dict(entry)
        plan_step["project_id"] = str(project_id or "")
        plan_step["env_id"] = str(env_id or "")
        existing = unlock_step.objects(
            project_id=plan_step["project_id"], env_id=plan_step["env_id"],
            step_key=plan_step["step_key"],
        ).first()
        if existing:
            continue
        unlock_step(ctime=now, updated_at=now, **plan_step).save()
        created_steps += 1

    created_facts = 0
    for fact_key in sorted(FACT_TITLES):
        existing = precondition_fact.objects(
            project_id=str(project_id or ""), env_id=str(env_id or ""), fact_key=fact_key
        ).first()
        if existing:
            continue
        precondition_fact(
            fact_key=fact_key, title=FACT_TITLES[fact_key],
            state=precondition_fact.UNKNOWN, project_id=str(project_id or ""),
            env_id=str(env_id or ""), ctime=now, updated_at=now,
        ).save()
        created_facts += 1

    return {"created_steps": created_steps, "created_facts": created_facts}


def ensure_plan_seeded(*, project_id: str = "", env_id: str = "",
                       enabled: bool = True) -> Dict[str, Any]:
    """Best-effort seeding hook for project/environment setup.

    Returns a report instead of raising, so a plan-bootstrap problem can never
    block creating a project or binding a source.  ``enabled=False`` makes the
    call a no-op, which is what tests and dry runs use.

    Seeding is skipped when either id is missing: a plan is scoped to exactly
    one (project, environment) pair, and seeding a half-scoped one would create
    rows that no later query could find.
    """
    project_id = str(project_id or "").strip()
    env_id = str(env_id or "").strip()
    if not enabled:
        return {"seeded": False, "reason": "disabled", "created_steps": 0, "created_facts": 0}
    if not project_id or not env_id:
        return {"seeded": False, "reason": "incomplete_scope",
                "created_steps": 0, "created_facts": 0}
    try:
        # Fast path: a plan is seeded once per (project, environment).  Binding
        # a source happens far more often than a plan is first needed, so pay
        # one lookup in the steady state instead of the full seed's fifteen.
        if unlock_step.objects(
            project_id=project_id, env_id=env_id,
        ).only("id").first():
            return {"seeded": False, "reason": "already_seeded",
                    "created_steps": 0, "created_facts": 0}
        created = seed_default_plan(project_id=project_id, env_id=env_id)
    except Exception as exc:
        return {"seeded": False, "reason": "{}: {}".format(exc.__class__.__name__, exc),
                "created_steps": 0, "created_facts": 0}
    return {
        "seeded": True,
        "reason": "",
        "project_id": project_id,
        "env_id": env_id,
        "created_steps": created["created_steps"],
        "created_facts": created["created_facts"],
    }
