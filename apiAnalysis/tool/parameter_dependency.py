"""
Conservative parameter dependency resolution for request construction.

This module intentionally resolves only reusable, high-confidence aliases. It
does not infer workflow-specific values such as "blacklist_user_id should be the
other account's user_id"; those belong in explicit security test orchestration.
"""
import re
from typing import Any, Dict, Iterable, List, Optional, Tuple

from apiAnalysis.db.collection import (
    idor_parameter_candidate,
    parameter_archive,
    parameter_relation,
)


EXACT_CONFIDENCE = 0.95
ALIAS_CONFIDENCE = 0.82
RELATION_CONFIDENCE_FLOOR = 0.70

DO_NOT_ALIAS = {
    "id",
    "blacklist_user_id",
    "blacklist_client_id",
    "account",
    "mobile",
    "email",
    "password",
    "code",
    "seccode",
    "captcha",
    "sign",
    "signature",
}

CANONICAL_ALIASES = {
    "userid": {"userid", "user_id", "uid"},
    "entid": {"entid", "ent_id", "enterpriseid", "enterprise_id", "tenantid", "tenant_id"},
    "ent_user_id": {"ent_user_id", "entuserid", "ent_userid"},
    "remoteid": {"remoteid", "remote_id", "remoteids"},
    "clientid": {"clientid", "client_id", "clientids"},
    "tagid": {"tagid", "tag_id", "tagids"},
    "policy_id": {"policy_id", "policyid"},
    "system_policy_id": {"system_policy_id", "systempolicyid"},
    "packageid": {"packageid", "package_id"},
    "seatid": {"seatid", "seat_id"},
    "macid": {"macid", "mac_id"},
    "fastcode": {"fastcode", "fast_code"},
    "transferid": {"transferid", "transfer_id"},
    "moduleid": {"moduleid", "module_id"},
    "securityid": {"securityid", "security_id"},
    "departmentid": {"departmentid", "department_id", "department_ids"},
    "groupid": {"groupid", "group_id", "group_ids"},
    "roleid": {"roleid", "role_id"},
    "grant_id": {"grant_id", "grantid"},
    "featureid": {"featureid", "feature_id"},
    "script_id": {"script_id", "scriptid"},
    "task_id": {"task_id", "taskid"},
    "zj_id": {"zj_id", "zjid"},
    "configid": {"configid", "config_id"},
}


def leaf(name: str) -> str:
    value = str(name or "").split(".")[-1].strip().lower()
    return re.sub(r"[^a-z0-9_]", "", value)


def canonical_name(name: str) -> str:
    low = leaf(name)
    for canonical, aliases in CANONICAL_ALIASES.items():
        if low in aliases:
            return canonical
    return low


def select_value(values: Iterable[Any]) -> Any:
    for value in values or []:
        if value not in (None, "", [], {}):
            return value
    return None


def trusted_relation_value(relation: Any) -> Any:
    """Return one scalar only from a verified or manually trusted relation."""
    if relation is None or not (
        bool(getattr(relation, "verified", False))
        or str(getattr(relation, "manual_decision", "") or "") == "trusted"
    ):
        return None
    for value in list(getattr(relation, "evidence", []) or []):
        if value is None or isinstance(value, (dict, list, tuple, set)):
            continue
        if isinstance(value, (str, int, float, bool)) and value != "":
            return value
    return None


def _archive_value(names: List[str], pathid: int, account_id: Optional[str], exact_path: bool,
                   project_id: Optional[str] = None, env_id: Optional[str] = None) -> Tuple[Any, Optional[parameter_archive]]:
    query: Dict[str, Any] = {"parameter__in": names}
    if project_id:
        query["project_id"] = project_id
    if env_id:
        query["env_id"] = env_id
    if account_id:
        query["account_id"] = account_id
    candidates = list(parameter_archive.objects(**query))
    # Legacy global fallback is retained only when no explicit project/env
    # boundary exists. New project-scoped requests must never borrow values
    # from another context silently.
    if account_id and not candidates and not project_id and not env_id:
        candidates = list(parameter_archive.objects(parameter__in=names))

    best = None
    for item in candidates:
        if exact_path and pathid not in (item.req_pathid or []) and pathid not in (item.res_pathid or []):
            continue
        score = 0
        if item.account_id == account_id:
            score += 3
        if pathid in (item.req_pathid or []):
            score += 2
        if pathid in (item.res_pathid or []):
            score += 1
        value = select_value(list(item.req_value or []) + list(item.res_value or []))
        if value in (None, "", [], {}):
            continue
        rank = (score, item.id)
        if best is None or rank > best[0]:
            best = (rank, value, item)
    if best:
        return best[1], best[2]
    return None, None


def _candidate_role(pathid: int, parameter: str) -> Dict[str, Any]:
    doc = idor_parameter_candidate.objects(pathid=pathid, parameter=parameter).first()
    if not doc:
        doc = idor_parameter_candidate.objects(pathid=pathid, parameter=leaf(parameter)).first()
    if not doc:
        return {}
    return {
        "role": doc.manual_role or doc.role,
        "confidence": doc.role_confidence,
        "reason_codes": list(doc.reason_codes or []),
    }


def _relation_value(parameter: str, pathid: int, *, project_id: Optional[str] = None,
                    env_id: Optional[str] = None) -> Tuple[Any, Optional[parameter_relation]]:
    context = {}
    if project_id:
        context["project_id"] = str(project_id)
    if env_id:
        context["env_id"] = str(env_id)
    for name in [parameter, leaf(parameter), canonical_name(parameter)]:
        for rel in parameter_relation.objects(
            parameter=name, req_pathid=pathid, **context
        ).order_by("-verified", "-score").limit(20):
            value = trusted_relation_value(rel)
            if value is not None:
                return value, rel
    return None, None


def resolve_parameter_value(
    parameter: str,
    pathid: int,
    account_id: Optional[str] = None,
    *,
    allow_alias: bool = True,
    project_id: Optional[str] = None,
    env_id: Optional[str] = None,
) -> Tuple[Any, Dict[str, Any]]:
    """
    Return `(value, source_meta)`.

    Source order:
    1. Verified/high-score parameter_relation for this endpoint.
    2. Exact-name parameter_archive, preferably account/path scoped.
    3. Whitelisted canonical alias archive, account scoped.
    """
    name = parameter or ""
    low = leaf(name)
    role_meta = _candidate_role(pathid, name)

    value, relation = _relation_value(
        name, pathid, project_id=project_id, env_id=env_id,
    )
    if value not in (None, "", [], {}):
        return value, {
            "source": "parameter_relation",
            "confidence": max(RELATION_CONFIDENCE_FLOOR, float(relation.score or 0)),
            "relation": relation.relation,
            "res_pathid": relation.res_pathid,
            "role": role_meta.get("role", ""),
            "role_confidence": role_meta.get("confidence", 0),
        }

    exact_names = list({name, low})
    value, archive = _archive_value(exact_names, pathid, account_id, exact_path=(low == "id"), project_id=project_id, env_id=env_id)
    if value not in (None, "", [], {}):
        return value, {
            "source": "parameter_archive",
            "confidence": EXACT_CONFIDENCE,
            "parameter": archive.parameter,
            "account_id": archive.account_id or "",
            "match": "exact",
            "role": role_meta.get("role", ""),
            "role_confidence": role_meta.get("confidence", 0),
        }

    canonical = canonical_name(name)
    if allow_alias and low not in DO_NOT_ALIAS and canonical != low:
        aliases = sorted(CANONICAL_ALIASES.get(canonical, {canonical}))
        value, archive = _archive_value(aliases, pathid, account_id, exact_path=False, project_id=project_id, env_id=env_id)
        if value not in (None, "", [], {}):
            return value, {
                "source": "parameter_dependency_alias",
                "confidence": ALIAS_CONFIDENCE,
                "parameter": archive.parameter,
                "canonical": canonical,
                "aliases": aliases,
                "account_id": archive.account_id or "",
                "role": role_meta.get("role", ""),
                "role_confidence": role_meta.get("confidence", 0),
            }

    return None, {
        "source": "unresolved",
        "confidence": 0,
        "role": role_meta.get("role", ""),
        "role_confidence": role_meta.get("confidence", 0),
    }
