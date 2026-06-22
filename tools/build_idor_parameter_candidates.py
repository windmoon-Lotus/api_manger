import argparse
import datetime as dt
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from apiAnalysis.db.collection import (  # noqa: E402
    idor_parameter_candidate,
    parameter_archive,
    parameter_relation,
    raw_data,
    req_data,
)
from apiAnalysis.main import _ensure_mongo_connection  # noqa: E402


AUTH_NAMES = {
    "authorization", "cookie", "token", "access_token", "accesstoken",
    "refresh_token", "refreshtoken", "password", "passwd", "pwd", "secret",
    "session", "sessionid", "sid", "csrf", "xsrf", "sign", "signature",
    "nonce", "timestamp", "ts",
}
PAGING_NAMES = {
    "page", "pageindex", "pagenum", "pagesize", "size", "limit", "offset",
    "start", "count", "sort", "order", "orderby", "keyword", "keywords",
    "search", "q", "lang", "locale",
}
TENANT_NAMES = {
    "entid", "ent_id", "enterpriseid", "enterprise_id", "tenantid",
    "tenant_id", "orgid", "org_id", "departmentid", "department_id",
    "deptid", "dept_id", "companyid", "company_id",
}
OWNER_NAMES = {
    "userid", "user_id", "uid", "account", "accountid", "account_id",
    "ownerid", "owner_id", "entuserid", "ent_userid", "ent_user_id",
    "memberid", "member_id",
}
RESOURCE_TOKENS = {
    "remoteid", "remote_id", "clientid", "client_id", "tagid", "tag_id",
    "policyid", "policy_id", "systempolicyid", "system_policy_id",
    "packageid", "package_id", "productid", "product_id", "seatid",
    "seat_id", "securityid", "security_id", "orderid", "order_id",
    "blacklistuserid", "blacklist_user_id", "blacklistclientid",
    "blacklist_client_id", "deviceid", "device_id", "hostid", "host_id",
    "groupid", "group_id", "roleid", "role_id", "configid", "config_id",
}
CONFIG_NAMES = {
    "type", "status", "state", "version", "module", "mode", "config",
    "enabled", "enable", "switch", "level", "name", "title", "remark",
}


def leaf(name: str) -> str:
    value = str(name or "").split(".")[-1].strip().lower()
    return re.sub(r"[^a-z0-9_]", "", value)


def norm_param(name: str) -> str:
    return re.sub(r"[^a-z0-9_]", "", str(name or "").lower())


def unique_short(values: List[Any], limit: int = 5) -> List[str]:
    out: List[str] = []
    for value in values or []:
        if value in (None, "", [], {}):
            continue
        text = str(value)
        if len(text) > 120:
            text = text[:117] + "..."
        if text not in out:
            out.append(text)
        if len(out) >= limit:
            break
    return out


def archive_rows_for(parameter: str, pathid: int) -> List[parameter_archive]:
    names = {parameter, leaf(parameter), norm_param(parameter)}
    rows = []
    for item in parameter_archive.objects(parameter__in=list(names)):
        if (item.req_pathid and pathid in item.req_pathid) or (item.res_pathid and pathid in item.res_pathid):
            rows.append(item)
        elif item.req_value or item.res_value:
            rows.append(item)
    if rows:
        return rows
    target_leaf = leaf(parameter)
    for item in parameter_archive.objects():
        if leaf(item.parameter) == target_leaf:
            rows.append(item)
    return rows


def relation_refs_for(parameter: str, pathid: int) -> List[Dict[str, Any]]:
    refs = []
    for rel in parameter_relation.objects(parameter=parameter, req_pathid=pathid).limit(20):
        refs.append({
            "req_pathid": rel.req_pathid,
            "res_pathid": rel.res_pathid,
            "rule": rel.rule,
            "relation": rel.relation,
            "score": rel.score,
            "reason_codes": list(rel.reason_codes or []),
        })
    if refs:
        return refs
    for rel in parameter_relation.objects(parameter=leaf(parameter), req_pathid=pathid).limit(20):
        refs.append({
            "req_pathid": rel.req_pathid,
            "res_pathid": rel.res_pathid,
            "rule": rel.rule,
            "relation": rel.relation,
            "score": rel.score,
            "reason_codes": list(rel.reason_codes or []),
        })
    return refs


def classify(parameter: str, position: str, required: bool, has_archive: bool, relation_refs: List[Dict[str, Any]]) -> Tuple[str, float, List[str]]:
    low = leaf(parameter)
    full = norm_param(parameter)
    reasons: List[str] = []
    score = 0.15

    if position == "path":
        score += 0.25
        reasons.append("PATH_PARAM")
    elif position == "query":
        score += 0.10
        reasons.append("QUERY_PARAM")
    if required:
        score += 0.12
        reasons.append("REQUIRED")
    if has_archive:
        score += 0.20
        reasons.append("ACCOUNT_SCOPED_VALUE")
    if relation_refs:
        score += 0.15
        reasons.append("REQUEST_RESPONSE_RELATION")

    if low in AUTH_NAMES or any(token in full for token in AUTH_NAMES):
        return "auth_context", min(0.98, score + 0.45), reasons + ["AUTH_NAME"]
    if low in PAGING_NAMES:
        return "pagination_filter", min(0.95, score + 0.35), reasons + ["PAGING_OR_FILTER_NAME"]
    if low in TENANT_NAMES:
        return "tenant_id", min(0.98, score + 0.38), reasons + ["TENANT_NAME"]
    if low in OWNER_NAMES:
        return "owner_id", min(0.96, score + 0.35), reasons + ["OWNER_NAME"]
    if low in RESOURCE_TOKENS or full in RESOURCE_TOKENS:
        return "resource_id", min(0.98, score + 0.40), reasons + ["RESOURCE_NAME"]
    if low.endswith("ids") or low.endswith("id") or full.endswith("ids") or full.endswith("id"):
        return "resource_id", min(0.90, score + 0.28), reasons + ["ID_SUFFIX"]
    if low in CONFIG_NAMES:
        return "business_config", min(0.80, score + 0.18), reasons + ["CONFIG_NAME"]
    if has_archive and relation_refs:
        return "resource_id", min(0.78, score + 0.18), reasons + ["VALUE_AND_RELATION_HINT"]
    if has_archive:
        return "unknown", min(0.62, score + 0.08), reasons + ["VALUE_ONLY_HINT"]
    return "unknown", min(0.50, score), reasons or ["NO_STRONG_SIGNAL"]


def sample_by_account(rows: List[parameter_archive]) -> Dict[str, List[str]]:
    samples: Dict[str, List[str]] = {}
    for item in rows:
        account = item.account_id or "unknown"
        values = unique_short(list(item.req_value or []) + list(item.res_value or []))
        if values:
            samples.setdefault(account, [])
            for value in values:
                if value not in samples[account]:
                    samples[account].append(value)
    return samples


def add_archive_tags(rows: List[parameter_archive], role: str) -> int:
    changed = 0
    role_tag = f"role:{role}"
    extra = "test:idor_candidate" if role in {"resource_id", "tenant_id", "owner_id"} else None
    if role in {"auth_context", "pagination_filter"}:
        extra = "test:do_not_swap"
    for item in rows:
        props = list(item.properties or [])
        wanted = [role_tag] + ([extra] if extra else [])
        missing = [tag for tag in wanted if tag not in props]
        if not missing:
            continue
        item.properties = props + missing
        item.save()
        changed += 1
    return changed


def main() -> int:
    parser = argparse.ArgumentParser(description="Build endpoint-scoped IDOR parameter candidates.")
    parser.add_argument("--source", default="apifox")
    parser.add_argument("--project", default="")
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--out", default=str(Path("..") / ".secrets" / "idor-parameter-candidates.private.json"))
    parser.add_argument("--no-tag-archive", action="store_true")
    args = parser.parse_args()

    _ensure_mongo_connection()
    query: Dict[str, Any] = {"source": args.source}
    if args.project:
        project_value = int(args.project) if str(args.project).isdigit() else args.project
        project_query = {
            "$or": [
                {"source_meta.apifox_project_id": project_value},
                {"source_meta.project_id": project_value},
                {"source_meta.project_id": str(args.project)},
                {"source_meta.projectId": project_value},
                {"source_meta.projectId": str(args.project)},
            ]
        }
        query["__raw__"] = project_query

    rows = raw_data.objects(**query).order_by("ptah_id")
    if args.limit:
        rows = rows.limit(args.limit)

    summary: Dict[str, int] = {}
    records = []
    archive_tagged = 0
    for endpoint in rows:
        for param in req_data.objects(raw_data=endpoint):
            if not param.parameter:
                continue
            archive_rows = archive_rows_for(param.parameter, endpoint.ptah_id)
            refs = relation_refs_for(param.parameter, endpoint.ptah_id)
            role, confidence, reason_codes = classify(
                param.parameter,
                param.position or "",
                bool(param.required),
                bool(archive_rows),
                refs,
            )
            samples = sample_by_account(archive_rows)
            existing = idor_parameter_candidate.objects(
                pathid=endpoint.ptah_id,
                parameter=param.parameter,
                position=param.position,
            ).first()
            doc = existing or idor_parameter_candidate(
                pathid=endpoint.ptah_id,
                parameter=param.parameter,
                position=param.position,
                ctime=dt.datetime.utcnow(),
            )
            doc.raw_data = endpoint
            doc.method = endpoint.method
            doc.path = endpoint.path
            doc.param_type = param.type
            doc.required = bool(param.required)
            doc.role = role
            doc.role_confidence = round(confidence, 4)
            doc.reason_codes = reason_codes
            doc.source_meta = param.source_meta or {}
            doc.sample_values_by_account = samples
            doc.relation_refs = refs
            doc.mtime = dt.datetime.utcnow()
            doc.save()
            if not args.no_tag_archive:
                archive_tagged += add_archive_tags(archive_rows, role)
            summary[role] = summary.get(role, 0) + 1
            records.append({
                "pathid": endpoint.ptah_id,
                "method": endpoint.method,
                "path": endpoint.path,
                "parameter": param.parameter,
                "position": param.position,
                "role": role,
                "confidence": round(confidence, 4),
                "reason_codes": reason_codes,
                "sample_accounts": sorted(samples.keys()),
                "relation_count": len(refs),
            })

    output = {
        "createdAt": int(dt.datetime.utcnow().timestamp()),
        "source": args.source,
        "project": args.project,
        "count": len(records),
        "summary": summary,
        "archiveTagged": archive_tagged,
        "items": records,
    }
    Path(args.out).write_text(json.dumps(output, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({
        "count": len(records),
        "summary": summary,
        "archiveTagged": archive_tagged,
        "out": args.out,
    }, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
