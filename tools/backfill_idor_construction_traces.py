import argparse
import datetime as dt
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from apiAnalysis.db.collection import (  # noqa: E402
    idor_construction_trace,
    idor_parameter_candidate,
    security_test_result,
)
from apiAnalysis.main import _ensure_mongo_connection  # noqa: E402


RESOURCE_ROLES = {"resource_id", "tenant_id", "owner_id"}
KEEP_ROLES = {"auth_context", "pagination_filter"}
EXCLUDED_ARCHIVE_PARAMS = {"page", "limit", "offset", "size", "lang", "locale", "keyword", "keywords"}


def leaf(name: str) -> str:
    return re.sub(r"[^a-z0-9_]", "", str(name or "").split(".")[-1].lower())


def candidate_for(pathid: int, name: str) -> Any:
    found = idor_parameter_candidate.objects(pathid=pathid, parameter=name).first()
    if found:
        return found
    target = leaf(name)
    for item in idor_parameter_candidate.objects(pathid=pathid):
        if leaf(item.parameter) == target:
            return item
    return None


def decisions(pathid: int, sources: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    selected: Dict[str, Any] = {}
    kept: Dict[str, Any] = {}
    for name, source in (sources or {}).items():
        candidate = candidate_for(pathid, name)
        role = (candidate.manual_role or candidate.role) if candidate else ""
        entry = {
            "source": source,
            "role": role or "legacy_archive_value",
            "confidence": getattr(candidate, "role_confidence", None) if candidate else None,
            "reason_codes": list(getattr(candidate, "reason_codes", []) or []) if candidate else [],
        }
        if role in RESOURCE_ROLES or (not role and leaf(name) not in EXCLUDED_ARCHIVE_PARAMS):
            selected[name] = entry
        elif role in KEEP_ROLES or leaf(name) in EXCLUDED_ARCHIVE_PARAMS:
            kept[name] = entry
        else:
            kept[name] = entry
    return {"selected": selected, "kept": kept}


def main() -> int:
    parser = argparse.ArgumentParser(description="Backfill IDOR construction traces from existing security_test_result rows.")
    parser.add_argument("--check-type", default="readonly_idor")
    parser.add_argument("--limit", type=int, default=0)
    args = parser.parse_args()

    _ensure_mongo_connection()
    query = security_test_result.objects(check_type=args.check_type).order_by("-ctime")
    if args.limit:
        query = query.limit(args.limit)

    created = 0
    skipped = 0
    for result in query:
        if idor_construction_trace.objects(result_id=result.id).first():
            skipped += 1
            continue
        row = result.evidence_summary or {}
        pathid = int(row.get("pathid") or result.related_pathid or 0)
        if not pathid:
            skipped += 1
            continue
        source_map = row.get("parameterSources") or {}
        dec = decisions(pathid, source_map)
        idor_construction_trace(
            run_id=result.run_id,
            result_id=result.id,
            pathid=pathid,
            case_name=result.case_name,
            check_type=result.check_type,
            method=result.method or row.get("method"),
            path=row.get("path") or (result.target or {}).get("path"),
            owner_account=f"account[{row.get('ownerIndex')}]" if row.get("ownerIndex") is not None else None,
            attacker_account=f"account[{row.get('attackerIndex')}]" if row.get("attackerIndex") is not None else None,
            selected_parameters=dec["selected"],
            kept_parameters=dec["kept"],
            mutations=[
                {"type": "resource_replay", "description": "recovered from existing result evidence"},
                {"type": "auth_swap", "from": row.get("ownerIndex"), "to": row.get("attackerIndex")},
            ],
            value_sources=source_map,
            request_before={"url": row.get("renderedUrl")},
            request_after={"url": row.get("renderedUrl"), "auth_account": f"account[{row.get('attackerIndex')}]"},
            strategy="readonly_resource_replay_with_attacker_auth",
            strategy_reason="backfilled from security_test_result evidence_summary",
            judge_inputs={
                "owner_status": (row.get("owner") or {}).get("statusCode"),
                "attacker_status": (row.get("attacker") or {}).get("statusCode"),
                "owner_response_length": (row.get("owner") or {}).get("responseLength"),
                "attacker_response_length": (row.get("attacker") or {}).get("responseLength"),
            },
            verdict=result.verdict,
            reason_codes=list(result.reason_codes or []),
            evidence_ref=result.evidence_ref,
            ctime=dt.datetime.utcnow(),
        ).save()
        created += 1

    print(json.dumps({"created": created, "skipped": skipped}, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
