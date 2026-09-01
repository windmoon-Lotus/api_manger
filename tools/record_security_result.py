import argparse
import datetime as dt
import json
import sys
from pathlib import Path
from typing import Any, Dict, List

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from apiAnalysis.db.collection import raw_data, security_test_run
from apiAnalysis.main import _ensure_mongo_connection
from apiAnalysis.tool.execution_contract import (
    ExecutionContext,
    create_execution_run,
    record_execution_result,
)


VERDICT_MAP = {
    "blocked_http": "no_vuln",
    "blocked_not_found": "no_vuln",
    "blocked_empty": "no_vuln",
    "likely_business_denied_or_common_error": "no_vuln",
    "weak_or_empty_signal": "not_evaluable",
    "not_evaluable_no_owner_data": "not_evaluable",
    "needs_review": "need_review",
    "potential_idor": "potential_vuln",
    "inconclusive": "error",
}

SEVERITY_MAP = {
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "info",
}


def _load_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _index_matrix(matrix_doc: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    indexed = {}
    for item in matrix_doc.get("results") or []:
        key = _case_key(item)
        if key:
            indexed[key] = item
    return indexed


def _case_key(item: Dict[str, Any]) -> str:
    return "|".join(
        str(item.get(name, ""))
        for name in ("case", "victimIndex", "attackerIndex")
    )


def _related_pathid(endpoint_id: Any, endpoint_name: str = "", method: str = "") -> int:
    if endpoint_id not in (None, ""):
        # Apifox endpoint ids are kept in the imported asset description/source
        # only indirectly today, so path matching remains the reliable fallback.
        pass
    query = {}
    if endpoint_name:
        query["path"] = endpoint_name
    if method:
        query["method"] = str(method).upper()
    item = raw_data.objects(**query).first() if query else None
    return int(item.ptah_id) if item else 0


def _summary_evidence(finding: Dict[str, Any], matrix_item: Dict[str, Any], mode: str) -> Dict[str, Any]:
    evidence = {
        "finding": finding,
        "matrix": matrix_item or {},
    }
    if mode == "safe":
        keep_finding = {
            key: finding.get(key)
            for key in (
                "ownerStatus",
                "attackerStatus",
                "ownerLength",
                "attackerLength",
                "lengthRatio",
                "ownerItemCount",
                "attackerItemCount",
                "ownerNonEmpty",
                "attackerNonEmpty",
                "sharedKeyCount",
                "sharedKeysSample",
                "ownerError",
                "attackerError",
                "reasons",
            )
        }
        keep_matrix = {
            key: matrix_item.get(key)
            for key in ("endpointId", "endpointName", "case", "classification", "victimIndex", "attackerIndex", "victimParam")
        } if matrix_item else {}
        evidence = {"finding": keep_finding, "matrix": keep_matrix}
    return evidence


def record_run(
    analysis_path: Path,
    matrix_path: Path = None,
    name: str = "",
    profile_id: str = "",
    check_type: str = "idor",
    mode: str = "full",
    operator: str = "",
    project_id: str = "",
    env_id: str = "",
) -> Dict[str, Any]:
    analysis_doc = _load_json(analysis_path)
    matrix_doc = _load_json(matrix_path) if matrix_path else {}
    matrix_index = _index_matrix(matrix_doc)
    findings: List[Dict[str, Any]] = analysis_doc.get("findings") or []

    effective_project_id = str(project_id or analysis_doc.get("project_id") or "")
    if not effective_project_id:
        raise ValueError("project_id is required by execution.v1")
    context = ExecutionContext(
        project_id=effective_project_id,
        env_id=str(env_id or analysis_doc.get("env_id") or ""),
        auth_mode="inherit",
        adapter_id="analysis_evidence_import",
        adapter_version="1",
    )
    run = create_execution_run(
        name=name or analysis_path.stem,
        check_type=check_type,
        context=context,
        scope={
            "analysis_path": str(analysis_path),
            "matrix_path": str(matrix_path) if matrix_path else "",
            "evidence_mode": mode,
        },
        evidence_ref=str(analysis_path),
        operator=operator,
    )
    run.profile_id = profile_id
    run.notes = "recorded from local analysis output through execution.v1"
    run.save()

    written = 0
    for finding in findings:
        matrix_item = matrix_index.get(_case_key(finding), {})
        verdict = str(finding.get("verdict") or "")
        priority = str(finding.get("priority") or "")
        endpoint_name = str(matrix_item.get("endpointName") or "")
        method = str(matrix_item.get("method") or "")
        owner = matrix_item.get("owner") or {}
        if not method and isinstance(owner, dict):
            method = owner.get("method") or ""
        related_pathid = int(matrix_item.get("pathid") or 0) or _related_pathid(
            matrix_item.get("endpointId"), endpoint_name=endpoint_name, method=method
        ) or None
        record_execution_result(
            run,
            None,
            case_name=str(finding.get("case") or matrix_item.get("case") or ""),
            check_type=check_type,
            target={
                "endpoint_id": matrix_item.get("endpointId"),
                "endpoint_name": endpoint_name,
                "pathid": matrix_item.get("pathid"),
                "victim_index": finding.get("victimIndex"),
                "attacker_index": finding.get("attackerIndex"),
                "victim_param": matrix_item.get("victimParam"),
            },
            method=str(method).upper() if method else "",
            verdict=VERDICT_MAP.get(verdict, verdict or "unknown"),
            priority=priority,
            severity=SEVERITY_MAP.get(priority, priority),
            confidence=0.9 if verdict in {"blocked_http", "blocked_not_found", "blocked_empty", "potential_idor"} else 0.55,
            reason_codes=finding.get("reasons") or [],
            evidence_summary=_summary_evidence(finding, matrix_item, mode=mode),
            evidence_ref=str(matrix_path or analysis_path),
            related_pathid=related_pathid,
        )
        written += 1

    run.status = security_test_run.DONE
    run.summary = analysis_doc.get("summary") or {}
    run.finished_at = dt.datetime.utcnow()
    run.save()

    return {"run_id": str(run.id), "results": written, "summary": analysis_doc.get("summary") or {}}


def main() -> int:
    parser = argparse.ArgumentParser(description="Record security analysis output into api_manger Mongo models.")
    parser.add_argument("--analysis", required=True)
    parser.add_argument("--matrix")
    parser.add_argument("--name", default="")
    parser.add_argument("--profile-id", default="")
    parser.add_argument("--check-type", default="idor")
    parser.add_argument("--mode", choices=["full", "safe"], default="full")
    parser.add_argument("--operator", default="")
    parser.add_argument("--project-id", required=True)
    parser.add_argument("--env-id", default="")
    args = parser.parse_args()

    _ensure_mongo_connection()
    summary = record_run(
        analysis_path=Path(args.analysis),
        matrix_path=Path(args.matrix) if args.matrix else None,
        name=args.name,
        profile_id=args.profile_id,
        check_type=args.check_type,
        mode=args.mode,
        operator=args.operator,
        project_id=args.project_id,
        env_id=args.env_id,
    )
    print(json.dumps(summary, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
