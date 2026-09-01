"""Record a locked batch's existing evidence through the common snapshot contract.

This does not replay requests. It creates reproducible snapshots for the exact
asset operations and records sanitized run/results with the private evidence
file as the source of truth.
"""
import argparse
import datetime as dt
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from apiAnalysis.db.collection import ProjectSourceBinding, raw_data, security_test_run
from apiAnalysis.main import _ensure_mongo_connection
from apiAnalysis.tool.execution_contract import (
    ExecutionContext,
    create_execution_run,
    create_execution_snapshot,
    record_execution_result,
)


def verdict_for_sample(sample):
    status = sample.get("status")
    if status in {401, 403}:
        return "no_vuln", ["anonymous_authentication_required"], 0.97
    if sample.get("sensitive_data_suspected"):
        return "need_review", ["anonymous_sensitive_data_suspected"], 0.9
    if status is None:
        return "error", ["transport_error"], 0.8
    if 200 <= int(status) < 300:
        return "need_review", ["anonymous_success_requires_public_data_review"], 0.65
    return "not_evaluable", ["unexpected_anonymous_response"], 0.55


def record_batch(manifest_path, evidence_path, source_type, source_id, check_type, name,
                 auth_mode="anonymous", account_id="", auth_provider_id="",
                 auth_context_ref=""):
    manifest_bytes = Path(manifest_path).read_bytes()
    manifest = json.loads(manifest_bytes.decode("utf-8-sig"))
    evidence = json.loads(Path(evidence_path).read_text(encoding="utf-8-sig"))
    manifest_hash = hashlib.sha256(manifest_bytes).hexdigest().upper()
    binding = ProjectSourceBinding.objects(
        source_type=source_type, source_id=str(source_id), active=True
    ).first()
    if not binding:
        raise ValueError("project source binding not found")
    existing = security_test_run.objects(
        project_id=binding.project_id,
        plan_sha256=manifest_hash,
        adapter_id="locked_snapshot_batch_import",
        evidence_ref=str(evidence_path),
    ).first()
    if existing:
        return {"run_id": str(existing.id), "created": False, "results": 0}

    context = ExecutionContext(
        project_id=binding.project_id,
        env_id=binding.env_id or "",
        account_id=account_id,
        auth_mode=auth_mode,
        auth_provider_id=auth_provider_id,
        auth_context_ref=auth_context_ref,
        adapter_id="locked_snapshot_batch_import",
        adapter_version="1",
        plan_version=str(manifest.get("plan_version") or manifest.get("version") or ""),
        plan_sha256=manifest_hash,
    )
    operations = manifest.get("runtime_operations") or manifest.get("cases") or []
    samples = {str(item.get("endpoint_id")): item for item in evidence.get("representative_samples") or []}
    run = create_execution_run(
        name=name, check_type=check_type, context=context,
        scope={
            "source_type": source_type, "source_id": str(source_id),
            "operation_count": len(operations), "evidence_import_only": True,
            "requests_replayed": 0,
        },
        evidence_ref=str(evidence_path), operator="Sol",
    )
    written = 0
    unresolved = []
    for operation in operations:
        endpoint_ids = operation.get("source_endpoint_ids") or [operation.get("endpoint_id")]
        asset = None
        for endpoint_id in endpoint_ids:
            asset = raw_data.objects(
                project_id=binding.project_id, source=source_type, source_id=str(endpoint_id)
            ).first()
            if asset:
                break
        if not asset:
            unresolved.append(operation.get("endpoint_id"))
            continue
        snapshot = create_execution_snapshot(asset.ptah_id, context, source="locked_batch_evidence_import")
        sample = samples.get(str(operation.get("endpoint_id"))) or {}
        verdict, reasons, confidence = verdict_for_sample(sample)
        record_execution_result(
            run, snapshot,
            case_name="{} {}".format(operation.get("method") or asset.method, operation.get("path") or asset.path),
            check_type=check_type,
            verdict=verdict,
            reason_codes=reasons,
            confidence=confidence,
            evidence_ref=str(evidence_path),
            evidence_summary={
                "endpoint_id": operation.get("endpoint_id"),
                "source_endpoint_ids": endpoint_ids,
                "status": sample.get("status"),
                "cluster": sample.get("cluster"),
                "sensitive_data_suspected": bool(sample.get("sensitive_data_suspected")),
                "evidence_import_only": True,
            },
        )
        written += 1
    run.status = security_test_run.DONE if not unresolved else security_test_run.FAILED
    run.summary = {
        "operations": len(operations), "results": written, "unresolved": unresolved,
        "cluster_counts": evidence.get("cluster_counts") or {},
        "current_run_attempt_count": evidence.get("current_run_attempt_count", 0),
        "cumulative_attempt_count": evidence.get("cumulative_attempt_count", 0),
        "requests_replayed_during_import": 0,
    }
    run.finished_at = dt.datetime.utcnow()
    run.save()
    return {"run_id": str(run.id), "created": True, "results": written, "unresolved": unresolved}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--evidence", required=True)
    parser.add_argument("--source-type", required=True)
    parser.add_argument("--source-id", required=True)
    parser.add_argument("--check-type", default="unauth_access")
    parser.add_argument("--name", required=True)
    parser.add_argument("--auth-mode", choices=["anonymous", "account", "inherit"], default="anonymous")
    parser.add_argument("--account-id", default="")
    parser.add_argument("--auth-provider-id", default="")
    parser.add_argument("--auth-context-ref", default="")
    args = parser.parse_args()
    _ensure_mongo_connection()
    result = record_batch(
        args.manifest, args.evidence, args.source_type, args.source_id,
        args.check_type, args.name, auth_mode=args.auth_mode,
        account_id=args.account_id, auth_provider_id=args.auth_provider_id,
        auth_context_ref=args.auth_context_ref,
    )
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()
