"""Sanitized observation capture and conservative project routing."""
import datetime as dt
import hashlib
import json
from typing import Any, Dict
from urllib.parse import parse_qsl, urlparse

from apiAnalysis.db.collection import (
    DataSource,
    ObservationRoutingDecision,
    ProjectAssetLink,
    ProjectSourceBinding,
    RequestObservation,
    raw_data,
)
from apiAnalysis.project_context import ensure_data_source
from apiAnalysis.tool.api_signature import abstract_signature, body_shape_signature
from apiAnalysis.tool.project_routing import route_observation


def decide_project(method: str, url: str, path: str, signature: str = "",
                   explicit_project_id: str = "", data_source_id: str = ""):
    parsed = urlparse(url or "")
    signature = signature or abstract_signature(method, path or parsed.path)
    assets = [
        {
            "project_id": item.project_id,
            "method": item.method,
            "domain": item.domain,
            "path": item.path,
            "abstract_signature": item.abstract_signature,
        }
        for item in raw_data.objects(
            project_id__nin=["", None], method=str(method or "GET").upper(), abstract_signature=signature
        ).only("project_id", "method", "domain", "path", "abstract_signature")
    ]
    binding_query = ProjectSourceBinding.objects(active=True)
    if data_source_id:
        binding_query = binding_query.filter(data_source_id=str(data_source_id))
    bindings = [
        {"project_id": item.project_id, "routing_rules": item.routing_rules or {}}
        for item in binding_query.only("project_id", "routing_rules")
    ]
    return route_observation(
        {"method": method, "url": url, "path": path, "abstract_signature": signature},
        assets, bindings=bindings, explicit_project_id=explicit_project_id,
    )


def _observation_id(source_type, source_id, method, url, sample_signature=""):
    material = json.dumps(
        [source_type, source_id, str(method).upper(), url, sample_signature],
        ensure_ascii=False, separators=(",", ":"),
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _stored_decision(row):
    return {
        "decision": str(getattr(row, "decision", "") or "unassigned"),
        "selected_project_id": str(
            getattr(row, "selected_project_id", "") or ""
        ),
        "selected_env_id": str(
            getattr(row, "selected_env_id", "") or ""
        ),
        "candidate_projects": list(
            getattr(row, "candidate_projects", None) or []
        ),
        "confidence": float(getattr(row, "confidence", 0.0) or 0.0),
        "reason_codes": list(getattr(row, "reason_codes", None) or []),
        "rule_version": str(getattr(row, "rule_version", "") or "v1"),
    }


def save_observation(*, source_type: str, source_id: str, method: str, url: str, path: str,
                     request_headers=None, request_body=None, response_status=None,
                     response_len=0, response_hash="", workspace_id="", import_run_id="",
                     account_id="", env_id="", sample=None, asset=None,
                     data_source_id="", routing_decision: Dict[str, Any] = None):
    source = DataSource.objects(
        data_source_id=str(data_source_id or "")
    ).first() if data_source_id else None
    if not source:
        external_id = str(workspace_id or source_id or import_run_id or "unknown")
        source = ensure_data_source(
            source_type,
            external_id,
            name="{}:{}".format(source_type, external_id),
            workspace_id=str(workspace_id or ""),
        )
    decision = routing_decision or decide_project(
        method,
        url,
        path,
        data_source_id=source.data_source_id,
    )
    sample_sig = str(getattr(sample, "sample_signature", "") or "")
    observation_id = _observation_id(source_type, source_id, method, url, sample_sig)
    parsed = urlparse(url or "")
    sanitized_url = parsed._replace(query="", fragment="").geturl()
    query_names = sorted({
        str(name)
        for name, _ in parse_qsl(
            parsed.query,
            keep_blank_values=True,
        )
        if name
    })
    signature = abstract_signature(method, path or parsed.path, body=request_body)
    observation = RequestObservation.objects(observation_id=observation_id).first()
    if not observation:
        observation = RequestObservation(
            observation_id=observation_id,
            data_source_id=source.data_source_id,
            source_type=source_type,
            source_id=str(source_id or ""),
            workspace_id=str(workspace_id or ""),
            import_run_id=str(import_run_id or ""),
            account_id=str(account_id or ""),
            env_id=str(env_id or ""),
            method=str(method).upper(),
            url=sanitized_url or path or parsed.path or "/",
            domain=parsed.netloc,
            path=path or parsed.path or "/",
            abstract_signature=signature,
            content_hash=hashlib.sha256((str(method).upper() + " " + url + " " + str(response_hash or "")).encode("utf-8")).hexdigest(),
            request_metadata={
                "header_names": sorted(str(key).lower() for key in (request_headers or {}).keys()),
                "query_names": query_names,
                "body_shape": body_shape_signature(request_body),
            },
            response_metadata={
                "status": response_status,
                "length": int(response_len or 0),
                "hash": str(response_hash or ""),
            },
            sample_id=str(sample.id) if sample and sample.id else "",
            captured_at=dt.datetime.utcnow(),
        )
        observation.save()
    latest = ObservationRoutingDecision.objects(
        observation_id=observation_id,
    ).order_by("-ctime", "-id").first()
    is_manual_final = (
        latest
        and str(latest.rule_version or "").startswith("manual-")
        and latest.decision in {
            ObservationRoutingDecision.ASSIGNED,
            ObservationRoutingDecision.IGNORED,
        }
    )
    if is_manual_final:
        decision = _stored_decision(latest)
    else:
        rule_version = str(decision.get("rule_version") or "v1")
        stored = ObservationRoutingDecision.objects(
            observation_id=observation_id,
            rule_version=rule_version,
        ).first()
        if stored:
            decision = _stored_decision(stored)
        else:
            stored = ObservationRoutingDecision(
                observation_id=observation_id,
                selected_project_id=decision.get(
                    "selected_project_id",
                ) or "",
                selected_env_id=decision.get("selected_env_id") or "",
                candidate_projects=decision.get(
                    "candidate_projects",
                ) or [],
                confidence=float(decision.get("confidence") or 0),
                reason_codes=decision.get("reason_codes") or [],
                decision=decision.get("decision") or "unassigned",
                rule_version=rule_version,
                ctime=dt.datetime.utcnow(),
            )
            stored.save()
    project_id = str(decision.get("selected_project_id") or "")
    if project_id and asset:
        if not asset.project_id:
            raw_data.objects(pk=asset.pk).update_one(
                set__project_id=project_id, set__env_id=str(env_id or ""),
                set__import_run_id=str(import_run_id or ""),
            )
        ProjectAssetLink.objects(project_id=project_id, pathid=int(asset.ptah_id), env_id=str(env_id or "")).update_one(
            set__relationship="observed", set__confidence=float(decision.get("confidence") or 0),
            set__reason_codes=decision.get("reason_codes") or [], add_to_set__observation_ids=observation_id,
            set__mtime=dt.datetime.utcnow(), upsert=True,
        )
        if sample:
            sample.project_id = project_id
            sample.env_id = str(env_id or "")
            sample.account_id = str(account_id or "")
            sample.import_run_id = str(import_run_id or "")
            sample.observation_id = observation_id
            sample.save()
    return observation, decision
