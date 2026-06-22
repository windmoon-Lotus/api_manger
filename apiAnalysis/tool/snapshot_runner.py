"""
Replay request snapshots for stage-2 validation and later tool adapters.

This module keeps execution small and explicit. It replays stored snapshots,
optionally overlays short-lived auth values from local environment variables,
and returns structured evidence without creating vulnerability findings.
"""
import json
import os
import time
from typing import Any, Dict
from urllib.parse import urlencode

from bson import ObjectId

from apiAnalysis.db.collection import request_snapshot
from apiAnalysis.model.model import requests_request
from apiAnalysis.tool.redact import redact_url


def _normalize_body(body):
    if body in [None, {}, ""]:
        return None
    if isinstance(body, bytes):
        return body
    if isinstance(body, list) and all(isinstance(item, int) for item in body):
        try:
            return bytes(body)
        except ValueError:
            return body
    return body


def _headers_with_local_auth(headers):
    result = dict(headers or {})
    authorization = os.getenv("API_MANAGER_AUTHORIZATION")
    cookie = os.getenv("API_MANAGER_AUTH_COOKIE")
    if authorization:
        result["Authorization"] = authorization
    if cookie:
        result["Cookie"] = cookie
    return result


def _request_kwargs(snapshot):
    headers = _headers_with_local_auth(snapshot.headers or {})
    body = _normalize_body(snapshot.body)
    content_type = (snapshot.content_type or headers.get("Content-Type") or headers.get("content-type") or "").lower()
    kwargs: Dict[str, Any] = {"headers": headers}
    if body is None:
        return kwargs
    if isinstance(body, dict) and "application/x-www-form-urlencoded" in content_type:
        kwargs["data"] = urlencode(body, doseq=True)
    elif isinstance(body, dict) and "json" in content_type:
        kwargs["json"] = body
    elif isinstance(body, (dict, list)) and "json" in content_type:
        kwargs["json"] = body
    elif isinstance(body, (dict, list)):
        kwargs["data"] = json.dumps(body, ensure_ascii=False)
    else:
        kwargs["data"] = body
    return kwargs


def replay_snapshot(snapshot, mutation=None):
    """
    Replay one request_snapshot document and return structured evidence.
    """
    if mutation:
        raise NotImplementedError("mutation replay should use standard payload mutator before snapshot persistence")
    started = time.perf_counter()
    try:
        response = requests_request(snapshot.method, snapshot.url, **_request_kwargs(snapshot))
        elapsed_ms = round((time.perf_counter() - started) * 1000, 2)
        expected = snapshot.expected_status_codes or []
        ok = response.status_code in expected if expected else 200 <= response.status_code < 400
        return {
            "snapshot_id": str(snapshot.id),
            "pathid": snapshot.pathid,
            "method": snapshot.method,
            "url": redact_url(snapshot.url),
            "domain": snapshot.domain,
            "status_code": response.status_code,
            "expected_status_codes": expected,
            "ok": ok,
            "elapsed_ms": elapsed_ms,
            "response_len": len(response.content or b""),
            "text_sample": (response.text or "")[:300],
            "error": "",
        }
    except Exception as exc:
        elapsed_ms = round((time.perf_counter() - started) * 1000, 2)
        return {
            "snapshot_id": str(snapshot.id),
            "pathid": snapshot.pathid,
            "method": snapshot.method,
            "url": redact_url(snapshot.url),
            "domain": snapshot.domain,
            "status_code": None,
            "expected_status_codes": snapshot.expected_status_codes or [],
            "ok": False,
            "elapsed_ms": elapsed_ms,
            "response_len": 0,
            "text_sample": "",
            "error": str(exc),
        }


def replay_snapshot_by_id(snapshot_id):
    snapshot = request_snapshot.objects(id=ObjectId(str(snapshot_id))).first()
    if not snapshot:
        return None
    return replay_snapshot(snapshot)


def replay_snapshots(limit=5, domain_regex=None):
    limit = limit if limit and limit > 0 else 5
    query = {}
    if domain_regex:
        query["domain__regex"] = domain_regex
    results = []
    for snapshot in request_snapshot.objects(**query).order_by("-ctime").limit(limit):
        results.append(replay_snapshot(snapshot))
    return results
