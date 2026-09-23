"""
Replay request snapshots for stage-2 validation and later tool adapters.

This module keeps execution small and explicit. It replays stored snapshots,
optionally overlays short-lived auth values from local environment variables,
and returns structured evidence without creating vulnerability findings.
"""
import json
import hashlib
import os
import time
from typing import Any, Dict
from urllib.parse import parse_qsl, urlencode, urlsplit

from bson import ObjectId

from apiAnalysis.db.collection import request_snapshot
from apiAnalysis.model.model import requests_request
from apiAnalysis.tool.account_context import AccountContext, AccountContextInvalid, AccountContextRef
from apiAnalysis.tool.redact import redact_url
from apiAnalysis.tool.request_evidence_preview import request_evidence_preview


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


def _strip_auth(headers):
    def is_auth_header(name):
        lowered = str(name).strip().lower().replace("_", "-")
        return (
            lowered in {
                "authorization", "cookie", "proxy-authorization", "x-api-key", "api-key",
                "x-auth-token", "x-access-token", "access-token", "token", "jwt",
                "session", "sessionid", "x-csrf-token", "x-xsrf-token",
            }
            or "authorization" in lowered
            or lowered.endswith("-token")
            or lowered.endswith("-api-key")
        )
    return {
        key: value for key, value in dict(headers or {}).items()
        if not is_auth_header(key)
    }


def _headers_with_local_auth(headers, auth_mode="inherit", account_context=None):
    if auth_mode == "anonymous":
        return _strip_auth(headers)
    if auth_mode not in {"inherit", "account"}:
        raise ValueError("unsupported auth_mode: {}".format(auth_mode))
    if auth_mode == "account":
        if not isinstance(account_context, AccountContext):
            raise AccountContextInvalid("account auth requires an in-memory account context")
        result = _strip_auth(headers)
        result.update(dict(account_context.headers))
        return result
    result = dict(headers or {})
    authorization = os.getenv("API_MANAGER_AUTHORIZATION")
    cookie = os.getenv("API_MANAGER_AUTH_COOKIE")
    if authorization:
        result["Authorization"] = authorization
    if cookie:
        result["Cookie"] = cookie
    return result


def _validated_request_options(request_options=None):
    options = dict(request_options or {})
    unsupported = set(options) - {"timeout", "allow_redirects"}
    if unsupported:
        raise ValueError("unsupported request options: {}".format(",".join(sorted(unsupported))))
    if "timeout" in options:
        timeout = float(options["timeout"])
        if not 1 <= timeout <= 300:
            raise ValueError("timeout must be between 1 and 300 seconds")
        options["timeout"] = timeout
    if "allow_redirects" in options:
        if not isinstance(options["allow_redirects"], bool):
            raise ValueError("allow_redirects must be a boolean")
    return options


def _validated_account_context(snapshot, auth_mode, account_context):
    if auth_mode != "account":
        return None
    if not isinstance(account_context, AccountContext):
        raise AccountContextInvalid("account auth requires an in-memory account context")
    reference = AccountContextRef(
        project_id=str(getattr(snapshot, "project_id", "") or account_context.project_id),
        env_id=str(getattr(snapshot, "env_id", "") or account_context.env_id),
        account_id=str(getattr(snapshot, "account_id", "") or account_context.account_id),
        provider_id=str(getattr(snapshot, "auth_provider_id", "") or account_context.provider_id),
        context_ref=str(getattr(snapshot, "auth_context_ref", "") or account_context.context_ref),
    )
    host = str(getattr(snapshot, "domain", "") or urlsplit(str(snapshot.url)).hostname or "")
    return account_context.validate(reference, host=host)


def _body_size(body):
    if body is None:
        return 0
    if isinstance(body, bytes):
        return len(body)
    if isinstance(body, str):
        return len(body.encode("utf-8"))
    try:
        return len(body)
    except TypeError:
        return 0


def _cookie_names(cookie_header):
    return sorted({
        part.split("=", 1)[0].strip()
        for part in str(cookie_header or "").split(";")
        if "=" in part and part.split("=", 1)[0].strip()
    })


def _json_shape(value):
    """Return bounded schema metadata without retaining response values."""
    summary = {
        "response_record_count": None,
        "response_collection_path": "",
        "response_top_level_keys": [],
        "response_field_names": [],
    }
    if isinstance(value, list):
        summary["response_record_count"] = len(value)
        summary["response_collection_path"] = "$"
        first = value[0] if value else None
        if isinstance(first, dict):
            summary["response_field_names"] = sorted(str(key)[:100] for key in first)[:60]
        return summary
    if not isinstance(value, dict):
        return summary

    summary["response_top_level_keys"] = sorted(str(key)[:100] for key in value)[:60]
    candidates = []
    for key, item in value.items():
        if isinstance(item, list):
            candidates.append(("$.{}".format(str(key)[:100]), item))
        elif isinstance(item, dict):
            for nested_key, nested_item in item.items():
                if isinstance(nested_item, list):
                    candidates.append((
                        "$.{}.{}".format(str(key)[:100], str(nested_key)[:100]),
                        nested_item,
                    ))
    if not candidates:
        return summary
    path, records = max(candidates, key=lambda candidate: len(candidate[1]))
    summary["response_record_count"] = len(records)
    summary["response_collection_path"] = path
    first = records[0] if records else None
    if isinstance(first, dict):
        summary["response_field_names"] = sorted(str(key)[:100] for key in first)[:60]
    return summary


def _response_trace_ids(response):
    """Collect only bounded correlation identifiers from response headers."""
    allowed = {
        "traceid", "trace-id", "x-trace-id", "x-request-id", "request-id",
        "x-correlation-id", "correlation-id",
    }
    result = []
    for name, value in dict(getattr(response, "headers", {}) or {}).items():
        if str(name).strip().lower() not in allowed:
            continue
        value = str(value or "").strip()[:200]
        if value.lower() in {"n/a", "none", "null", "unknown", "-"}:
            continue
        if value and value not in result:
            result.append(value)
    return result[:10]


def _request_summary(snapshot, request_kwargs, response=None, account_context=None):
    """Describe the prepared request without exposing header, cookie or body values."""
    prepared = getattr(response, "request", None)
    prepared_url = str(getattr(prepared, "url", "") or snapshot.url or "")
    parsed = urlsplit(prepared_url)
    prepared_headers = dict(getattr(prepared, "headers", {}) or {})
    request_headers = prepared_headers or dict(request_kwargs.get("headers") or {})
    cookie_names = set((request_kwargs.get("cookies") or {}).keys())
    cookie_names.update(_cookie_names(request_headers.get("Cookie") or request_headers.get("cookie")))
    body = getattr(prepared, "body", None)
    if prepared is None:
        body = request_kwargs.get("json", request_kwargs.get("data"))
    context_metadata = dict(getattr(account_context, "metadata", {}) or {})
    return {
        "request_method": str(getattr(prepared, "method", "") or snapshot.method or "").upper(),
        "request_origin": "{}://{}".format(parsed.scheme, parsed.netloc)
        if parsed.scheme and parsed.netloc else "",
        "request_path": parsed.path or str(getattr(snapshot, "path", "") or ""),
        "request_query_names": sorted({
            name for name, _value in parse_qsl(parsed.query, keep_blank_values=True)
        }),
        "request_header_names": sorted(str(name) for name in request_headers),
        "request_cookie_names": sorted(str(name) for name in cookie_names),
        "request_auth_header_names": sorted(
            str(name) for name in getattr(account_context, "headers", {})
        ),
        "request_auth_cookie_names": sorted(
            str(name) for name in getattr(account_context, "cookies", {})
        ),
        "request_body_bytes": _body_size(body),
        "request_content_type": str(
            request_headers.get("Content-Type") or request_headers.get("content-type") or ""
        ).split(";", 1)[0].strip().lower(),
        "request_timeout_seconds": request_kwargs.get("timeout"),
        "request_allow_redirects": bool(request_kwargs.get("allow_redirects", False)),
        "request_tls_verify": bool(request_kwargs.get("verify", True)),
        "auth_request_count": max(0, int(context_metadata.get("auth_request_count") or 0)),
    }


def _request_kwargs(snapshot, auth_mode=None, request_options=None, account_context=None):
    mode = auth_mode or getattr(snapshot, "auth_mode", None) or "inherit"
    account_context = _validated_account_context(snapshot, mode, account_context)
    headers = _headers_with_local_auth(
        snapshot.headers or {}, auth_mode=mode, account_context=account_context,
    )
    body = _normalize_body(snapshot.body)
    content_type = (snapshot.content_type or headers.get("Content-Type") or headers.get("content-type") or "").lower()
    kwargs: Dict[str, Any] = {"headers": headers}
    if mode == "inherit" and getattr(snapshot, "cookies", None):
        kwargs["cookies"] = dict(snapshot.cookies)
    elif mode == "account" and account_context.cookies:
        kwargs["cookies"] = dict(account_context.cookies)
    kwargs.update(_validated_request_options(request_options))
    kwargs["verify"] = bool(
        dict(getattr(account_context, "metadata", {}) or {}).get("tls_verify", True)
    )
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


def _replay_snapshot(snapshot, mutation=None, auth_mode=None, request_options=None,
                     account_context=None, capture_json=False,
                     request_trace_callback=None, request_trace_phase="request",
                     response_text_callback=None):
    if mutation:
        raise NotImplementedError("mutation replay should use standard payload mutator before snapshot persistence")
    started = time.perf_counter()
    captured_json = None
    request_kwargs = {}
    try:
        effective_auth_mode = auth_mode or getattr(snapshot, "auth_mode", None) or "inherit"
        validated_context = _validated_account_context(
            snapshot, effective_auth_mode, account_context,
        )
        request_kwargs = _request_kwargs(
            snapshot,
            auth_mode=effective_auth_mode,
            request_options=request_options,
            account_context=validated_context,
        )
        if request_trace_callback is not None:
            request_trace_callback(request_evidence_preview(
                snapshot, request_kwargs, phase=request_trace_phase,
            ))
        response = requests_request(
            snapshot.method,
            snapshot.url,
            **request_kwargs
        )
        elapsed_ms = round((time.perf_counter() - started) * 1000, 2)
        if response_text_callback is not None:
            # Hand the caller the response text it asked for.  The text never
            # enters `evidence`, so body-free evidence stays body-free; and a
            # consumer failure must not alter request execution.
            try:
                response_text_callback(response.text or "")
            except Exception:
                pass
        expected = snapshot.expected_status_codes or []
        ok = response.status_code in expected if expected else 200 <= response.status_code < 400
        content = response.content or b""
        content_type = str(response.headers.get("Content-Type") or "").split(";", 1)[0].strip().lower()
        json_type = ""
        if "json" in content_type and content:
            if len(content) > 2 * 1024 * 1024:
                json_type = "large"
            else:
                try:
                    captured_json = response.json()
                    if isinstance(captured_json, dict):
                        json_type = "object"
                    elif isinstance(captured_json, list):
                        json_type = "list"
                    elif captured_json is None:
                        json_type = "null"
                    else:
                        json_type = "scalar"
                except Exception:
                    json_type = "invalid"
        evidence = {
            "snapshot_id": str(snapshot.id),
            "pathid": snapshot.pathid,
            "method": snapshot.method,
            "url": redact_url(snapshot.url),
            "domain": snapshot.domain,
            "project_id": getattr(snapshot, "project_id", "") or "",
            "auth_mode": effective_auth_mode,
            "status_code": response.status_code,
            "expected_status_codes": expected,
            "ok": ok,
            "elapsed_ms": elapsed_ms,
            "response_len": len(content),
            "response_sha256": hashlib.sha256(content).hexdigest(),
            "response_content_type": content_type,
            "response_json_type": json_type,
            "trace_ids": _response_trace_ids(response),
            "text_sample": (response.text or "")[:300],
            "error": "",
            "error_type": "",
            **_request_summary(
                snapshot, request_kwargs, response=response,
                account_context=validated_context,
            ),
            **_json_shape(captured_json),
        }
        return (evidence, captured_json) if capture_json else evidence
    except Exception as exc:
        elapsed_ms = round((time.perf_counter() - started) * 1000, 2)
        effective_auth_mode = auth_mode or getattr(snapshot, "auth_mode", None) or "inherit"
        evidence = {
            "snapshot_id": str(snapshot.id),
            "pathid": snapshot.pathid,
            "method": snapshot.method,
            "url": redact_url(snapshot.url),
            "domain": snapshot.domain,
            "project_id": getattr(snapshot, "project_id", "") or "",
            "auth_mode": effective_auth_mode,
            "status_code": None,
            "expected_status_codes": snapshot.expected_status_codes or [],
            "ok": False,
            "elapsed_ms": elapsed_ms,
            "response_len": 0,
            "response_sha256": "",
            "response_content_type": "",
            "response_json_type": "",
            "text_sample": "",
            "error": str(exc),
            "error_type": exc.__class__.__name__,
            **_request_summary(
                snapshot, request_kwargs, account_context=account_context,
            ),
        }
        return (evidence, None) if capture_json else evidence


def replay_snapshot(snapshot, mutation=None, auth_mode=None, request_options=None,
                    account_context=None, request_trace_callback=None,
                    request_trace_phase="request", response_text_callback=None):
    """Replay one request snapshot and return body-free structured evidence."""
    return _replay_snapshot(
        snapshot,
        mutation=mutation,
        auth_mode=auth_mode,
        request_options=request_options,
        account_context=account_context,
        capture_json=False,
        request_trace_callback=request_trace_callback,
        request_trace_phase=request_trace_phase,
        response_text_callback=response_text_callback,
    )


def replay_snapshot_with_json(snapshot, mutation=None, auth_mode=None,
                              request_options=None, account_context=None,
                              request_trace_callback=None,
                              request_trace_phase="request",
                              response_text_callback=None):
    """Replay for an in-process dependency adapter.

    The parsed JSON value is returned only to the caller and must not be placed
    in scheduler evidence, logs or persistent result documents.
    """
    return _replay_snapshot(
        snapshot,
        mutation=mutation,
        auth_mode=auth_mode,
        request_options=request_options,
        account_context=account_context,
        capture_json=True,
        request_trace_callback=request_trace_callback,
        request_trace_phase=request_trace_phase,
        response_text_callback=response_text_callback,
    )


def replay_snapshot_by_id(snapshot_id, **kwargs):
    snapshot = request_snapshot.objects(id=ObjectId(str(snapshot_id))).first()
    if not snapshot:
        return None
    return replay_snapshot(snapshot, **kwargs)


def replay_snapshots(limit=5, domain_regex=None):
    limit = limit if limit and limit > 0 else 5
    query = {}
    if domain_regex:
        query["domain__regex"] = domain_regex
    results = []
    for snapshot in request_snapshot.objects(**query).order_by("-ctime").limit(limit):
        results.append(replay_snapshot(snapshot))
    return results
