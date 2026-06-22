"""
Compose executable requests from parsed parameters.
"""
import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from typing import Dict, Any
from apiAnalysis.db.collection import (
    raw_data,
    req_data,
    parameter_archive,
    parameter_data,
    generate_req,
    parameter_relation,
    request_snapshot,
)
from apiAnalysis.tool.parameter_dependency import resolve_parameter_value
from apiAnalysis.tool.request_sample_store import best_request_sample
from apiAnalysis.tool.tool import unflatten_json


def _select_value(values):
    if not values:
        return None
    if isinstance(values, list):
        return values[0]
    return values


def _lookup_archive_value(parameter_name, pathid, account_id=None):
    query = {"parameter": parameter_name, "req_pathid__contains": pathid}
    if account_id:
        query["account_id"] = account_id
    entry = parameter_archive.objects(**query).first()
    if not entry and account_id:
        entry = parameter_archive.objects(parameter=parameter_name, req_pathid__contains=pathid).first()
    if entry and entry.req_value:
        return _select_value(entry.req_value)
    return None


def _normalize_parameter_name(name):
    sheer_parameter = name.split(".")[-1]
    if re.match(r'^\d+$', sheer_parameter) and len(name.split(".")) > 1:
        sheer_parameter = ".".join(name.split(".")[-2:])
    return sheer_parameter


def _relation_value(parameter_name, pathid):
    relation = parameter_relation.objects(parameter=parameter_name, req_pathid=pathid).first()
    if relation and relation.evidence:
        return relation.evidence[0]
    return None


def _resolve_dependency_value(parameter_name, pathid, account_id=None):
    value, meta = resolve_parameter_value(parameter_name, pathid, account_id=account_id)
    if value in (None, "", [], {}):
        return None, meta
    return value, meta


def _normalize_headers(headers):
    result = {}
    for key, value in (headers or {}).items():
        if isinstance(value, list):
            result[key] = value[0] if value else ""
        else:
            result[key] = value
    result.pop("Content-Length", None)
    result.pop("content-length", None)
    return result


def _header_value(headers, name):
    for key, value in (headers or {}).items():
        if str(key).lower() == name.lower():
            return value
    return None


def _merge_url_query(url, query):
    if not query:
        return url
    split = urlsplit(url or "")
    pairs = parse_qsl(split.query, keep_blank_values=True)
    replace_keys = {str(key) for key in query.keys()}
    pairs = [(key, value) for key, value in pairs if key not in replace_keys]
    for key, value in query.items():
        if isinstance(value, list):
            pairs.extend((key, item) for item in value)
        else:
            pairs.append((key, value))
    return urlunsplit((split.scheme, split.netloc, split.path, urlencode(pairs, doseq=True), split.fragment))


def render_request_url(payload: Dict[str, Any]) -> str:
    url = payload.get("url") or ""
    for key, value in (payload.get("path_params") or {}).items():
        url = url.replace("{" + key + "}", str(value))
        url = url.replace(":" + key, str(value))
    return _merge_url_query(url, payload.get("query") or {})


def build_request_payload(pathid: int, account_id: str = None, env_id: str = None, source: str = "asset") -> Dict[str, Any]:
    data = raw_data.objects(ptah_id=pathid).first()
    if not data:
        return {}

    req_entries = list(req_data.objects(raw_data=data))
    sample = best_request_sample(data)
    base_url = sample.url if sample else data.url
    base_query = sample.query if sample else data.query
    base_headers = sample.headers if sample else data.headers
    base_body = sample.body if sample else (data.raw_req[0] if data.raw_req else None)
    base_response_sample = sample.response_sample if sample else (data.raw_res[0] if data.raw_res else None)
    expected_status_codes = []
    if sample and sample.response_status_code is not None:
        expected_status_codes = [sample.response_status_code]
    else:
        expected_status_codes = data.response_status_code or []
    query_params = {}
    header_params = _normalize_headers(base_headers)
    path_params = {}
    body_params = {}
    content_type = _header_value(header_params, "content-type")
    parameter_sources = {}

    for entry in req_entries:
        name = entry.parameter
        if not name:
            continue
        value = _select_value(entry.value)
        value_source = "req_data"
        dependency_meta = {}
        if value is None:
            value, dependency_meta = _resolve_dependency_value(name, pathid, account_id=account_id)
            value_source = dependency_meta.get("source") or "parameter_dependency"
        if value is None:
            value = _relation_value(name, pathid)
            value_source = "parameter_relation"
        if value is None:
            value = _lookup_archive_value(name, pathid, account_id=account_id)
            value_source = "parameter_archive"
        if value is None:
            value = ""
            value_source = "empty_default"
        position = entry.position or "body"
        content_type = entry.Content_type or content_type
        parameter_sources[name] = {
            "position": position,
            "source": value_source,
            "required": bool(entry.required),
            "type": entry.type or "",
            "dependency": dependency_meta,
        }
        if position == "query":
            query_params[name] = value
        elif position == "header":
            header_params[name] = value
        elif position == "path":
            path_params[name] = value
        else:
            body_params[name] = value

    body = unflatten_json(body_params) if body_params else {}
    payload = {
        "pathid": data.ptah_id,
        "raw_id": str(data.id),
        "source": source,
        "env_id": env_id or "",
        "account_id": account_id or "",
        "method": (data.method or "GET").upper(),
        "url": base_url,
        "rendered_url": "",
        "path": data.path,
        "domain": data.domain,
        "content_type": content_type or "application/json",
        "query": query_params or (base_query or {}),
        "headers": header_params,
        "cookies": {},
        "path_params": path_params,
        "body": body,
        "raw_body_sample": base_body,
        "response_sample": base_response_sample,
        "expected_status_codes": expected_status_codes,
        "parameter_sources": parameter_sources,
        "metadata": {
            "action": data.action or "",
            "rule": data.rule or "",
            "tags": data.tags or "",
            "description": data.des or "",
            "sample_id": str(sample.id) if sample else "",
        },
    }
    payload["rendered_url"] = render_request_url(payload)
    return payload


def payload_to_snapshot_data(payload: Dict[str, Any], data=None) -> Dict[str, Any]:
    return {
        "pathid": payload.get("pathid"),
        "raw_data": data,
        "source": payload.get("source") or "asset",
        "env_id": payload.get("env_id") or "",
        "account_id": payload.get("account_id") or "",
        "method": payload.get("method") or "GET",
        "url": payload.get("rendered_url") or payload.get("url") or "",
        "path": payload.get("path") or "",
        "domain": payload.get("domain") or "",
        "query": payload.get("query") or {},
        "headers": payload.get("headers") or {},
        "cookies": payload.get("cookies") or {},
        "path_params": payload.get("path_params") or {},
        "body": payload.get("body") if payload.get("body") not in [None, {}] else payload.get("raw_body_sample"),
        "content_type": payload.get("content_type") or "application/json",
        "expected_status_codes": payload.get("expected_status_codes") or [],
        "parameter_sources": payload.get("parameter_sources") or {},
        "metadata": payload.get("metadata") or {},
    }


def create_request_snapshot(pathid: int, account_id: str = None, env_id: str = None, source: str = "asset"):
    data = raw_data.objects(ptah_id=pathid).first()
    payload = build_request_payload(pathid, account_id=account_id, env_id=env_id, source=source)
    if not data or not payload:
        return None
    snapshot_data = payload_to_snapshot_data(payload, data=data)
    snapshot = request_snapshot(**snapshot_data)
    snapshot.save()
    return snapshot


def build_compose_record(pathid: int):
    data = raw_data.objects(ptah_id=pathid).first()
    if not data:
        return None
    parameters = []
    parameterids = []
    content_type = None
    for entry in req_data.objects(raw_data=data):
        if not entry.parameter:
            continue
        parameters.append(entry.parameter)
        content_type = entry.Content_type or content_type
        pdata = parameter_data.objects(parameter=entry.parameter).first()
        if pdata:
            parameterids.append(pdata.parameterid)
    record = generate_req.objects(pathid=pathid).first()
    if not record:
        record = generate_req(pathid=pathid)
    record.parameters = list(set(parameters))
    record.parameterids = list(set(parameterids))
    record.Content_type = content_type
    record.save()
    return record
