#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Converts a mitmproxy dump file to a swagger schema."""
import json
import re
from urllib.parse import urlparse, urlencode
from bson.objectid import ObjectId
from pymongo import UpdateOne
from typing import Any, Optional, Sequence, Union, Iterable, Dict, List
# from swagger_utilbak import getworkbook,reverse_jsonpath
import openpyxl
from hashlib import md5

from apiAnalysis.tool.tool import *
from apiAnalysis.tool.api_signature import abstract_signature, api_signature_object_id
from apiAnalysis.tool.request_sample_store import save_request_sample
from mitmproxy.exceptions import FlowReadException
import apiAnalysis.tool.console_util as console_util
from apiAnalysis.db.collection import *
from apiAnalysis.conf.conf import logger
from apiAnalysis.input.har_capture_reader import HarCaptureReader, har_archive_heuristic
from apiAnalysis.input.mitmproxy_capture_reader import (
    MitmproxyCaptureReader,
    mitmproxy_dump_file_huristic,
)


def get_next_sequence(collection_name):
    """
    使用MongoEngine从counters集合获取下一个自增ID。
    """
    result = Counter.objects(_id=collection_name).modify(
        upsert=True, new=True, inc__sequence_value=1
    )

    # 确保 result 是 Counter 对象而不是字符串
    if isinstance(result, Counter):
        return result.sequence_value
    else:
        raise ValueError(f"Expected Counter object but got {type(result).__name__}")


def allocate_sequence_range(collection_name, count):
    if count <= 0:
        return []
    result = Counter.objects(_id=collection_name).modify(
        upsert=True, new=True, inc__sequence_value=count
    )
    if not isinstance(result, Counter):
        raise ValueError(f"Expected Counter object but got {type(result).__name__}")
    start = result.sequence_value - count + 1
    return list(range(start, result.sequence_value + 1))


_LAST_PROGRESS_STEP = -1
_PROGRESS_OUTPUT_ENABLED = True
MAX_PARAMETER_VALUES = 20
MAX_RESPONSE_PARAMETER_VALUES = 5


def set_progress_output_enabled(enabled: bool):
    global _PROGRESS_OUTPUT_ENABLED, _LAST_PROGRESS_STEP
    _PROGRESS_OUTPUT_ENABLED = bool(enabled)
    _LAST_PROGRESS_STEP = -1


def progress_callback(progress):
    """
    Throttle terminal updates to reduce stdout overhead on large imports.
    """
    if not _PROGRESS_OUTPUT_ENABLED:
        return
    global _LAST_PROGRESS_STEP
    step = int(max(0.0, min(1.0, float(progress))) * 100)
    if step == _LAST_PROGRESS_STEP:
        return
    _LAST_PROGRESS_STEP = step
    console_util.print_progress_bar(progress)


def _is_path_param(segment):
    if not segment:
        return False
    if segment.isdigit():
        return True
    if re.match(r"^[0-9a-fA-F]{8,}$", segment):
        return True
    if re.match(r"^[0-9a-fA-F-]{8,}$", segment) and any(ch.isdigit() for ch in segment):
        return True
    return False


def _extract_path_params(url):
    parsed = urlparse(url)
    parts = [p for p in parsed.path.split("/") if p]
    params = []
    for idx, segment in enumerate(parts, start=1):
        if _is_path_param(segment):
            params.append((f"path_param_{idx}", segment))
    return params


def _resolve_ref(ref, components):
    if not ref or not components:
        return None
    if not ref.startswith("#/"):
        return None
    parts = ref.lstrip("#/").split("/")
    node = components
    for part in parts:
        if isinstance(node, dict):
            node = node.get(part)
        else:
            return None
    return node


def _flatten_schema(schema, components, parent_key=""):
    if not schema:
        return []
    if "$ref" in schema:
        schema = _resolve_ref(schema.get("$ref"), components) or {}
    names = []
    if "allOf" in schema:
        for item in schema.get("allOf", []):
            names.extend(_flatten_schema(item, components, parent_key))
        return names
    if "oneOf" in schema:
        for item in schema.get("oneOf", []):
            names.extend(_flatten_schema(item, components, parent_key))
        return names
    if "anyOf" in schema:
        for item in schema.get("anyOf", []):
            names.extend(_flatten_schema(item, components, parent_key))
        return names
    schema_type = schema.get("type")
    properties = schema.get("properties", {})
    if schema_type == "object" or properties:
        for key, subschema in properties.items():
            new_key = f"{parent_key}.{key}" if parent_key else key
            names.extend(_flatten_schema(subschema, components, new_key))
        if not properties and parent_key:
            names.append(parent_key)
        return names
    if schema_type == "array":
        item_schema = schema.get("items", {})
        array_key = f"{parent_key}[]" if parent_key else "[]"
        nested = _flatten_schema(item_schema, components, array_key)
        return nested if nested else ([array_key] if parent_key else [])
    if parent_key:
        names.append(parent_key)
    return names


def _normalize_base_url(base_url):
    base_url = (base_url or "").strip().rstrip("/")
    if not base_url:
        return ""
    if "://" not in base_url:
        base_url = "https://" + base_url
    return base_url


def _join_base_url(base_url, path):
    base_url = _normalize_base_url(base_url)
    if not base_url:
        return path
    return base_url + "/" + str(path or "").lstrip("/")


def _openapi_servers(openapi_doc, base_url=None):
    override = _normalize_base_url(base_url)
    if override:
        return override
    servers = openapi_doc.get("servers", [])
    if not servers:
        return ""
    url = servers[0].get("url", "")
    if "{" in url and "}" in url:
        url = url.split("{")[0].rstrip("/")
    return _normalize_base_url(url)


def _openapi_parameters(path_item, operation):
    params = []
    for entry in path_item.get("parameters", []):
        params.append(entry)
    for entry in operation.get("parameters", []):
        params.append(entry)
    seen = set()
    unique = []
    for param in params:
        key = (param.get("name"), param.get("in"))
        if key in seen:
            continue
        seen.add(key)
        unique.append(param)
    return unique


def _ensure_raw_data(path, method, base_url, response_status_codes):
    query = {}
    request_body = None
    full_url = _join_base_url(base_url, path)
    parsed = urlparse(full_url)
    abstract_sig = abstract_signature(method, path, query, request_body)
    _id = ObjectId(api_signature_object_id(method, full_url, path, query, request_body, host=parsed.netloc, asset_kind="abstract"))
    data = raw_data.objects(_id=_id).first()
    if data:
        data.asset_kind = data.asset_kind or "abstract"
        data.abstract_signature = data.abstract_signature or abstract_sig
        if response_status_codes:
            merged_codes = list(data.response_status_code or [])
            for code in response_status_codes:
                if code not in merged_codes:
                    merged_codes.append(code)
            data.response_status_code = merged_codes
        data.save()
        return data
    domain = None
    url = full_url
    if base_url:
        domain = parsed.netloc
    data = raw_data(
        _id=_id,
        method=method,
        asset_kind="abstract",
        abstract_signature=abstract_sig,
        domain=domain,
        path=path,
        url=url,
        ptah_id=get_next_sequence("raw_data"),
        query=query,
        headers={},
        raw_req=[],
        raw_res=[],
        Max_records=10,
        response_status_code=response_status_codes
    )
    data.save()
    return data


def data_generate_openapi(file_path, base_url=None):
    with open(file_path, "r", encoding="utf-8") as f:
        openapi_doc = json.load(f)
    components = openapi_doc.get("components", {})
    base_url = _openapi_servers(openapi_doc, base_url=base_url)
    paths = openapi_doc.get("paths", {})
    for path, operations in paths.items():
        if not isinstance(operations, dict):
            continue
        for method, operation in operations.items():
            if method.lower() not in ["get", "post", "put", "delete", "patch", "head", "options"]:
                continue
            parameters = _openapi_parameters(operations, operation)
            responses = operation.get("responses", {})
            response_status_codes = []
            for code in responses.keys():
                if str(code).isdigit():
                    response_status_codes.append(int(code))
            data = _ensure_raw_data(path, method.upper(), base_url, response_status_codes)
            for param in parameters:
                name = param.get("name")
                position = param.get("in")
                if not name or not position:
                    continue
                required = param.get("required", False)
                content_type = position
                datastore = req_data.objects(parameter=name, raw_data=data, position=position).first()
                if datastore is None:
                    Req_data = req_data(
                        raw_data=data,
                        Content_type=content_type,
                        parameter=name,
                        position=position,
                        relation="any",
                        required=required,
                        value=[]
                    )
                    Req_data.save()
            request_body = operation.get("requestBody", {})
            content = request_body.get("content", {})
            for content_type, body_info in content.items():
                schema = body_info.get("schema", {})
                for name in _flatten_schema(schema, components):
                    datastore = req_data.objects(parameter=name, raw_data=data, position="body").first()
                    if datastore is None:
                        Req_data = req_data(
                            raw_data=data,
                            Content_type=content_type,
                            parameter=name,
                            position="body",
                            relation="any",
                            required=False,
                            value=[]
                        )
                        Req_data.save()
            for status, resp in responses.items():
                content = resp.get("content", {})
                for content_type, resp_info in content.items():
                    schema = resp_info.get("schema", {})
                    for name in _flatten_schema(schema, components):
                        datastore = res_data.objects(parameter=name, raw_data=data, position="body").first()
                        if datastore is None:
                            Res_data = res_data(
                                raw_data=data,
                                Content_type=content_type,
                                parameter=name,
                                position="body",
                                relation="any",
                                value=[]
                            )
                            Res_data.save()


def _postman_iter_items(items):
    for item in items:
        if "item" in item:
            yield from _postman_iter_items(item.get("item", []))
        else:
            yield item


def data_generate_postman(file_path, base_url=None):
    base_url = _normalize_base_url(base_url)
    with open(file_path, "r", encoding="utf-8") as f:
        postman_doc = json.load(f)
    for item in _postman_iter_items(postman_doc.get("item", [])):
        request = item.get("request", {})
        method = request.get("method")
        url_info = request.get("url")
        if not method or not url_info:
            continue
        if isinstance(url_info, dict):
            raw_url = url_info.get("raw")
        else:
            raw_url = url_info
        if not raw_url:
            continue
        parsed = urlparse(raw_url)
        if base_url and not parsed.netloc:
            raw_url = _join_base_url(base_url, raw_url)
            parsed = urlparse(raw_url)
        path = parsed.path or "/"
        query = {}
        if isinstance(url_info, dict):
            for q in url_info.get("query", []) or []:
                if "key" in q:
                    query[q["key"]] = q.get("value")
        else:
            query = extract_url_params(raw_url)[1]
        headers = {}
        for h in request.get("header", []) or []:
            if "key" in h:
                headers[h["key"]] = [h.get("value")]
        body = request.get("body", {})
        request_body = None
        if body:
            mode = body.get("mode")
            if mode == "raw":
                request_body = body.get("raw")
            elif mode == "urlencoded":
                pairs = []
                for p in body.get("urlencoded", []) or []:
                    if "key" in p:
                        pairs.append((p["key"], p.get("value")))
                request_body = urlencode(pairs)
        abstract_sig = abstract_signature(method, path, query, request_body)
        _id = ObjectId(api_signature_object_id(method, raw_url, path, query, request_body, host=parsed.netloc, asset_kind="concrete"))
        data = raw_data.objects(_id=_id).first()
        if data:
            if not data.url:
                data.url = raw_url
            if not data.domain:
                data.domain = parsed.netloc
            if not data.query:
                data.query = query
            if not data.headers:
                data.headers = headers
            if not data.Max_records:
                data.Max_records = 10
            data.asset_kind = data.asset_kind or "concrete"
            data.abstract_signature = data.abstract_signature or abstract_sig
            if request_body and len(data.raw_req) < data.Max_records:
                data.raw_req.append(request_body)
            data.save()
            continue
        data = raw_data(
            _id=_id,
            asset_kind="concrete",
            abstract_signature=abstract_sig,
            method=method.upper(),
            domain=parsed.netloc,
            path=path,
            url=raw_url,
            ptah_id=get_next_sequence("raw_data"),
            query=query,
            headers=headers,
            raw_req=[request_body] if request_body else [],
            raw_res=[],
            Max_records=10,
            response_status_code=[]
        )
        data.save()
        save_request_sample(
            data,
            method=method,
            url=raw_url,
            path=path,
            domain=parsed.netloc,
            query=query,
            headers=headers,
            body=request_body,
            response_status_code=None,
            response_body=None,
        )


def _normalize_simple_value(value):
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="ignore").strip()
    if isinstance(value, str):
        return value.strip()
    return value


def _normalize_any_value(value):
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="ignore").strip()
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, list):
        return [_normalize_any_value(v) for v in value if v is not None]
    if isinstance(value, dict):
        normalized = {}
        for key, val in value.items():
            normalized[_normalize_simple_value(key)] = _normalize_any_value(val)
        return normalized
    return value


def _normalize_bool_value(value):
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        val = value.strip().lower()
        if val in {"true", "1", "yes", "y", "on"}:
            return True
        if val in {"false", "0", "no", "n", "off"}:
            return False
    if isinstance(value, int):
        return bool(value)
    return value


def _normalize_int_list(values):
    if values is None:
        return []
    if not isinstance(values, list):
        values = [values]
    normalized = []
    for item in values:
        if item is None:
            continue
        try:
            normalized.append(int(item))
        except (TypeError, ValueError):
            continue
    return normalized


def _flatten_value_list(values):
    """
    Flatten one-level nested lists and drop None.
    """
    flat = []
    for value in (values or []):
        if value is None:
            continue
        if isinstance(value, list):
            for item in value:
                if item is not None:
                    flat.append(item)
        else:
            flat.append(value)
    return flat


def _value_dedupe_key(value):
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
    except TypeError:
        return str(value)


def _append_unique(values, value, seen=None, limit=None):
    if limit is not None and len(values) >= limit:
        return seen if seen is not None else {_value_dedupe_key(item) for item in values or []}
    if seen is None:
        seen = {_value_dedupe_key(item) for item in values or []}
    key = _value_dedupe_key(value)
    if key not in seen:
        values.append(value)
        seen.add(key)
    return seen


def _normalize_query(query_value):
    if query_value is None:
        return {}
    if isinstance(query_value, dict):
        normalized = {}
        for key, value in query_value.items():
            key_norm = _normalize_simple_value(key)
            if isinstance(value, list):
                values = [_normalize_simple_value(v) for v in value]
                normalized[key_norm] = values[0] if len(values) == 1 else values
            else:
                normalized[key_norm] = _normalize_simple_value(value)
        return normalized
    if isinstance(query_value, str):
        parsed = extract_url_params("http://placeholder.local/?" + query_value)[1]
        return _normalize_query(parsed)
    return {}


def _normalize_headers(headers_value):
    if headers_value is None:
        return {}
    if not isinstance(headers_value, dict):
        return {}
    normalized = {}
    for key, value in headers_value.items():
        key_norm = _normalize_simple_value(key)
        if isinstance(value, list):
            normalized[key_norm] = [_normalize_simple_value(v) for v in value if v is not None]
        else:
            normalized[key_norm] = [_normalize_simple_value(value)] if value is not None else []
    return normalized


def _normalize_raw_list(raw_values):
    if raw_values is None:
        return []
    if not isinstance(raw_values, list):
        raw_values = [raw_values]
    normalized = []
    for item in raw_values:
        if item is None:
            continue
        if isinstance(item, (dict, list)):
            normalized.append(json.dumps(item, ensure_ascii=False, separators=(",", ":")))
        else:
            normalized.append(_normalize_simple_value(item))
    return normalized


def _normalize_status_codes(status_codes):
    if status_codes is None:
        return []
    if not isinstance(status_codes, list):
        status_codes = [status_codes]
    normalized = []
    for code in status_codes:
        if code is None:
            continue
        try:
            normalized.append(int(code))
        except (TypeError, ValueError):
            continue
    return normalized


FORMAT_TABLES = {
    "raw_data": {
        "label": "原始接口数据(rawData)",
        "supports_filter": True,
        "targets": {
            "method": "请求方法",
            "domain": "域名",
            "path": "路径",
            "url": "完整URL",
            "action": "接口分类",
            "rule": "分类规则",
            "des": "接口描述",
            "tags": "标签",
            "modificator": "修改人",
            "query": "Query参数",
            "headers": "请求头",
            "raw_req": "原始请求体",
            "raw_res": "原始响应体",
            "response_status_code": "响应状态码",
        },
    },
    "req_data": {
        "label": "请求参数解析(reqParseData)",
        "supports_filter": True,
        "targets": {
            "content_type": "内容类型",
            "parameter": "参数名",
            "position": "参数位置",
            "relation": "关系",
            "priority": "优先级",
            "value": "参数值",
            "required": "必填标记",
            "type": "类型",
            "des": "描述",
            "modificator": "修改人",
        },
    },
    "res_data": {
        "label": "响应参数解析(resParseData)",
        "supports_filter": True,
        "targets": {
            "content_type": "内容类型",
            "parameter": "参数名",
            "position": "参数位置",
            "relation": "关系",
            "value": "参数值",
            "type": "类型",
            "des": "描述",
            "modificator": "修改人",
        },
    },
    "parameter_data": {
        "label": "参数聚合(parameterData)",
        "supports_filter": False,
        "targets": {
            "parameter": "参数名",
            "req_pathid": "请求路径ID",
            "res_pathid": "响应路径ID",
            "req_value": "请求值",
            "res_value": "响应值",
            "modificator": "修改人",
        },
    },
}


FORMAT_QUICK_MODES = {
    "raw_data": [
        {
            "key": "basic",
            "label": "基础修复",
            "targets": ["method", "path", "url", "action", "rule", "tags", "query", "headers"],
        },
        {
            "key": "payload",
            "label": "请求响应体修复",
            "targets": ["raw_req", "raw_res", "response_status_code"],
        },
        {
            "key": "all",
            "label": "全量修复",
            "targets": list(FORMAT_TABLES["raw_data"]["targets"].keys()),
        },
    ],
    "req_data": [
        {
            "key": "basic",
            "label": "基础修复",
            "targets": ["content_type", "parameter", "position", "relation", "type", "des"],
        },
        {
            "key": "value_only",
            "label": "仅参数值修复",
            "targets": ["value", "required", "priority"],
        },
        {
            "key": "all",
            "label": "全量修复",
            "targets": list(FORMAT_TABLES["req_data"]["targets"].keys()),
        },
    ],
    "res_data": [
        {
            "key": "basic",
            "label": "基础修复",
            "targets": ["content_type", "parameter", "position", "relation", "type", "des"],
        },
        {
            "key": "value_only",
            "label": "仅参数值修复",
            "targets": ["value"],
        },
        {
            "key": "all",
            "label": "全量修复",
            "targets": list(FORMAT_TABLES["res_data"]["targets"].keys()),
        },
    ],
    "parameter_data": [
        {
            "key": "path_only",
            "label": "仅路径ID修复",
            "targets": ["req_pathid", "res_pathid"],
        },
        {
            "key": "value_only",
            "label": "仅值修复",
            "targets": ["req_value", "res_value"],
        },
        {
            "key": "all",
            "label": "全量修复",
            "targets": list(FORMAT_TABLES["parameter_data"]["targets"].keys()),
        },
    ],
}


def get_format_table_options():
    options = []
    for key, conf in FORMAT_TABLES.items():
        options.append({
            "key": key,
            "label": conf["label"],
            "supports_filter": conf["supports_filter"],
            "targets": conf["targets"],
        })
    return options


def get_format_quick_modes():
    return FORMAT_QUICK_MODES


def resolve_format_targets(table_name, quick_mode="custom", manual_targets=None):
    manual_targets = manual_targets or []
    if quick_mode and quick_mode != "custom":
        for item in FORMAT_QUICK_MODES.get(table_name, []):
            if item["key"] == quick_mode:
                return list(item.get("targets", []))
    return manual_targets


def format_raw_data_mongodb(targets=None, path_regex=None, action=None, limit=0, dry_run=False):
    """
    Format legacy raw_data documents with optional field targets and filters.
    """
    allowed_targets = {
        "method", "domain", "path", "url", "action", "rule", "des", "tags", "modificator",
        "query", "headers", "raw_req", "raw_res", "response_status_code"
    }
    selected = set(targets or allowed_targets)
    selected = {t for t in selected if t in allowed_targets}
    if not selected:
        selected = allowed_targets

    query = {}
    if path_regex:
        query["path__regex"] = path_regex
    if action:
        query["action"] = action

    objects = raw_data.objects(**query).order_by("-ptah_id")
    if limit and int(limit) > 0:
        objects = objects[:int(limit)]

    scanned = 0
    updated = 0
    changed_fields = {k: 0 for k in sorted(selected)}
    changed_ids = []

    for obj in objects:
        scanned += 1
        changed = False

        if "method" in selected:
            method = (_normalize_simple_value(obj.method) or "").upper()
            if obj.method != method:
                obj.method = method
                changed = True
                changed_fields["method"] += 1
        if "domain" in selected:
            domain = _normalize_simple_value(obj.domain)
            if obj.domain != domain:
                obj.domain = domain
                changed = True
                changed_fields["domain"] += 1
        if "path" in selected:
            path = _normalize_simple_value(obj.path)
            if path and not path.startswith("/"):
                path = "/" + path
            if obj.path != path:
                obj.path = path
                changed = True
                changed_fields["path"] += 1
        if "url" in selected:
            url = _normalize_simple_value(obj.url)
            if obj.url != url:
                obj.url = url
                changed = True
                changed_fields["url"] += 1
        if "action" in selected:
            action_val = _normalize_simple_value(obj.action)
            if obj.action != action_val:
                obj.action = action_val
                changed = True
                changed_fields["action"] += 1
        if "rule" in selected:
            rule_val = _normalize_simple_value(obj.rule)
            if obj.rule != rule_val:
                obj.rule = rule_val
                changed = True
                changed_fields["rule"] += 1
        if "des" in selected:
            des_val = _normalize_simple_value(obj.des)
            if obj.des != des_val:
                obj.des = des_val
                changed = True
                changed_fields["des"] += 1
        if "tags" in selected:
            tags_val = _normalize_simple_value(obj.tags)
            if obj.tags != tags_val:
                obj.tags = tags_val
                changed = True
                changed_fields["tags"] += 1
        if "modificator" in selected:
            modificator_val = _normalize_simple_value(obj.modificator)
            if obj.modificator != modificator_val:
                obj.modificator = modificator_val
                changed = True
                changed_fields["modificator"] += 1
        if "query" in selected:
            query_val = _normalize_query(obj.query)
            if obj.query != query_val:
                obj.query = query_val
                changed = True
                changed_fields["query"] += 1
        if "headers" in selected:
            headers = _normalize_headers(obj.headers)
            if obj.headers != headers:
                obj.headers = headers
                changed = True
                changed_fields["headers"] += 1
        if "raw_req" in selected:
            raw_req = _normalize_raw_list(obj.raw_req)
            if obj.raw_req != raw_req:
                obj.raw_req = raw_req
                changed = True
                changed_fields["raw_req"] += 1
        if "raw_res" in selected:
            raw_res = _normalize_raw_list(obj.raw_res)
            if obj.raw_res != raw_res:
                obj.raw_res = raw_res
                changed = True
                changed_fields["raw_res"] += 1
        if "response_status_code" in selected:
            status_codes = _normalize_status_codes(obj.response_status_code)
            if obj.response_status_code != status_codes:
                obj.response_status_code = status_codes
                changed = True
                changed_fields["response_status_code"] += 1

        if changed:
            updated += 1
            if len(changed_ids) < 20:
                changed_ids.append(str(obj.id))
            if not dry_run:
                obj.save()

    return {
        "scanned": scanned,
        "updated": updated,
        "dry_run": bool(dry_run),
        "targets": sorted(selected),
        "changed_fields": {k: v for k, v in changed_fields.items() if v > 0},
        "sample_ids": changed_ids,
    }


def _build_related_raw_ids(path_regex=None, action=None):
    if not path_regex and not action:
        return None
    raw_query = {}
    if path_regex:
        raw_query["path__regex"] = path_regex
    if action:
        raw_query["action"] = action
    return [obj.id for obj in raw_data.objects(**raw_query).only("id")]


def _format_req_data_mongodb(targets=None, path_regex=None, action=None, limit=0, dry_run=False):
    allowed_targets = set(FORMAT_TABLES["req_data"]["targets"].keys())
    selected = set(targets or allowed_targets)
    selected = {t for t in selected if t in allowed_targets}
    if not selected:
        selected = allowed_targets

    objects = req_data.objects()
    related_ids = _build_related_raw_ids(path_regex=path_regex, action=action)
    if related_ids is not None:
        if not related_ids:
            objects = req_data.objects(id=None)
        else:
            objects = objects.filter(raw_data__in=related_ids)
    if limit and int(limit) > 0:
        objects = objects[:int(limit)]

    scanned, updated = 0, 0
    changed_fields = {k: 0 for k in sorted(selected)}
    sample_ids = []

    for obj in objects:
        scanned += 1
        changed = False
        if "content_type" in selected:
            val = _normalize_simple_value(obj.Content_type)
            if obj.Content_type != val:
                obj.Content_type = val
                changed, changed_fields["content_type"] = True, changed_fields["content_type"] + 1
        if "parameter" in selected:
            val = _normalize_simple_value(obj.parameter)
            if obj.parameter != val:
                obj.parameter = val
                changed, changed_fields["parameter"] = True, changed_fields["parameter"] + 1
        if "position" in selected:
            val = _normalize_simple_value(obj.position)
            if obj.position != val:
                obj.position = val
                changed, changed_fields["position"] = True, changed_fields["position"] + 1
        if "relation" in selected:
            val = _normalize_simple_value(obj.relation)
            if obj.relation != val:
                obj.relation = val
                changed, changed_fields["relation"] = True, changed_fields["relation"] + 1
        if "priority" in selected and obj.Priority is not None:
            try:
                val = int(obj.Priority)
            except (TypeError, ValueError):
                val = obj.Priority
            if obj.Priority != val:
                obj.Priority = val
                changed, changed_fields["priority"] = True, changed_fields["priority"] + 1
        if "value" in selected:
            val = _normalize_any_value(obj.value or [])
            if obj.value != val:
                obj.value = val
                changed, changed_fields["value"] = True, changed_fields["value"] + 1
        if "required" in selected:
            val = _normalize_bool_value(obj.required)
            if obj.required != val:
                obj.required = val
                changed, changed_fields["required"] = True, changed_fields["required"] + 1
        if "type" in selected:
            val = _normalize_simple_value(obj.type)
            if obj.type != val:
                obj.type = val
                changed, changed_fields["type"] = True, changed_fields["type"] + 1
        if "des" in selected:
            val = _normalize_simple_value(obj.des)
            if obj.des != val:
                obj.des = val
                changed, changed_fields["des"] = True, changed_fields["des"] + 1
        if "modificator" in selected:
            val = _normalize_simple_value(obj.modificator)
            if obj.modificator != val:
                obj.modificator = val
                changed, changed_fields["modificator"] = True, changed_fields["modificator"] + 1
        if changed:
            updated += 1
            if len(sample_ids) < 20:
                sample_ids.append(str(obj.id))
            if not dry_run:
                obj.save()

    return {
        "table": "req_data",
        "scanned": scanned,
        "updated": updated,
        "dry_run": bool(dry_run),
        "targets": sorted(selected),
        "changed_fields": {k: v for k, v in changed_fields.items() if v > 0},
        "sample_ids": sample_ids,
    }


def _format_res_data_mongodb(targets=None, path_regex=None, action=None, limit=0, dry_run=False):
    allowed_targets = set(FORMAT_TABLES["res_data"]["targets"].keys())
    selected = set(targets or allowed_targets)
    selected = {t for t in selected if t in allowed_targets}
    if not selected:
        selected = allowed_targets

    objects = res_data.objects()
    related_ids = _build_related_raw_ids(path_regex=path_regex, action=action)
    if related_ids is not None:
        if not related_ids:
            objects = res_data.objects(id=None)
        else:
            objects = objects.filter(raw_data__in=related_ids)
    if limit and int(limit) > 0:
        objects = objects[:int(limit)]

    scanned, updated = 0, 0
    changed_fields = {k: 0 for k in sorted(selected)}
    sample_ids = []

    for obj in objects:
        scanned += 1
        changed = False
        if "content_type" in selected:
            val = _normalize_simple_value(obj.Content_type)
            if obj.Content_type != val:
                obj.Content_type = val
                changed, changed_fields["content_type"] = True, changed_fields["content_type"] + 1
        if "parameter" in selected:
            val = _normalize_simple_value(obj.parameter)
            if obj.parameter != val:
                obj.parameter = val
                changed, changed_fields["parameter"] = True, changed_fields["parameter"] + 1
        if "position" in selected:
            val = _normalize_simple_value(obj.position)
            if obj.position != val:
                obj.position = val
                changed, changed_fields["position"] = True, changed_fields["position"] + 1
        if "relation" in selected:
            val = _normalize_simple_value(obj.relation)
            if obj.relation != val:
                obj.relation = val
                changed, changed_fields["relation"] = True, changed_fields["relation"] + 1
        if "value" in selected:
            val = _normalize_any_value(obj.value or [])
            if obj.value != val:
                obj.value = val
                changed, changed_fields["value"] = True, changed_fields["value"] + 1
        if "type" in selected:
            val = _normalize_simple_value(obj.type)
            if obj.type != val:
                obj.type = val
                changed, changed_fields["type"] = True, changed_fields["type"] + 1
        if "des" in selected:
            val = _normalize_simple_value(obj.des)
            if obj.des != val:
                obj.des = val
                changed, changed_fields["des"] = True, changed_fields["des"] + 1
        if "modificator" in selected:
            val = _normalize_simple_value(obj.modificator)
            if obj.modificator != val:
                obj.modificator = val
                changed, changed_fields["modificator"] = True, changed_fields["modificator"] + 1
        if changed:
            updated += 1
            if len(sample_ids) < 20:
                sample_ids.append(str(obj.id))
            if not dry_run:
                obj.save()

    return {
        "table": "res_data",
        "scanned": scanned,
        "updated": updated,
        "dry_run": bool(dry_run),
        "targets": sorted(selected),
        "changed_fields": {k: v for k, v in changed_fields.items() if v > 0},
        "sample_ids": sample_ids,
    }


def _format_parameter_data_mongodb(targets=None, limit=0, dry_run=False):
    allowed_targets = set(FORMAT_TABLES["parameter_data"]["targets"].keys())
    selected = set(targets or allowed_targets)
    selected = {t for t in selected if t in allowed_targets}
    if not selected:
        selected = allowed_targets

    objects = parameter_data.objects()
    if limit and int(limit) > 0:
        objects = objects[:int(limit)]

    scanned, updated = 0, 0
    changed_fields = {k: 0 for k in sorted(selected)}
    sample_ids = []

    for obj in objects:
        scanned += 1
        changed = False
        if "parameter" in selected:
            val = _normalize_simple_value(obj.parameter)
            if obj.parameter != val:
                obj.parameter = val
                changed, changed_fields["parameter"] = True, changed_fields["parameter"] + 1
        if "req_pathid" in selected:
            val = _normalize_int_list(obj.req_pathid)
            if obj.req_pathid != val:
                obj.req_pathid = val
                changed, changed_fields["req_pathid"] = True, changed_fields["req_pathid"] + 1
        if "res_pathid" in selected:
            val = _normalize_int_list(obj.res_pathid)
            if obj.res_pathid != val:
                obj.res_pathid = val
                changed, changed_fields["res_pathid"] = True, changed_fields["res_pathid"] + 1
        if "req_value" in selected:
            val = _flatten_value_list(_normalize_any_value(obj.req_value or []))
            if obj.req_value != val:
                obj.req_value = val
                changed, changed_fields["req_value"] = True, changed_fields["req_value"] + 1
        if "res_value" in selected:
            val = _flatten_value_list(_normalize_any_value(obj.res_value or []))
            if obj.res_value != val:
                obj.res_value = val
                changed, changed_fields["res_value"] = True, changed_fields["res_value"] + 1
        if "modificator" in selected:
            val = _normalize_simple_value(obj.modificator)
            if obj.modificator != val:
                obj.modificator = val
                changed, changed_fields["modificator"] = True, changed_fields["modificator"] + 1
        if changed:
            updated += 1
            if len(sample_ids) < 20:
                sample_ids.append(str(obj.id))
            if not dry_run:
                obj.save()

    return {
        "table": "parameter_data",
        "scanned": scanned,
        "updated": updated,
        "dry_run": bool(dry_run),
        "targets": sorted(selected),
        "changed_fields": {k: v for k, v in changed_fields.items() if v > 0},
        "sample_ids": sample_ids,
    }


def format_mongodb_table(table_name="raw_data", targets=None, path_regex=None, action=None, limit=0, dry_run=False):
    table_name = (table_name or "raw_data").strip()
    if table_name == "raw_data":
        summary = format_raw_data_mongodb(
            targets=targets,
            path_regex=path_regex,
            action=action,
            limit=limit,
            dry_run=dry_run,
        )
        summary["table"] = "raw_data"
        return summary
    if table_name == "req_data":
        return _format_req_data_mongodb(
            targets=targets, path_regex=path_regex, action=action, limit=limit, dry_run=dry_run
        )
    if table_name == "res_data":
        return _format_res_data_mongodb(
            targets=targets, path_regex=path_regex, action=action, limit=limit, dry_run=dry_run
        )
    if table_name == "parameter_data":
        return _format_parameter_data_mongodb(targets=targets, limit=limit, dry_run=dry_run)
    raise ValueError("unsupported table: {}".format(table_name))


def data_generate_mongodb(data, typevalue):
    capture_reader: Union[MitmproxyCaptureReader, HarCaptureReader]
    if typevalue == "mitm":
        capture_reader = MitmproxyCaptureReader(data, progress_callback if _PROGRESS_OUTPUT_ENABLED else None)
    elif typevalue == "har":
        capture_reader = HarCaptureReader(data, progress_callback if _PROGRESS_OUTPUT_ENABLED else None)
        #print(capture_reader)
    else:
        pass
    imported_ids = []
    try:
        for req in capture_reader.captured_requests():
            url = req.get_url()
            method = req.get_method()
            if url == "None" or method == "OPTIONS":
                continue
            logger.debug("import request %s %s", method, url)
            request_header = req.get_request_headers()
            request_body = req.get_request_body()
            response_status_code = req.get_response_status_code()
            response_body = req.get_response_body()
            path, querys = extract_url_params(url)
            path = regex_path(path)
            host = None
            host_header = request_header.get("Host")
            if isinstance(host_header, list) and host_header:
                host = host_header[0]
            elif isinstance(host_header, str) and host_header:
                host = host_header
            if not host:
                host = urlparse(url).netloc or None
            if querys == "{}":
                querys = None
            if request_body == b'':
                request_body = None
            abstract_sig = abstract_signature(method, path, querys, request_body)
            _id = ObjectId(api_signature_object_id(method, url, path, querys, request_body, host=host, asset_kind="concrete"))
            data = raw_data.objects(_id=_id).first()
            if data:
                if not data.url:
                    data.url = url
                if not data.domain:
                    data.domain = host
                if not data.query:
                    data.query = querys
                if not data.headers:
                    data.headers = request_header
                if not data.Max_records:
                    data.Max_records = 10
                data.asset_kind = data.asset_kind or "concrete"
                data.abstract_signature = data.abstract_signature or abstract_sig
                if len(data.raw_req) < data.Max_records:
                    data.raw_req.append(request_body)
                    data.raw_res.append(response_body)
                data.save()
            else:
                data = raw_data(_id=_id, asset_kind="concrete", abstract_signature=abstract_sig,
                                method=method, domain=host, path=path, url=url,
                                ptah_id=get_next_sequence("raw_data"), query=querys, headers=request_header,
                                raw_req=[request_body], raw_res=[response_body],
                                Max_records=10, response_status_code=[response_status_code]
                                )
                data.save()
            save_request_sample(
                data,
                method=method,
                url=url,
                path=path,
                domain=host,
                query=querys,
                headers=request_header,
                body=request_body,
                response_status_code=response_status_code,
                response_body=response_body,
            )
            imported_ids.append(data.id)
    except Exception as e:
        logger.exception("data_generate failed: %s", e)
    return imported_ids


def parameter_disassemble_mongodb(raw_ids=None, pathids=None, limit=0):
    query = {}
    if raw_ids:
        query["_id__in"] = [ObjectId(str(item)) for item in raw_ids]
    if pathids:
        query["ptah_id__in"] = list(pathids)
    objects = raw_data.objects(**query)
    if limit and limit > 0:
        objects = objects.limit(limit)
    for data in objects:
        try:
            if data.url:
                for name, value in _extract_path_params(data.url):
                    datastore = req_data.objects(parameter=name, raw_data=data, position="path").first()
                    if datastore is None:
                        Req_data = req_data(raw_data=data,
                                            Content_type="path",
                                            parameter=name,
                                            position="path",
                                            relation="any",
                                            value=[value])
                        Req_data.save()
                    else:
                        if value not in datastore.value:
                            datastore.value.append(value)
                            datastore.save()
            if data.query and isinstance(data.query, dict):
                for parameter, value in data.query.items():
                    datastore = None
                    if req_data.objects:
                        datastore = req_data.objects(parameter=parameter, raw_data=data, position="query").first()
                    if datastore is None:
                        Req_data = req_data(raw_data=data,
                                            Content_type="query",
                                            parameter=parameter,
                                            position="query",
                                            relation="any",
                                            value=[value])
                        Req_data.save()
                    else:
                        if value not in datastore.value:
                            datastore.value.append(value)
                            datastore.save()
            if data.headers and isinstance(data.headers, dict):
                for parameter, value_list in data.headers.items():
                    if parameter.lower() == "cookie":
                        continue
                    value = value_list[0] if isinstance(value_list, list) and value_list else value_list
                    datastore = None
                    if req_data.objects:
                        datastore = req_data.objects(parameter=parameter, raw_data=data, position="header").first()
                    if datastore is None:
                        Req_data = req_data(raw_data=data,
                                            Content_type="header",
                                            parameter=parameter,
                                            position="header",
                                            relation="any",
                                            value=[value])
                        Req_data.save()
                    else:
                        if value not in datastore.value:
                            datastore.value.append(value)
                            datastore.save()
            for requests in data.raw_req:
                #print(requests, 1234)
                if requests is not None:
                    #print(data.path,"req")
                    body, content_type = body_parse(requests)
                    if content_type is not None:
                        parameters = flatten_json(body)
                        for parameter, value in parameters.items():
                            datastore = None
                            if req_data.objects:
                                datastore = req_data.objects(parameter=parameter, raw_data=data, position="body").first()
                            if datastore is None:
                                Req_data = req_data(raw_data=data,
                                                    Content_type=content_type,
                                                    parameter=parameter,
                                                    position="body",
                                                    relation="any",
                                                    value=[value]
                                                    )
                                Req_data.save()
                            else:
                                if value not in datastore.value:
                                    datastore.value.append(value)
                                    datastore.save()
                else:
                    datastore = None
                    if req_data.objects:
                        datastore = req_data.objects(parameter=None, raw_data=data).first()
                    if datastore is None:
                        Req_data = req_data(raw_data=data, Content_type=None,
                                            parameter=None,
                                            value=None
                                            )
                        Req_data.save()
            for response in data.raw_res:
                if response is not None:
                    #print(data.path,"res")
                    # 解析响应体和内容类型
                    body, content_type = body_parse(response)
                    if content_type:
                        # 扁平化 JSON 数据
                        parameters = flatten_json(body)
                        #print(parameters,type(parameters))
                        for parameter, value in parameters.items():
                            #print(123111111111111111)
                            datastore = None
                            # 检查是否存在对应的 res_data 对象
                            if res_data.objects():
                                datastore = res_data.objects(parameter=parameter, raw_data=data, position="body").first()
                            #print(parameter, "jjjjjj")
                            if datastore is None:
                                # 创建并保存新的 res_data 对象
                                Res_data = res_data(
                                    raw_data=data,
                                    Content_type=content_type,
                                    parameter=parameter,
                                    position="body",
                                    relation="any",
                                    value=[value]
                                )
                                Res_data.save()
                            else:
                                # 更新现有的 res_data 对象
                                if value not in datastore.value:
                                    datastore.value.append(value)
                                    datastore.save()
                else:
                    # 创建并保存内容类型为空的 res_data 对象
                    datastore = None
                    # 检查是否存在对应的 res_data 对象
                    if res_data.objects():
                        datastore = res_data.objects(parameter=None, raw_data=data).first()
                    if datastore is None:
                        resdata = res_data(
                            raw_data=data,
                            Content_type=None,
                            parameter=None,
                            value=None
                        )
                        resdata.save()
        except Exception as e:
            logger.exception("parameter_disassemble_mongodb failed, path=%s, err=%s", data.path, e)


def parameter_date_mongodb(rawdatacolletion=None, raw_ids=None, pathids=None,
                           max_req_values=MAX_PARAMETER_VALUES,
                           max_res_values=MAX_RESPONSE_PARAMETER_VALUES):
    query = {}
    if rawdatacolletion is not None:
        query["raw_data__in"] = rawdatacolletion if isinstance(rawdatacolletion, list) else [rawdatacolletion]
    if raw_ids:
        query["raw_data__in"] = [ObjectId(str(item)) for item in raw_ids]
    if pathids:
        query["raw_data__ptah_id__in"] = list(pathids)
    request_queryset = req_data.objects(**query)
    response_queryset = res_data.objects(**query)
    try:
        aggregated = {}

        for item in request_queryset:
            if not item.parameter:
                continue
            bucket = aggregated.setdefault(item.parameter, {"req_values": [], "res_values": [], "req_pathids": set(), "res_pathids": set()})
            seen = {_value_dedupe_key(value) for value in bucket["req_values"]}
            for value in _flatten_value_list(item.value):
                _append_unique(bucket["req_values"], value, seen, limit=max_req_values)
            bucket["req_pathids"].add(item.raw_data.ptah_id)

        for item in response_queryset:
            if not item.parameter:
                continue
            bucket = aggregated.setdefault(item.parameter, {"req_values": [], "res_values": [], "req_pathids": set(), "res_pathids": set()})
            seen = {_value_dedupe_key(value) for value in bucket["res_values"]}
            for value in _flatten_value_list(item.value):
                _append_unique(bucket["res_values"], value, seen, limit=max_res_values)
            bucket["res_pathids"].add(item.raw_data.ptah_id)

        if not aggregated:
            return

        names = list(aggregated.keys())
        existing_names = set(parameter_data.objects(parameter__in=names).scalar("parameter"))
        missing_names = [name for name in names if name not in existing_names]
        allocated_ids = dict(zip(missing_names, allocate_sequence_range("parameter_data", len(missing_names))))

        operations = []
        for name, bucket in aggregated.items():
            update = {
                "$addToSet": {
                    "req_value": {"$each": bucket["req_values"]},
                    "res_value": {"$each": bucket["res_values"]},
                    "req_pathid": {"$each": sorted(bucket["req_pathids"])},
                    "res_pathid": {"$each": sorted(bucket["res_pathids"])},
                }
            }
            if name in allocated_ids:
                update["$setOnInsert"] = {
                    "parameter": name,
                    "parameterid": allocated_ids[name],
                }
            operations.append(UpdateOne({"parameter": name}, update, upsert=True))

        if operations:
            parameter_data._get_collection().bulk_write(operations, ordered=False)
    except Exception as e:
        logger.exception("parameter_date_mongodb failed: %s", e)


def compact_parameter_data_values(max_req_values=MAX_PARAMETER_VALUES, max_res_values=MAX_RESPONSE_PARAMETER_VALUES):
    updated = 0
    for item in parameter_data.objects:
        changed = False
        if item.req_value and len(item.req_value) > max_req_values:
            item.req_value = item.req_value[:max_req_values]
            changed = True
        if item.res_value and len(item.res_value) > max_res_values:
            item.res_value = item.res_value[:max_res_values]
            changed = True
        if changed:
            item.save()
            updated += 1
    return updated
