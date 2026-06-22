import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import urlparse

from bson.objectid import ObjectId

from apiAnalysis.db.collection import raw_data, req_data, res_data
from apiAnalysis.db.save import get_next_sequence
from apiAnalysis.tool.api_signature import abstract_signature, api_signature_object_id


HTTP_METHODS = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}
SENSITIVE_HINTS = ("authorization", "cookie", "token", "password", "passwd", "secret", "session")
# Optional built-in serverId -> baseUrl map for a specific deployment. Leave
# empty for generic use; supply hosts per import via --base-url or the per-import
# project server map (_PROJECT_SERVER_BASE_URLS) instead of hardcoding here.
FORMAL_SERVER_BASE_URLS: Dict[str, str] = {}


def _load_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _normalize_base_url(base_url: str = "") -> str:
    value = (base_url or "").strip().rstrip("/")
    if value and "://" not in value:
        value = "https://" + value
    return value


def _join_url(base_url: str, path: str) -> str:
    path_text = str(path or "")
    if "://" in path_text:
        return path_text
    base = _normalize_base_url(base_url)
    if not base:
        return path_text or "/"
    return base + "/" + path_text.lstrip("/")


# Optional per-import serverId -> baseUrl map (set by the caller for multi-host
# projects whose endpoints carry Apifox server UUIDs that resolve to different
# backend hosts).
_PROJECT_SERVER_BASE_URLS: Dict[str, str] = {}


def _endpoint_base_url(endpoint: Dict[str, Any], fallback_base_url: str = "") -> str:
    server_id = str(endpoint.get("serverId") or "")
    fallback = _normalize_base_url(fallback_base_url)
    # Project server map wins: route each endpoint to its real host by serverId.
    if _PROJECT_SERVER_BASE_URLS:
        if server_id in _PROJECT_SERVER_BASE_URLS and _PROJECT_SERVER_BASE_URLS[server_id]:
            return _normalize_base_url(_PROJECT_SERVER_BASE_URLS[server_id])
        if server_id in ("", "default") and _PROJECT_SERVER_BASE_URLS.get("default"):
            return _normalize_base_url(_PROJECT_SERVER_BASE_URLS["default"])
    # Specific (non-default) known server ids keep their dedicated host so
    # multi-host projects route correctly even when a base-url is supplied.
    if server_id and server_id != "default" and server_id in FORMAL_SERVER_BASE_URLS:
        return FORMAL_SERVER_BASE_URLS[server_id]
    # For empty/"default" server ids, an explicit per-import base-url wins, so
    # callers can route a project to its own host without editing this module.
    if fallback:
        return fallback
    return FORMAL_SERVER_BASE_URLS.get(server_id) or FORMAL_SERVER_BASE_URLS["default"]


def _enabled(items: Optional[Iterable[Dict[str, Any]]]) -> List[Dict[str, Any]]:
    return [item for item in (items or []) if item and item.get("enable", True)]


def _safe_example(name: str, value: Any) -> List[Any]:
    if value in (None, ""):
        return []
    lowered = str(name or "").lower()
    if any(hint in lowered for hint in SENSITIVE_HINTS):
        return []
    if isinstance(value, (dict, list)):
        return [value]
    return [str(value)]


def _coerce_type_str(value: Any, fallback: str = "") -> str:
    # JSON Schema permits union types like ["string", "null"]; the model column
    # is a single StringField, so collapse to the first concrete type.
    if isinstance(value, (list, tuple)):
        value = next((x for x in value if x and x != "null"), None) or (value[0] if value else None)
    if value in (None, ""):
        return fallback
    return str(value)


def _schema_type(schema: Any, fallback: str = "") -> str:
    if isinstance(schema, dict):
        return _coerce_type_str(schema.get("type"), fallback)
    return fallback


def _flatten_schema(schema: Any, parent: str = "") -> List[Dict[str, Any]]:
    if not isinstance(schema, dict):
        return []
    if "$ref" in schema:
        return []
    for key in ("allOf", "oneOf", "anyOf"):
        if isinstance(schema.get(key), list):
            result: List[Dict[str, Any]] = []
            for item in schema[key]:
                result.extend(_flatten_schema(item, parent=parent))
            return result
    schema_type = schema.get("type")
    properties = schema.get("properties") or {}
    required = set(schema.get("required") or [])
    if properties:
        result = []
        for name, child in properties.items():
            full_name = f"{parent}.{name}" if parent else str(name)
            nested = _flatten_schema(child, parent=full_name)
            if nested:
                for item in nested:
                    item["required"] = item.get("required") or name in required
                result.extend(nested)
            else:
                result.append(
                    {
                        "name": full_name,
                        "type": _schema_type(child),
                        "required": name in required,
                        "description": child.get("description") if isinstance(child, dict) else "",
                        "example": child.get("example") if isinstance(child, dict) else None,
                    }
                )
        return result
    if schema_type == "array":
        items = schema.get("items") or {}
        array_name = parent + "[]" if parent else "[]"
        nested = _flatten_schema(items, parent=array_name)
        return nested or [{"name": array_name, "type": "array", "required": False, "description": "", "example": None}]
    if parent:
        return [
            {
                "name": parent,
                "type": schema_type or "",
                "required": False,
                "description": schema.get("description") or "",
                "example": schema.get("example"),
            }
        ]
    return []


def _response_status_codes(endpoint: Dict[str, Any]) -> List[int]:
    codes = []
    for response in endpoint.get("responses") or []:
        try:
            code = int(response.get("code"))
        except (TypeError, ValueError):
            continue
        if code not in codes:
            codes.append(code)
    return codes


def _endpoint_source_meta(endpoint: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "apifox_endpoint_id": endpoint.get("id"),
        "apifox_project_id": endpoint.get("projectId"),
        "apifox_module_id": endpoint.get("moduleId"),
        "apifox_folder_id": endpoint.get("folderId"),
        "apifox_server_id": endpoint.get("serverId"),
        "operation_id": endpoint.get("operationId"),
        "name": endpoint.get("name"),
        "status": endpoint.get("status"),
        "visibility": endpoint.get("visibility"),
        "ordering": endpoint.get("ordering"),
        "created_at": endpoint.get("createdAt"),
        "updated_at": endpoint.get("updatedAt"),
        "custom_api_fields": endpoint.get("customApiFields") or {},
    }


def _param_source_meta(param: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "apifox_param_id": param.get("id"),
        "enable": param.get("enable", True),
        "schema": param.get("schema") or {},
        "raw_type": param.get("type"),
    }


def _response_source_meta(response: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "apifox_response_id": response.get("id"),
        "name": response.get("name"),
        "code": response.get("code"),
        "description": response.get("description"),
        "media_type": response.get("mediaType"),
    }


def _upsert_raw(endpoint: Dict[str, Any], base_url: str) -> raw_data:
    method = str(endpoint.get("method") or "GET").upper()
    if method not in HTTP_METHODS:
        method = "GET"
    path = endpoint.get("path") or endpoint.get("name") or "/"
    url = _join_url(_endpoint_base_url(endpoint, base_url), path)
    parsed = urlparse(url)
    signature = abstract_signature(method, path, {}, None)
    raw_id = ObjectId(api_signature_object_id(method, url, path, {}, None, host=parsed.netloc, asset_kind="abstract"))
    source_id = str(endpoint.get("id") or "")
    data = raw_data.objects(source="apifox", source_id=source_id).first() if source_id else None
    if not data:
        data = raw_data.objects(_id=raw_id).first()
    status_codes = _response_status_codes(endpoint)
    tags = endpoint.get("tags") or []
    tag_text = ",".join(str(item) for item in tags) if isinstance(tags, list) else str(tags or "")
    if not data:
        data = raw_data(
            _id=raw_id,
            source="apifox",
            source_id=source_id,
            source_meta=_endpoint_source_meta(endpoint),
            asset_kind="abstract",
            abstract_signature=signature,
            domain=parsed.netloc,
            path=path,
            ptah_id=get_next_sequence("raw_data"),
            query={},
            method=method,
            url=url,
            headers={},
            des=endpoint.get("description") or endpoint.get("name") or "",
            tags=tag_text,
            raw_req=[],
            raw_res=[],
            response_status_code=status_codes,
            Max_records=10,
        )
    else:
        data.source = data.source or "apifox"
        data.source_id = data.source_id or source_id
        data.source_meta = _endpoint_source_meta(endpoint)
        data.asset_kind = data.asset_kind or "abstract"
        data.abstract_signature = data.abstract_signature or signature
        data.domain = parsed.netloc
        data.path = path
        data.url = url
        data.method = data.method or method
        data.des = endpoint.get("description") or data.des
        data.tags = tag_text or data.tags
        merged = list(data.response_status_code or [])
        for code in status_codes:
            if code not in merged:
                merged.append(code)
        data.response_status_code = merged
    data.save()
    return data


def _upsert_req(data: raw_data, name: str, position: str, required: bool = False, param_type: str = "", desc: str = "", values=None, content_type: str = "", source_meta=None) -> None:
    if not name:
        return
    item = req_data.objects(raw_data=data, parameter=name, position=position).first()
    if not item:
        item = req_data(raw_data=data, parameter=name, position=position, relation="any")
    item.required = bool(required)
    item.type = _coerce_type_str(param_type) or item.type
    item.des = desc or item.des
    item.Content_type = content_type or position
    item.source_meta = source_meta or item.source_meta or {}
    existing = list(item.value or [])
    for value in values or []:
        if value not in existing:
            existing.append(value)
    item.value = existing[:20]
    item.save()


def _upsert_res(data: raw_data, name: str, content_type: str = "", param_type: str = "", desc: str = "", source_meta=None) -> None:
    if not name:
        return
    item = res_data.objects(raw_data=data, parameter=name, position="body").first()
    if not item:
        item = res_data(raw_data=data, parameter=name, position="body", relation="any", value=[])
    item.Content_type = content_type or item.Content_type
    item.type = _coerce_type_str(param_type) or item.type
    item.des = desc or item.des
    item.source_meta = source_meta or item.source_meta or {}
    item.save()


def _import_request_params(endpoint: Dict[str, Any], data: raw_data) -> int:
    count = 0
    groups = endpoint.get("parameters") or {}
    for position in ("path", "query", "header", "cookie"):
        for param in _enabled(groups.get(position) or []):
            name = param.get("name")
            if not name:
                continue
            _upsert_req(
                data,
                name,
                position=position,
                required=param.get("required", False),
                param_type=param.get("type") or _schema_type(param.get("schema")),
                desc=param.get("description") or "",
                values=_safe_example(name, param.get("example")),
                source_meta=_param_source_meta(param),
            )
            count += 1
    body = endpoint.get("requestBody") or {}
    content_type = body.get("contentType") or body.get("type") or "body"
    for param in _enabled(body.get("parameters") or []):
        name = param.get("name")
        if not name:
            continue
        _upsert_req(
            data,
            name,
            position="body",
            required=param.get("required", False),
            param_type=param.get("type") or _schema_type(param.get("schema")),
            desc=param.get("description") or "",
            values=_safe_example(name, param.get("example")),
            content_type=content_type,
            source_meta=_param_source_meta(param),
        )
        count += 1
    for param in _flatten_schema(body.get("jsonSchema") or body.get("schema") or {}):
        _upsert_req(
            data,
            param["name"],
            position="body",
            required=param.get("required", False),
            param_type=param.get("type") or "",
            desc=param.get("description") or "",
            values=_safe_example(param["name"], param.get("example")),
            content_type=content_type,
            source_meta={"schema_source": "request_body_json_schema"},
        )
        count += 1
    return count


def _import_response_params(endpoint: Dict[str, Any], data: raw_data) -> int:
    count = 0
    for response in endpoint.get("responses") or []:
        content_type = response.get("contentType") or response.get("mediaType") or "body"
        for param in _flatten_schema(response.get("jsonSchema") or response.get("itemSchema") or {}):
            _upsert_res(
                data,
                param["name"],
                content_type=content_type,
                param_type=param.get("type") or "",
                desc=param.get("description") or "",
                source_meta=_response_source_meta(response),
            )
            count += 1
    return count


def import_apifox_detail_file(path: Path, base_url: str = "") -> Dict[str, Any]:
    doc = _load_json(path)
    endpoint = doc.get("data") or doc
    if endpoint.get("type") and endpoint.get("type") != "http":
        return {"imported": False, "reason": "non_http", "file": str(path)}
    data = _upsert_raw(endpoint, base_url=base_url)
    req_count = _import_request_params(endpoint, data)
    res_count = _import_response_params(endpoint, data)
    return {
        "imported": True,
        "endpoint_id": endpoint.get("id"),
        "pathid": data.ptah_id,
        "method": data.method,
        "path": data.path,
        "req_params": req_count,
        "res_params": res_count,
    }


def import_apifox_details(details_dir: Path, base_url: str = "", limit: int = 0,
                          server_map: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    global _PROJECT_SERVER_BASE_URLS
    _PROJECT_SERVER_BASE_URLS = dict(server_map or {})
    files = sorted(Path(details_dir).glob("*.json"))
    if limit and limit > 0:
        files = files[:limit]
    imported = 0
    skipped = 0
    req_params = 0
    res_params = 0
    pathids: List[int] = []
    for file_path in files:
        result = import_apifox_detail_file(file_path, base_url=base_url)
        if result.get("imported"):
            imported += 1
            req_params += int(result.get("req_params") or 0)
            res_params += int(result.get("res_params") or 0)
            pathids.append(int(result["pathid"]))
        else:
            skipped += 1
    return {
        "files": len(files),
        "imported": imported,
        "skipped": skipped,
        "req_params": req_params,
        "res_params": res_params,
        "pathids": pathids,
    }
