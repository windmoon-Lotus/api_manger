import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Set

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from apiAnalysis.db.collection import raw_data, req_data  # noqa: E402
from apiAnalysis.main import _ensure_mongo_connection  # noqa: E402


def load_json(path: Path) -> Dict[str, Any]:
    raw = path.read_bytes()
    for encoding in ("utf-8-sig", "utf-16", "utf-16le", "gbk"):
        try:
            return json.loads(raw.decode(encoding))
        except Exception:
            continue
    raise ValueError(f"Cannot decode JSON file: {path}")


def resolve_ref(doc: Dict[str, Any], ref: str) -> Dict[str, Any]:
    if not ref or not ref.startswith("#/"):
        return {}
    current: Any = doc
    for part in ref[2:].split("/"):
        if not isinstance(current, dict):
            return {}
        current = current.get(part)
        if current is None:
            return {}
    return current if isinstance(current, dict) else {}


def flatten_schema(doc: Dict[str, Any], schema: Any, parent: str = "", seen: Set[str] = None) -> List[Dict[str, Any]]:
    seen = seen or set()
    if not isinstance(schema, dict):
        return []
    if "$ref" in schema:
        ref = schema.get("$ref") or ""
        if ref in seen:
            return []
        return flatten_schema(doc, resolve_ref(doc, ref), parent=parent, seen=seen | {ref})
    for key in ("allOf", "oneOf", "anyOf"):
        if isinstance(schema.get(key), list):
            rows: List[Dict[str, Any]] = []
            for item in schema[key]:
                rows.extend(flatten_schema(doc, item, parent=parent, seen=set(seen)))
            return rows
    props = schema.get("properties") or {}
    required = set(schema.get("required") or [])
    if props:
        rows = []
        for name, child in props.items():
            full = f"{parent}.{name}" if parent else str(name)
            nested = flatten_schema(doc, child, parent=full, seen=set(seen))
            if nested:
                for row in nested:
                    row["required"] = row.get("required") or name in required
                rows.extend(nested)
            else:
                rows.append({
                    "name": full,
                    "type": child.get("type") if isinstance(child, dict) else "",
                    "required": name in required,
                    "description": child.get("description") if isinstance(child, dict) else "",
                    "example": child.get("example") if isinstance(child, dict) else None,
                })
        return rows
    if schema.get("type") == "array":
        nested = flatten_schema(doc, schema.get("items") or {}, parent=parent + "[]" if parent else "[]", seen=set(seen))
        return nested or [{"name": parent + "[]" if parent else "[]", "type": "array", "required": False, "description": "", "example": None}]
    if parent:
        return [{"name": parent, "type": schema.get("type") or "", "required": False, "description": schema.get("description") or "", "example": schema.get("example")}]
    return []


def safe_values(name: str, value: Any) -> List[Any]:
    if value in (None, ""):
        return []
    lowered = str(name or "").lower()
    if any(hint in lowered for hint in ("authorization", "cookie", "token", "password", "secret", "session")):
        return []
    return [value]


def upsert_body_param(endpoint: raw_data, field: Dict[str, Any], content_type: str) -> None:
    name = field.get("name") or ""
    if not name:
        return
    item = req_data.objects(raw_data=endpoint, parameter=name, position="body").first()
    if not item:
        item = req_data(raw_data=endpoint, parameter=name, position="body", relation="any")
    item.required = bool(field.get("required"))
    item.type = field.get("type") or item.type
    item.des = field.get("description") or item.des
    item.Content_type = content_type
    item.source_meta = {"schema_source": "openapi_export", "schema_ref_resolved": True}
    values = list(item.value or [])
    for value in safe_values(name, field.get("example")):
        if value not in values:
            values.append(value)
    item.value = values[:20]
    item.save()


def main() -> int:
    parser = argparse.ArgumentParser(description="Import OpenAPI requestBody schemas into api_manger req_data.")
    parser.add_argument("--openapi", required=True)
    parser.add_argument("--source", default="apifox")
    parser.add_argument("--limit", type=int, default=0)
    args = parser.parse_args()

    _ensure_mongo_connection()
    doc = load_json(Path(args.openapi))
    imported_endpoints = 0
    imported_fields = 0
    missing_assets = 0
    for path, methods in (doc.get("paths") or {}).items():
        if not isinstance(methods, dict):
            continue
        for method, operation in methods.items():
            if method.lower() not in {"get", "post", "put", "patch", "delete", "head", "options"}:
                continue
            content = ((operation or {}).get("requestBody") or {}).get("content") or {}
            for content_type, content_item in content.items():
                fields = flatten_schema(doc, (content_item or {}).get("schema") or {})
                if not fields:
                    continue
                endpoint = raw_data.objects(source=args.source, path=path, method=method.upper()).first()
                if not endpoint:
                    missing_assets += 1
                    continue
                for field in fields:
                    upsert_body_param(endpoint, field, content_type)
                    imported_fields += 1
                imported_endpoints += 1
                break
            if args.limit and imported_endpoints >= args.limit:
                print(json.dumps({"imported_endpoints": imported_endpoints, "imported_fields": imported_fields, "missing_assets": missing_assets}, ensure_ascii=False, sort_keys=True))
                return 0
    print(json.dumps({"imported_endpoints": imported_endpoints, "imported_fields": imported_fields, "missing_assets": missing_assets}, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
