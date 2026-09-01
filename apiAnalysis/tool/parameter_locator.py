"""Stable parameter locations for display, analysis and request materialization.

Legacy parameter names use dotted paths for both concrete JSON samples
(``items.0.id``) and JSON Schema paths (``items[].id``).  Those strings are
useful labels, but they are not sufficient execution locators: numeric object
keys are ambiguous and schema wildcards need an explicit materialization rule.

This module keeps the legacy/raw path while adding a small typed-token locator.
Analysis can group by ``canonical_name``/``schema_path`` and execution can use
the typed tokens without guessing whether a segment is an object key or list
index.
"""
from __future__ import annotations

import re
from typing import Any, Dict, Iterable, Iterator, List, Mapping, Optional, Sequence, Tuple


LOCATOR_VERSION = 2
_DYNAMIC_KEY = re.compile(
    r"^(?:\d{4,}|[0-9a-f]{8,}|[0-9a-f]{8}-[0-9a-f-]{27,})$",
    re.IGNORECASE,
)


def _pointer_escape(value: str) -> str:
    return str(value).replace("~", "~0").replace("/", "~1")


def _canonical_leaf(value: str) -> str:
    value = str(value or "").strip().replace("-", "_")
    return value.lower()


def _is_dynamic_property(value: str) -> bool:
    return bool(_DYNAMIC_KEY.fullmatch(str(value or "")))


def _tokens_from_path(path: str, schema: Optional[bool] = None) -> List[Dict[str, Any]]:
    text = str(path or "")
    schema = "[]" in text if schema is None else bool(schema)
    tokens: List[Dict[str, Any]] = []
    for segment_index, raw_segment in enumerate(text.split(".")):
        if raw_segment == "":
            continue
        segment = raw_segment
        array_count = 0
        while segment.endswith("[]"):
            segment = segment[:-2]
            array_count += 1
        if segment:
            # Schema properties, including numeric map keys, are always object
            # keys.  Concrete legacy paths use numeric segments as array indexes
            # except at the root, where numeric JSON object keys are common.
            if (
                not schema
                and segment.isdigit()
                and segment_index > 0
                and int(segment) <= 10000
            ):
                tokens.append({"kind": "array", "index": int(segment), "wildcard": False})
            else:
                tokens.append({
                    "kind": "property",
                    "value": segment,
                    "dynamic": _is_dynamic_property(segment),
                })
        for _ in range(array_count):
            tokens.append({"kind": "array", "index": 0, "wildcard": True})
    return tokens


def _paths_from_tokens(tokens: Sequence[Mapping[str, Any]]) -> Tuple[str, str, str, str, str]:
    raw_parts: List[str] = []
    schema_parts: List[str] = []
    display_parts: List[str] = []
    pointer_parts: List[str] = []
    leaf = ""
    for token in tokens:
        kind = token.get("kind")
        if kind == "property":
            value = str(token.get("value") or "")
            raw_parts.append(value)
            schema_parts.append(value)
            display_parts.append("{key}" if token.get("dynamic") else value)
            pointer_parts.append(_pointer_escape(value))
            leaf = value
        elif kind == "array":
            index = int(token.get("index") or 0)
            wildcard = bool(token.get("wildcard"))
            if raw_parts:
                if wildcard:
                    raw_parts[-1] += "[]"
                else:
                    raw_parts.append(str(index))
            else:
                raw_parts.append("[]" if wildcard else str(index))
            if schema_parts:
                schema_parts[-1] += "[]"
            else:
                schema_parts.append("[]")
            if display_parts:
                display_parts[-1] += "[]"
            else:
                display_parts.append("[]")
            pointer_parts.append("*" if wildcard else str(index))
    return ".".join(raw_parts), ".".join(schema_parts), ".".join(display_parts), "/" + "/".join(pointer_parts), leaf


def locator_from_tokens(tokens: Sequence[Mapping[str, Any]], *, raw_path: str = "",
                        direction: str = "request", position: str = "body",
                        locator_kind: str = "instance") -> Dict[str, Any]:
    normalized = [dict(token) for token in tokens]
    derived_raw, schema_path, display_path, pointer, leaf = _paths_from_tokens(normalized)
    return {
        "version": LOCATOR_VERSION,
        "direction": str(direction or "request"),
        "position": str(position or "body"),
        "kind": str(locator_kind or "instance"),
        "raw_path": str(raw_path or derived_raw),
        "schema_path": schema_path,
        "display_path": display_path,
        "json_pointer": pointer,
        "leaf_name": leaf,
        "canonical_name": _canonical_leaf(leaf),
        "tokens": normalized,
    }


def locator_from_path(path: str, *, direction: str = "request", position: str = "body",
                      schema: Optional[bool] = None) -> Dict[str, Any]:
    is_schema = "[]" in str(path or "") if schema is None else bool(schema)
    tokens = _tokens_from_path(path, schema=is_schema)
    return locator_from_tokens(
        tokens,
        raw_path=str(path or ""),
        direction=direction,
        position=position,
        locator_kind="schema" if is_schema else "instance",
    )


def parameter_locator(path: str, *, direction: str, position: str,
                      source_meta: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
    """Return a normalized locator, reusing an imported locator when present."""
    existing = dict((source_meta or {}).get("locator") or {})
    if existing.get("version") == LOCATOR_VERSION and existing.get("tokens"):
        existing["direction"] = direction
        existing["position"] = position
        return existing
    if position != "body":
        token = {
            "kind": "property",
            "value": str(path or ""),
            "dynamic": False,
        }
        return locator_from_tokens(
            [token], raw_path=str(path or ""), direction=direction,
            position=position, locator_kind="parameter",
        )
    return locator_from_path(path, direction=direction, position=position)


def locator_document_fields(path: str, *, direction: str, position: str,
                            source_meta: Optional[Mapping[str, Any]] = None,
                            schema: Optional[bool] = None) -> Dict[str, Any]:
    if position == "body" and schema is not None:
        locator = locator_from_path(
            path, direction=direction, position=position, schema=schema,
        )
    else:
        locator = parameter_locator(path, direction=direction, position=position, source_meta=source_meta)
    return {
        "direction": direction,
        "raw_path": locator.get("raw_path") or str(path or ""),
        "schema_path": locator.get("schema_path") or str(path or ""),
        "display_path": locator.get("display_path") or str(path or ""),
        "canonical_name": locator.get("canonical_name") or _canonical_leaf(path),
        "locator": locator,
    }


def iter_json_leaf_occurrences(value: Any, *, direction: str = "request",
                               position: str = "body") -> Iterator[Tuple[Dict[str, Any], Any]]:
    """Yield typed locators and leaf values from a concrete JSON value."""
    def walk(node: Any, tokens: List[Dict[str, Any]]) -> Iterator[Tuple[Dict[str, Any], Any]]:
        if isinstance(node, dict):
            if not node:
                yield locator_from_tokens(tokens, direction=direction, position=position), node
                return
            for key, child in node.items():
                token = {
                    "kind": "property",
                    "value": str(key),
                    "dynamic": _is_dynamic_property(str(key)),
                }
                yield from walk(child, tokens + [token])
            return
        if isinstance(node, list):
            if not node:
                yield locator_from_tokens(tokens, direction=direction, position=position), node
                return
            for index, child in enumerate(node):
                yield from walk(child, tokens + [{
                    "kind": "array", "index": index, "wildcard": False,
                }])
            return
        yield locator_from_tokens(tokens, direction=direction, position=position), node

    yield from walk(value, [])


def _container_for(next_token: Optional[Mapping[str, Any]]) -> Any:
    return [] if next_token and next_token.get("kind") == "array" else {}


def set_value_at_locator(root: Any, locator: Mapping[str, Any], value: Any,
                         *, wildcard_index: int = 0) -> Any:
    """Set one value at a typed locator, materializing schema arrays safely."""
    tokens = list(locator.get("tokens") or [])
    if not tokens:
        return value
    if root is None or not isinstance(root, (dict, list)):
        root = _container_for(tokens[0])
    current = root
    for index, token in enumerate(tokens):
        is_last = index == len(tokens) - 1
        next_token = None if is_last else tokens[index + 1]
        kind = token.get("kind")
        if kind == "property":
            key = str(token.get("value") or "")
            if not isinstance(current, dict):
                raise ValueError("property locator requires an object container")
            if is_last:
                current[key] = value
            else:
                expected = list if next_token.get("kind") == "array" else dict
                if not isinstance(current.get(key), expected):
                    current[key] = _container_for(next_token)
                current = current[key]
            continue
        if kind != "array":
            raise ValueError("unsupported locator token")
        if not isinstance(current, list):
            raise ValueError("array locator requires a list container")
        item_index = wildcard_index if token.get("wildcard") else int(token.get("index") or 0)
        while len(current) <= item_index:
            current.append(None)
        if is_last:
            current[item_index] = value
        else:
            expected = list if next_token.get("kind") == "array" else dict
            if not isinstance(current[item_index], expected):
                current[item_index] = _container_for(next_token)
            current = current[item_index]
    return root


def set_value_at_path(root: Any, path: str, value: Any, *, direction: str = "request",
                      position: str = "body", schema: Optional[bool] = None) -> Any:
    locator = locator_from_path(path, direction=direction, position=position, schema=schema)
    return set_value_at_locator(root, locator, value)


def extract_values_at_locator(value: Any, locator: Mapping[str, Any], *, limit: int = 20) -> List[Any]:
    """Extract bounded values; wildcard arrays and dynamic map keys fan out."""
    tokens = list(locator.get("tokens") or [])
    results: List[Any] = []

    def walk(node: Any, token_index: int) -> None:
        if len(results) >= max(1, int(limit)):
            return
        if token_index >= len(tokens):
            results.append(node)
            return
        token = tokens[token_index]
        if token.get("kind") == "property":
            if not isinstance(node, dict):
                return
            key = str(token.get("value") or "")
            if token.get("dynamic"):
                for child in node.values():
                    walk(child, token_index + 1)
                    if len(results) >= limit:
                        break
            elif key in node:
                walk(node[key], token_index + 1)
            return
        if token.get("kind") == "array":
            if not isinstance(node, list):
                return
            if token.get("wildcard"):
                for child in node:
                    walk(child, token_index + 1)
                    if len(results) >= limit:
                        break
            else:
                item_index = int(token.get("index") or 0)
                if 0 <= item_index < len(node):
                    walk(node[item_index], token_index + 1)

    walk(value, 0)
    return results[:limit]


def materialize_flat_json(flat_values: Mapping[str, Any], value_selector=lambda item: item) -> Any:
    root: Any = None
    for path, raw_value in (flat_values or {}).items():
        selected = value_selector(raw_value)
        root = set_value_at_path(root, str(path), selected)
    return {} if root is None else root
