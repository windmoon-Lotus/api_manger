"""Minimal tool registry and JSON-schema validation for AI tool calls."""
from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from .policy import CAP_PROJECT_READ


_JSON_TYPES = {
    "string": str,
    "boolean": bool,
    "integer": int,
    "number": (int, float),
    "array": list,
    "object": dict,
    "null": type(None),
}


def _matches_type(value: Any, type_name: str) -> bool:
    expected = _JSON_TYPES.get(type_name)
    if expected is None:
        return True
    if type_name == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if type_name == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    return isinstance(value, expected)


@dataclass
class ToolSpec:
    """One callable tool exposed to AI sessions."""

    name: str
    description: str
    parameters: Dict[str, Any]
    function: Callable[[Dict[str, Any]], Any]
    capability: str = CAP_PROJECT_READ
    writes: bool = False
    network: bool = False
    mutation: bool = False
    shell: bool = False
    risk: str = "low"
    provenance: str = "managed"
    hidden: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "parameters": self.parameters,
            "capability": self.capability,
            "writes": self.writes,
            "network": self.network,
            "mutation": self.mutation,
            "shell": self.shell,
            "risk": self.risk,
            "provenance": self.provenance,
        }


class ToolRegistry:
    def __init__(self) -> None:
        self._tools: Dict[str, ToolSpec] = {}

    def register(self, spec: ToolSpec) -> None:
        if not spec.name or not spec.name.strip():
            raise ValueError("tool name is required")
        if not callable(spec.function):
            raise ValueError("tool {} function must be callable".format(spec.name))
        if spec.risk not in {"low", "medium", "high", "critical"}:
            raise ValueError("tool {} has invalid risk {!r}".format(spec.name, spec.risk))
        params = spec.parameters or {}
        if not isinstance(params, dict) or params.get("type", "object") != "object":
            raise ValueError(
                "tool {} parameters must be a JSON object schema".format(spec.name)
            )
        self._tools[spec.name] = spec

    def get(self, name: str) -> Optional[ToolSpec]:
        return self._tools.get(name)

    def require(self, name: str) -> ToolSpec:
        spec = self.get(name)
        if spec is None:
            raise KeyError("unknown tool: {}".format(name))
        return spec

    def list(self, include_hidden: bool = True) -> List[ToolSpec]:
        tools = [spec for spec in self._tools.values() if include_hidden or not spec.hidden]
        return sorted(tools, key=lambda item: item.name)

    def validate_arguments(self, spec: ToolSpec, arguments: Any) -> List[str]:
        """Return a list of argument errors (empty means valid)."""
        errors: List[str] = []
        if arguments is None:
            arguments = {}
        if not isinstance(arguments, dict):
            return ["arguments must be a JSON object"]
        schema = spec.parameters or {}
        properties = schema.get("properties") or {}
        if not isinstance(properties, dict):
            return ["parameters.properties must be an object"]
        for required in schema.get("required") or []:
            if required not in arguments:
                errors.append("missing required argument: {}".format(required))
        for name, value in arguments.items():
            prop = properties.get(name)
            if not isinstance(prop, dict):
                continue
            expected_type = prop.get("type")
            if expected_type and not _matches_type(value, expected_type):
                errors.append(
                    "argument {!r} must be of type {!r}".format(name, expected_type)
                )
        return errors

    def invoke(self, name: str, arguments: Any) -> Dict[str, Any]:
        spec = self.require(name)
        errors = self.validate_arguments(spec, arguments)
        if errors:
            return {
                "ok": False,
                "error": "invalid arguments",
                "errors": errors,
                "tool": name,
                "provenance": spec.provenance,
            }
        try:
            output = spec.function(arguments or {})
            return {
                "ok": True,
                "output": _jsonable(output),
                "tool": name,
                "writes": spec.writes,
                "network": spec.network,
                "mutation": spec.mutation,
                "shell": spec.shell,
                "risk": spec.risk,
                "provenance": spec.provenance,
            }
        except Exception as exc:  # tool failures are data, not crashes
            return {
                "ok": False,
                "error": "{}: {}".format(type(exc).__name__, str(exc)),
                "tool": name,
                "provenance": spec.provenance,
            }


def _jsonable(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, dict):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_jsonable(item) for item in value]
    if isinstance(value, (dt.datetime, dt.date, dt.time)):
        return value.isoformat()
    if isinstance(value, bytes):
        try:
            return value.decode("utf-8")
        except UnicodeDecodeError:
            return value.hex()
    return str(value)
