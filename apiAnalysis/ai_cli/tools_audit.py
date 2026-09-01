"""Read-only post-run audit tools exposed to AI sessions.

These tools only read caller-supplied local artifacts. They never send HTTP
requests, mutate project state, or write reports. Live SQLi execution remains
behind the managed project plan/scheduler adapter and cleanup sweeps remain an
operator-controlled network command.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Optional

from .policy import CAP_FILESYSTEM_READ
from .registry import ToolRegistry, ToolSpec


def _load_json(path: str) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8-sig"))


def _boundary(arguments: Dict[str, Any]) -> Dict[str, Any]:
    from tools.audit.boundary_audit import audit_transcript

    transcript = Path(str(arguments.get("transcript") or ""))
    scope = _load_json(str(arguments.get("scope") or ""))
    if not isinstance(scope, dict):
        raise ValueError("scope must contain a JSON object")
    return audit_transcript(transcript, scope)


def _evidence_verify(arguments: Dict[str, Any]) -> Dict[str, Any]:
    from tools.audit.evidence_verify import verify_evidence

    evidence = _load_json(str(arguments.get("evidence") or ""))
    if not isinstance(evidence, dict):
        raise ValueError("evidence must contain a JSON object")
    return verify_evidence(evidence)


def _coverage(arguments: Dict[str, Any]) -> Dict[str, Any]:
    from tools.audit.coverage_report import coverage, extract_keys

    key_field = str(arguments.get("key_field") or "key")

    def keys(name: str) -> list:
        path: Optional[str] = arguments.get(name)
        return extract_keys(_load_json(str(path)), key_field) if path else []

    return coverage(keys("total"), keys("candidates"), keys("tested"))


def register_audit_tools(registry: ToolRegistry) -> None:
    common = {
        "capability": CAP_FILESYSTEM_READ,
        "writes": False,
        "network": False,
        "mutation": False,
        "shell": False,
        "risk": "low",
        "provenance": "managed",
    }
    registry.register(ToolSpec(
        name="audit.boundary",
        description="Audit a local stream-json transcript against a local scope file.",
        parameters={
            "type": "object",
            "properties": {
                "transcript": {"type": "string"},
                "scope": {"type": "string"},
            },
            "required": ["transcript", "scope"],
        },
        function=_boundary,
        **common,
    ))
    registry.register(ToolSpec(
        name="audit.evidence_verify",
        description="Recompute stored SQLi screening verdicts from a local evidence file.",
        parameters={
            "type": "object",
            "properties": {"evidence": {"type": "string"}},
            "required": ["evidence"],
        },
        function=_evidence_verify,
        **common,
    ))
    registry.register(ToolSpec(
        name="audit.coverage",
        description="Compare local total, candidate and tested endpoint sets.",
        parameters={
            "type": "object",
            "properties": {
                "total": {"type": "string"},
                "candidates": {"type": "string"},
                "tested": {"type": "string"},
                "key_field": {"type": "string", "default": "key"},
            },
            "required": ["total", "candidates", "tested"],
        },
        function=_coverage,
        **common,
    ))
