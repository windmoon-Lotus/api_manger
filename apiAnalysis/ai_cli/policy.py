"""Soft access presets, approval preferences and policy files for the AI CLI.

The policy is a user preference, not a permission boundary.  ``full-access +
never`` therefore means "execute without asking" instead of "add hidden
blocks".  Unknown capabilities are prompted by default and can be allowed or
denied through custom policy files or per-tool fragments.
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional


SCHEMA_VERSION = "ai.policy.v1"

ACCESS_PRESETS = ("read-only", "workspace-write", "full-access", "custom")
APPROVAL_PREFERENCES = ("always", "on-risk", "never")

# Canonical capability names used by ToolSpec and policy files.
CAP_PROJECT_READ = "project.read"
CAP_DATA_READ = "data.read"
CAP_FILESYSTEM_READ = "filesystem.read"
CAP_FILESYSTEM_WRITE = "filesystem.write"
CAP_NETWORK_REQUEST = "network.request"
CAP_COMMAND_SHELL = "command.shell"
CAP_API_MUTATION = "api.mutation"
CAP_PLUGIN = "plugin"

PRESET_CAPABILITIES: Dict[str, Dict[str, bool]] = {
    "read-only": {
        CAP_PROJECT_READ: True,
        CAP_DATA_READ: True,
        CAP_FILESYSTEM_READ: True,
        CAP_FILESYSTEM_WRITE: False,
        CAP_NETWORK_REQUEST: False,
        CAP_COMMAND_SHELL: False,
        CAP_API_MUTATION: False,
        CAP_PLUGIN: False,
    },
    "workspace-write": {
        CAP_PROJECT_READ: True,
        CAP_DATA_READ: True,
        CAP_FILESYSTEM_READ: True,
        CAP_FILESYSTEM_WRITE: True,
        CAP_NETWORK_REQUEST: False,
        CAP_COMMAND_SHELL: False,
        CAP_API_MUTATION: False,
        CAP_PLUGIN: False,
    },
    "full-access": {
        CAP_PROJECT_READ: True,
        CAP_DATA_READ: True,
        CAP_FILESYSTEM_READ: True,
        CAP_FILESYSTEM_WRITE: True,
        CAP_NETWORK_REQUEST: True,
        CAP_COMMAND_SHELL: True,
        CAP_API_MUTATION: True,
        CAP_PLUGIN: True,
    },
}


_DEFAULT_POLICY_DIR = os.path.join(
    os.path.expanduser("~"), ".api_manager", "ai_policy.d"
)


def default_policy_dir() -> str:
    return os.getenv("API_MANAGER_AI_POLICY_DIR") or _DEFAULT_POLICY_DIR


@dataclass
class AiPolicy:
    """Effective policy for one AI CLI session."""

    schema_version: str = SCHEMA_VERSION
    name: str = "default"
    access: str = "read-only"
    approval: str = "on-risk"
    capabilities: Dict[str, bool] = field(default_factory=dict)
    filesystem: Dict[str, Any] = field(default_factory=dict)
    network: Dict[str, Any] = field(default_factory=dict)
    commands: Dict[str, Any] = field(default_factory=dict)
    api_testing: Dict[str, Any] = field(default_factory=dict)
    evidence: Dict[str, Any] = field(default_factory=dict)
    allow_tools: Dict[str, bool] = field(default_factory=dict)
    fragment_dir: str = ""

    def validate(self) -> None:
        if self.access not in ACCESS_PRESETS:
            raise ValueError(
                "access must be one of {}".format(", ".join(ACCESS_PRESETS))
            )
        if self.approval not in APPROVAL_PREFERENCES:
            raise ValueError(
                "approval must be one of {}".format(", ".join(APPROVAL_PREFERENCES))
            )
        for capability, allowed in self.capabilities.items():
            if not isinstance(allowed, bool):
                raise ValueError(
                    "capability {} must be a boolean, got {!r}".format(
                        capability, allowed
                    )
                )

    def capability_status(self, capability: str) -> str:
        """Return ``allowed``, ``denied`` or ``unknown`` for a capability."""
        if capability in self.capabilities:
            return "allowed" if self.capabilities[capability] else "denied"
        preset = PRESET_CAPABILITIES.get(self.access)
        if preset and capability in preset:
            return "allowed" if preset[capability] else "denied"
        return "unknown"

    def allows(self, capability: str) -> Optional[bool]:
        status = self.capability_status(capability)
        if status == "allowed":
            return True
        if status == "denied":
            return False
        return None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "name": self.name,
            "access": self.access,
            "approval": self.approval,
            "capabilities": dict(sorted(self.capabilities.items())),
            "filesystem": self.filesystem,
            "network": self.network,
            "commands": self.commands,
            "api_testing": self.api_testing,
            "evidence": self.evidence,
            "allow_tools": dict(sorted(self.allow_tools.items())),
            "fragment_dir": self.fragment_dir or default_policy_dir(),
        }


def validate_access(access: str) -> str:
    if access not in ACCESS_PRESETS:
        raise ValueError(
            "access must be one of {}".format(", ".join(ACCESS_PRESETS))
        )
    return access


def validate_approval(approval: str) -> str:
    if approval not in APPROVAL_PREFERENCES:
        raise ValueError(
            "approval must be one of {}".format(", ".join(APPROVAL_PREFERENCES))
        )
    return approval


def _preset_capabilities(access: str) -> Dict[str, bool]:
    return dict(PRESET_CAPABILITIES.get(access) or {})


def _load_policy_json(path: Path) -> Dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError("policy file {} is not valid JSON: {}".format(path, exc))
    if not isinstance(payload, dict):
        raise ValueError("policy file {} must contain a JSON object".format(path))
    return payload


def policy_from_file(path: str) -> AiPolicy:
    """Load a custom policy file (JSON; TOML needs tomli/3.11+)."""
    policy_path = Path(path)
    if not policy_path.exists():
        raise FileNotFoundError("policy file not found: {}".format(path))
    if policy_path.suffix.lower() == ".toml":
        raise ValueError(
            "TOML policy files require Python 3.11+ (tomllib) or tomli; "
            "use a JSON policy file instead"
        )
    payload = _load_policy_json(policy_path)
    access = str(payload.get("access") or "").strip() or "custom"
    approval = str(payload.get("approval") or "").strip() or "on-risk"
    validate_access(access)
    validate_approval(approval)
    capabilities = dict(payload.get("capabilities") or {})
    if access == "custom":
        # Custom policies start from an empty capability set; anything not
        # explicitly listed stays "unknown" and is prompted.
        capabilities = dict(capabilities)
    else:
        base = _preset_capabilities(access)
        base.update(dict(capabilities))
        capabilities = base
    policy = AiPolicy(
        schema_version=str(payload.get("schema_version") or SCHEMA_VERSION),
        name=str(payload.get("name") or "custom"),
        access=access,
        approval=approval,
        capabilities=capabilities,
        filesystem=dict(payload.get("filesystem") or {}),
        network=dict(payload.get("network") or {}),
        commands=dict(payload.get("commands") or {}),
        api_testing=dict(payload.get("api_testing") or {}),
        evidence=dict(payload.get("evidence") or {}),
    )
    policy.validate()
    return policy


def _safe_fragment_name(tool_name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", tool_name).strip("._") or "tool"


def merge_fragments(policy: AiPolicy, policy_dir: Optional[str] = None) -> AiPolicy:
    """Merge per-tool approval fragments from ``policy_dir``."""
    directory = policy_dir or default_policy_dir()
    policy.fragment_dir = directory
    root = Path(directory)
    if not root.is_dir():
        return policy
    for path in sorted(root.glob("*.json")):
        try:
            payload = _load_policy_json(path)
        except ValueError:
            continue
        tool_name = str(payload.get("tool") or "").strip()
        if not tool_name:
            continue
        allow = bool(payload.get("allow", True))
        policy.allow_tools[tool_name] = allow
    return policy


def save_fragment(
    tool_name: str,
    allow: bool = True,
    policy_dir: Optional[str] = None,
) -> str:
    """Persist one per-tool approval fragment; returns the written path."""
    directory = policy_dir or default_policy_dir()
    root = Path(directory)
    root.mkdir(parents=True, exist_ok=True)
    path = root / "{}.json".format(_safe_fragment_name(tool_name))
    payload = {
        "schema_version": SCHEMA_VERSION,
        "tool": tool_name,
        "allow": bool(allow),
        "note": "generated by apiAnalysis.ai_cli approval prompt",
    }
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    return str(path)


def compose_policy(
    access: str = "read-only",
    approval: str = "on-risk",
    policy_file: Optional[str] = None,
    policy_dir: Optional[str] = None,
) -> AiPolicy:
    """Build the effective policy: preset -> policy file -> approval fragments."""
    validate_access(access)
    validate_approval(approval)
    if policy_file:
        loaded = policy_from_file(policy_file)
        # CLI access/approval arguments override the file only when the user
        # explicitly supplied them; defaults keep the file's own values.
        if access != "read-only" or approval != "on-risk":
            loaded.access = validate_access(access)
            loaded.approval = validate_approval(approval)
            if loaded.access != "custom" and loaded.access in PRESET_CAPABILITIES:
                base = _preset_capabilities(loaded.access)
                base.update(loaded.capabilities)
                loaded.capabilities = base
        return merge_fragments(loaded, policy_dir)
    base = _preset_capabilities(access)
    policy = AiPolicy(
        access=access,
        approval=approval,
        capabilities=base,
    )
    return merge_fragments(policy, policy_dir)


def safe_default_policy_json() -> Dict[str, Any]:
    """The suggested ``safe-default`` example from the design document."""
    return {
        "schema_version": SCHEMA_VERSION,
        "name": "safe-default",
        "access": "workspace-write",
        "approval": "on-risk",
        "capabilities": {
            CAP_PROJECT_READ: True,
            CAP_DATA_READ: True,
            CAP_FILESYSTEM_READ: True,
            CAP_FILESYSTEM_WRITE: True,
            CAP_NETWORK_REQUEST: False,
            CAP_COMMAND_SHELL: False,
            CAP_API_MUTATION: False,
            CAP_PLUGIN: False,
        },
        "filesystem": {"read": ["*"], "write": ["./apiAnalysis", "./tests", "./docs"]},
        "network": {"origins": [], "business_requests": False},
        "commands": {"shell": False, "allow": []},
        "api_testing": {
            "methods": ["GET", "HEAD", "OPTIONS"],
            "request_budget": 50,
            "concurrency": 1,
            "mutation": False,
            "cleanup_required": True,
        },
        "evidence": {"include_private": False, "redact_stdout": True},
    }
