"""Approval gate, prompts and session audit for AI CLI runs."""
from __future__ import annotations

import json
import sys
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, TextIO

from .policy import AiPolicy, save_fragment
from .registry import ToolSpec


APPROVAL_EXIT_CODE = 10


@dataclass
class ApprovalDecision:
    action: str  # approved | denied | approval_required
    reason: str = ""


class SessionLog:
    """In-memory audit trail, optionally appended to a JSONL file."""

    def __init__(self, session_id: str, path: Optional[str] = None) -> None:
        self.session_id = session_id
        self.path = path
        self.entries: List[Dict[str, Any]] = []

    def record(self, **entry: Any) -> None:
        entry["session_id"] = self.session_id
        entry["ts"] = time.time()
        self.entries.append(entry)
        if self.path:
            with open(self.path, "a", encoding="utf-8") as handle:
                handle.write(
                    json.dumps(entry, ensure_ascii=False, sort_keys=True) + "\n"
                )


_SENSITIVE_KEY_PARTS = (
    "token",
    "password",
    "secret",
    "authorization",
    "cookie",
    "api_key",
    "apikey",
    "access_key",
    "private",
    "credential",
)


def redact_arguments(arguments: Dict[str, Any]) -> Dict[str, Any]:
    """Mask likely-secret argument values before display or logging."""
    if not isinstance(arguments, dict):
        return arguments
    redacted: Dict[str, Any] = {}
    for key, value in arguments.items():
        lowered = str(key).lower()
        if any(part in lowered for part in _SENSITIVE_KEY_PARTS):
            redacted[key] = "***"
        elif isinstance(value, dict):
            redacted[key] = redact_arguments(value)
        elif isinstance(value, list):
            redacted[key] = [
                redact_arguments(item) if isinstance(item, dict) else item
                for item in value
            ]
        else:
            redacted[key] = value
    return redacted


class ApprovalGate:
    """Decide whether a tool call executes, prompts, or is denied."""

    def __init__(
        self,
        policy: AiPolicy,
        *,
        yes: bool = False,
        interactive: Optional[bool] = None,
        stdin: Optional[TextIO] = None,
        stdout: Optional[TextIO] = None,
        session: Optional[SessionLog] = None,
    ) -> None:
        self.policy = policy
        self.yes = yes
        self.interactive = sys.stdin.isatty() if interactive is None else interactive
        self.stdin = stdin or sys.stdin
        self.stdout = stdout or sys.stdout
        self.session = session
        self.session_allow: set = set()

    def decide(self, spec: ToolSpec, arguments: Dict[str, Any]) -> ApprovalDecision:
        status = self.policy.capability_status(spec.capability)
        if status == "denied":
            return ApprovalDecision("denied", "policy_denied:{}".format(spec.capability))
        if self.yes:
            return ApprovalDecision("approved", "yes_flag")
        if self.policy.allow_tools.get(spec.name) is True:
            return ApprovalDecision("approved", "always_allowed_rule")
        if spec.name in self.session_allow:
            return ApprovalDecision("approved", "session_allow")
        if self.policy.approval == "never":
            return ApprovalDecision("approved", "approval_never")
        if self.policy.approval == "always":
            needs_prompt = bool(
                spec.writes or spec.network or spec.shell or spec.mutation
            )
        else:  # on-risk
            needs_prompt = bool(
                spec.risk in {"high", "critical"}
                or spec.mutation
                or spec.shell
            )
        if not needs_prompt:
            return ApprovalDecision("approved", "auto_not_risky")
        if not self.interactive:
            return ApprovalDecision("approval_required", "non_interactive")
        choice = self._prompt(spec, redact_arguments(arguments))
        if choice == 4:
            return ApprovalDecision("denied", "user_denied")
        if choice == 1:
            return ApprovalDecision("approved", "once")
        if choice == 2:
            self.session_allow.add(spec.name)
            return ApprovalDecision("approved", "session")
        if choice == 3:
            save_fragment(spec.name, allow=True, policy_dir=self.policy.fragment_dir)
            return ApprovalDecision("approved", "always_rule")
        return ApprovalDecision("denied", "user_denied")

    def _prompt(self, spec: ToolSpec, arguments: Dict[str, Any]) -> int:
        flags = []
        if spec.writes:
            flags.append("writes")
        if spec.network:
            flags.append("network")
        if spec.mutation:
            flags.append("mutation")
        if spec.shell:
            flags.append("shell")
        lines = [
            "AI 请求执行：",
            "  tool: {}".format(spec.name),
            "  description: {}".format(spec.description),
            "  arguments: {}".format(
                json.dumps(arguments, ensure_ascii=False, sort_keys=True)
            ),
            "  capability: {} (risk={})".format(spec.capability, spec.risk),
            "  flags: {}".format(",".join(flags) or "read-only"),
            "[1] 本次允许  [2] 本会话允许  [3] 总是允许此规则  [4] 拒绝",
        ]
        self.stdout.write("\n".join(lines) + "\n> ")
        self.stdout.flush()
        raw = self.stdin.readline()
        if not raw:
            return 4
        try:
            return int(raw.strip())
        except (TypeError, ValueError):
            return 4


def new_session_id() -> str:
    return uuid.uuid4().hex
