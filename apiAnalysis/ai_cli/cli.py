"""Command-line entry for the AI-only protocol (A0).

Protocol contract:

- stdout carries only JSON/JSONL; logs go to stderr;
- exit codes: 0 success, 1 runtime/policy error, 2 usage, 10 approval
  required in non-interactive mode;
- long-running sessions emit a ``session_id`` so callers can correlate later
  audit or resume work;
- ``--yes`` and ``--approval never`` are explicit user decisions, while
  ``--dry-run`` reports what would run without invoking anything.
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import subprocess
import sys
from typing import Any, Dict, List, Optional

from . import __version__
from .policy import (
    ACCESS_PRESETS,
    APPROVAL_PREFERENCES,
    CAP_COMMAND_SHELL,
    AiPolicy,
    compose_policy,
    default_policy_dir,
    safe_default_policy_json,
)
from .provider import (
    FakeProvider,
    OpenAICompatibleProvider,
    ProviderError,
    ToolCall,
    default_providers,
    provider_factory,
)
from .registry import ToolRegistry, ToolSpec
from .session import (
    APPROVAL_EXIT_CODE,
    ApprovalGate,
    SessionLog,
    new_session_id,
    redact_arguments,
)
from .tasks import TASK_TOOL, merge_task_arguments, task_names
from .tools_fake import register_fake_tools
from .tools_audit import register_audit_tools
from .tools_project import register_project_tools


logger = logging.getLogger(__name__)

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2
STDOUT_TRUNCATE = 4000


def _configure_logging(level_name: str) -> None:
    level = getattr(logging, (level_name or "WARNING").upper(), logging.WARNING)
    logging.basicConfig(stream=sys.stderr, level=level, format="%(levelname)s %(name)s %(message)s")
    logging.getLogger("apiAnalysis").setLevel(level)


def emit(obj: Dict[str, Any]) -> None:
    print(json.dumps(obj, ensure_ascii=False, sort_keys=True))


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m apiAnalysis.ai_cli",
        description="AI-only CLI protocol with soft access policy and approval.",
    )
    parser.add_argument("--version", action="version", version=__version__)
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="WARNING",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    def add_policy_options(target: argparse.ArgumentParser) -> None:
        target.add_argument(
            "--access", choices=list(ACCESS_PRESETS), default="read-only",
            help="Access preset (default: read-only)",
        )
        target.add_argument(
            "--approval", choices=list(APPROVAL_PREFERENCES), default="on-risk",
            help="Approval preference (default: on-risk)",
        )
        target.add_argument("--policy", default="", help="Policy JSON file path.")
        target.add_argument(
            "--policy-dir", default="",
            help="Directory holding per-tool approval fragments.",
        )

    p = sub.add_parser("capabilities", help="List providers, tools and the effective policy.")
    add_policy_options(p)
    p.add_argument("--json", action="store_true", help="Emit JSON instead of a table.")

    p = sub.add_parser("policy", help="Show or validate the effective soft policy.")
    p.add_argument("action", nargs="?", choices=["show", "validate"], default="show")
    p.add_argument("file", nargs="?")
    add_policy_options(p)
    p.add_argument("--json", action="store_true")

    p = sub.add_parser(
        "run",
        help="Process JSON/JSONL tool requests, or run a provider agent loop.",
    )
    add_policy_options(p)
    p.add_argument("--project-id", default="")
    p.add_argument("--env-id", default="")
    p.add_argument("--yes", action="store_true", help="Approve every action for this session.")
    p.add_argument("--dry-run", action="store_true", help="Check policy/approval without invoking tools.")
    p.add_argument("--input", default="", help="JSON/JSONL request file, or '-' for stdin.")
    p.add_argument("--json", action="store_true", help="Emit JSON (default for run).")
    p.add_argument("--session-log", default="", help="Append JSONL audit entries to this file.")
    p.add_argument("--provider", default="", choices=["fake", "openai-compatible"], help="Run an internal agent loop.")
    p.add_argument("--goal", default="", help="Goal for the internal agent loop.")
    p.add_argument("--script", default="", help="JSON script file for the fake provider.")
    p.add_argument("--max-steps", type=int, default=20)

    p = sub.add_parser("task", help="Single-shot project task for external agents.")
    p.add_argument("task_name", choices=task_names())
    add_policy_options(p)
    p.add_argument("--project-id", default="")
    p.add_argument("--env-id", default="")
    p.add_argument("--input", default="", help="Context JSON file, or '-' for stdin.")
    p.add_argument("--yes", action="store_true")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--json", action="store_true")
    p.add_argument("--session-log", default="")

    p = sub.add_parser("shell", help="Run a Shell command with provenance=unmanaged.")
    add_policy_options(p)
    p.add_argument("--yes", action="store_true")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--json", action="store_true")
    p.add_argument("--session-log", default="")
    p.add_argument("--timeout", type=int, default=120)
    p.add_argument("argv", nargs="*", help="Shell command to run (after --).")
    return parser


def _policy_from_args(args: argparse.Namespace) -> AiPolicy:
    return compose_policy(
        access=getattr(args, "access", "read-only"),
        approval=getattr(args, "approval", "on-risk"),
        policy_file=getattr(args, "policy", "") or None,
        policy_dir=getattr(args, "policy_dir", "") or None,
    )


def _build_registry() -> ToolRegistry:
    registry = ToolRegistry()
    register_fake_tools(registry)
    register_audit_tools(registry)
    register_project_tools(registry)
    return registry


def _read_text_source(args: argparse.Namespace, flag: str = "input") -> str:
    source = getattr(args, flag, "") or ""
    if source == "-":
        return sys.stdin.read()
    if source:
        with open(source, "r", encoding="utf-8") as handle:
            return handle.read()
    if not sys.stdin.isatty():
        return sys.stdin.read()
    return ""


def _parse_json_requests(text: str) -> List[Dict[str, Any]]:
    stripped = text.strip()
    if not stripped:
        return []
    if stripped.startswith("["):
        payload = json.loads(stripped)
        return payload if isinstance(payload, list) else []
    if stripped.startswith("{"):
        payload = json.loads(stripped)
        return [payload]
    requests: List[Dict[str, Any]] = []
    for line in stripped.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        requests.append(json.loads(line))
    return requests


def _normalize_requests(raw_requests: List[Any]) -> List[Dict[str, Any]]:
    normalized: List[Dict[str, Any]] = []
    for raw in raw_requests:
        if not isinstance(raw, dict):
            continue
        if "tool" in raw:
            normalized.append(raw)
            continue
        if "tool_calls" in raw and isinstance(raw["tool_calls"], list):
            for call in raw["tool_calls"]:
                if isinstance(call, dict) and call.get("name"):
                    normalized.append({
                        "tool": call["name"],
                        "arguments": call.get("arguments") or {},
                    })
    return normalized


def _load_script(path: str) -> list:
    if not path:
        return []
    with open(path, "r", encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, list):
        raise ValueError("--script must contain a JSON array")
    steps: list = []
    for item in payload:
        if not isinstance(item, dict):
            continue
        if "tool_call" in item and isinstance(item["tool_call"], dict):
            steps.append(ToolCall(
                name=str(item["tool_call"].get("name") or ""),
                arguments=dict(item["tool_call"].get("arguments") or {}),
            ))
        elif "text" in item:
            steps.append(str(item["text"]))
    return steps


def _execute_one(
    seq: int,
    request: Dict[str, Any],
    registry: ToolRegistry,
    gate: ApprovalGate,
    session: SessionLog,
    dry_run: bool,
) -> int:
    """Execute one normalized request; returns the per-request exit code."""
    tool_name = str(request.get("tool") or "")
    arguments = request.get("arguments") or {}
    spec = registry.get(tool_name)
    if spec is None:
        emit({
            "seq": seq,
            "session_id": session.session_id,
            "tool": tool_name,
            "ok": False,
            "error": "unknown tool: {}".format(tool_name),
            "approval": "n/a",
        })
        session.record(seq=seq, tool=tool_name, ok=False, error="unknown_tool")
        return EXIT_ERROR

    decision = gate.decide(spec, arguments)
    if decision.action == "approval_required":
        emit({
            "seq": seq,
            "session_id": session.session_id,
            "tool": tool_name,
            "ok": False,
            "approval": "approval_required",
            "message": "approval required; rerun with --yes, --approval never, or approve interactively",
            "arguments": redact_arguments(arguments),
        })
        session.record(seq=seq, tool=tool_name, ok=False, approval="approval_required")
        return APPROVAL_EXIT_CODE
    if decision.action == "denied":
        emit({
            "seq": seq,
            "session_id": session.session_id,
            "tool": tool_name,
            "ok": False,
            "approval": "denied",
            "error": "denied: {}".format(decision.reason),
            "arguments": redact_arguments(arguments),
        })
        session.record(seq=seq, tool=tool_name, ok=False, approval="denied", reason=decision.reason)
        return EXIT_ERROR

    if dry_run:
        emit({
            "seq": seq,
            "session_id": session.session_id,
            "tool": tool_name,
            "ok": True,
            "approval": decision.action,
            "dry_run": True,
            "would_run": True,
            "capability": spec.capability,
            "risk": spec.risk,
            "arguments": redact_arguments(arguments),
        })
        session.record(seq=seq, tool=tool_name, ok=True, dry_run=True, approval=decision.action)
        return EXIT_OK

    result = registry.invoke(tool_name, arguments)
    emit({
        "seq": seq,
        "session_id": session.session_id,
        "tool": tool_name,
        "ok": result.get("ok", False),
        "approval": decision.action,
        "provenance": result.get("provenance"),
        "output" if result.get("ok") else "error": (
            result.get("output") if result.get("ok") else result.get("error")
        ),
    })
    session.record(
        seq=seq,
        tool=tool_name,
        ok=result.get("ok", False),
        approval=decision.action,
        provenance=result.get("provenance"),
    )
    return EXIT_OK if result.get("ok") else EXIT_ERROR


def _cmd_capabilities(args: argparse.Namespace) -> int:
    policy = _policy_from_args(args)
    registry = _build_registry()
    providers = [
        {
            "id": provider_id,
            "display_name": provider.display_name,
            "available": True,
        }
        for provider_id, provider in default_providers().items()
    ]
    payload = {
        "schema_version": "ai.cli.capabilities.v1",
        "providers": providers,
        "presets": list(ACCESS_PRESETS),
        "approval_preferences": list(APPROVAL_PREFERENCES),
        "commands": ["capabilities", "policy", "run", "task", "shell"],
        "tools": [spec.to_dict() for spec in registry.list()],
        "policy": policy.to_dict(),
        "safe_default_policy": safe_default_policy_json(),
    }
    if args.json:
        emit(payload)
        return EXIT_OK
    print("providers: {}".format(", ".join(item["id"] for item in providers)))
    print("presets: {}".format(", ".join(payload["presets"])))
    print("approval: {}".format(", ".join(payload["approval_preferences"])))
    print("commands: {}".format(", ".join(payload["commands"])))
    print("tools:")
    for spec in payload["tools"]:
        print("  {} [{} risk={} writes={} network={} mutation={} shell={}] -> {}".format(
            spec["name"], spec["provenance"], spec["risk"], spec["writes"],
            spec["network"], spec["mutation"], spec["shell"], spec["description"],
        ))
    print("effective policy: access={} approval={}".format(
        policy.access, policy.approval,
    ))
    return EXIT_OK


def _cmd_policy(args: argparse.Namespace) -> int:
    action = args.action or "show"
    if action == "validate":
        if not args.file:
            print("usage: policy validate <file>", file=sys.stderr)
            return EXIT_USAGE
        from .policy import policy_from_file

        try:
            policy = policy_from_file(args.file)
        except (ValueError, FileNotFoundError) as exc:
            emit({"ok": False, "error": str(exc)})
            return EXIT_ERROR
        emit({"ok": True, "policy": policy.to_dict()})
        return EXIT_OK
    policy = _policy_from_args(args)
    if args.json:
        emit(policy.to_dict())
        return EXIT_OK
    payload = policy.to_dict()
    print("name: {}".format(payload["name"]))
    print("access: {}".format(payload["access"]))
    print("approval: {}".format(payload["approval"]))
    for capability, allowed in payload["capabilities"].items():
        print("  {}: {}".format(capability, "allow" if allowed else "deny"))
    return EXIT_OK


def _cmd_run(args: argparse.Namespace) -> int:
    policy = _policy_from_args(args)
    registry = _build_registry()
    session = SessionLog(new_session_id(), path=args.session_log or None)
    gate = ApprovalGate(policy, yes=args.yes, session=session)
    if args.provider:
        return _run_provider_loop(args, policy, registry, session, gate)
    try:
        text = _read_text_source(args)
        raw_requests = _parse_json_requests(text)
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        emit({"ok": False, "error": "invalid input: {}".format(exc)})
        return EXIT_ERROR
    requests = _normalize_requests(raw_requests)
    if not requests and raw_requests:
        emit({"ok": False, "error": "input contains no recognizable tool requests"})
        return EXIT_ERROR
    if not requests:
        emit({"session_id": session.session_id, "ok": True, "processed": 0})
        return EXIT_OK
    worst = EXIT_OK
    for seq, request in enumerate(requests, start=1):
        code = _execute_one(seq, request, registry, gate, session, args.dry_run)
        if code == APPROVAL_EXIT_CODE:
            worst = APPROVAL_EXIT_CODE
        elif code != EXIT_OK and worst != APPROVAL_EXIT_CODE:
            worst = EXIT_ERROR
    return worst


def _run_provider_loop(
    args: argparse.Namespace,
    policy: AiPolicy,
    registry: ToolRegistry,
    session: SessionLog,
    gate: ApprovalGate,
) -> int:
    try:
        script = _load_script(args.script)
        provider = provider_factory(args.provider, script=script)
    except (ValueError, OSError, ProviderError, json.JSONDecodeError) as exc:
        emit({"ok": False, "error": str(exc)})
        return EXIT_ERROR
    goal = args.goal or ""
    if not goal:
        try:
            text = _read_text_source(args)
            requests = _parse_json_requests(text)
        except (ValueError, OSError, json.JSONDecodeError) as exc:
            emit({"ok": False, "error": "invalid goal/input: {}".format(exc)})
            return EXIT_ERROR
        if isinstance(requests, list) and requests and isinstance(requests[0], dict):
            goal = str(requests[0].get("goal") or requests[0].get("content") or "")
    messages: List[Dict[str, Any]] = [{"role": "user", "content": goal or "complete the task"}]
    worst = EXIT_OK
    for step in range(1, max(1, args.max_steps) + 1):
        try:
            result = provider.invoke(messages, tools=registry.list())
        except ProviderError as exc:
            emit({"step": step, "ok": False, "error": str(exc)})
            return EXIT_ERROR
        if result.tool_calls:
            for call in result.tool_calls:
                spec = registry.get(call.name)
                if spec is None:
                    emit({"step": step, "tool": call.name, "ok": False, "error": "unknown tool"})
                    worst = EXIT_ERROR
                    continue
                decision = gate.decide(spec, call.arguments)
                if decision.action == "approval_required":
                    emit({
                        "step": step,
                        "tool": call.name,
                        "ok": False,
                        "approval": "approval_required",
                        "message": "approval required; rerun with --yes or --approval never",
                    })
                    return APPROVAL_EXIT_CODE
                if decision.action == "denied":
                    emit({
                        "step": step, "tool": call.name, "ok": False,
                        "approval": "denied", "error": decision.reason,
                    })
                    worst = EXIT_ERROR
                    messages.append({
                        "role": "tool",
                        "tool_call_id": call.name,
                        "content": json.dumps({"skipped": "denied"}),
                    })
                    continue
                if args.dry_run:
                    emit({
                        "step": step, "tool": call.name, "ok": True,
                        "approval": decision.action, "dry_run": True,
                    })
                    messages.append({
                        "role": "tool",
                        "tool_call_id": call.name,
                        "content": json.dumps({"dry_run": True}),
                    })
                    continue
                outcome = registry.invoke(call.name, call.arguments)
                emit({
                    "step": step,
                    "tool": call.name,
                    "ok": outcome.get("ok", False),
                    "approval": decision.action,
                    "provenance": outcome.get("provenance"),
                    "output" if outcome.get("ok") else "error": (
                        outcome.get("output") if outcome.get("ok") else outcome.get("error")
                    ),
                })
                session.record(
                    step=step, tool=call.name, ok=outcome.get("ok", False),
                    approval=decision.action, provenance=outcome.get("provenance"),
                )
                if not outcome.get("ok"):
                    worst = EXIT_ERROR
                messages.append({
                    "role": "tool",
                    "tool_call_id": call.name,
                    "content": json.dumps(outcome, ensure_ascii=False, sort_keys=True),
                })
        else:
            emit({
                "step": step,
                "ok": True,
                "finish": True,
                "content": result.content,
                "model": result.model or provider.provider_id,
            })
            break
    return worst


def _cmd_task(args: argparse.Namespace) -> int:
    policy = _policy_from_args(args)
    registry = _build_registry()
    session = SessionLog(new_session_id(), path=args.session_log or None)
    gate = ApprovalGate(policy, yes=args.yes, session=session)
    input_payload: Any = None
    if args.input:
        try:
            text = _read_text_source(args)
            input_payload = json.loads(text) if text.strip() else None
        except (ValueError, OSError, json.JSONDecodeError) as exc:
            emit({"ok": False, "error": "invalid task input: {}".format(exc)})
            return EXIT_ERROR
    cli_values = {
        "project_id": args.project_id,
        "env_id": args.env_id,
    }
    arguments = merge_task_arguments(args.task_name, cli_values, input_payload)
    tool_name = TASK_TOOL[args.task_name]
    request = {"tool": tool_name, "arguments": arguments}
    code = _execute_one(1, request, registry, gate, session, args.dry_run)
    return code


def _shell_spec() -> ToolSpec:
    def _unused(_: Dict[str, Any]) -> Any:
        raise RuntimeError("shell is executed by the ai_cli shell command")

    return ToolSpec(
        name="shell",
        description="Run a Shell command (provenance=unmanaged).",
        parameters={
            "type": "object",
            "properties": {"command": {"type": "string"}},
            "required": ["command"],
        },
        function=_unused,
        capability=CAP_COMMAND_SHELL,
        shell=True,
        risk="high",
        provenance="unmanaged",
    )


def _cmd_shell(args: argparse.Namespace) -> int:
    command = list(args.argv or [])
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        print("usage: ai_cli shell [options] -- <command> <args...>", file=sys.stderr)
        return EXIT_USAGE
    policy = _policy_from_args(args)
    session = SessionLog(new_session_id(), path=args.session_log or None)
    gate = ApprovalGate(policy, yes=args.yes, session=session)
    spec = _shell_spec()
    command_text = " ".join(command)
    decision = gate.decide(spec, {"command": command_text})
    if decision.action == "approval_required":
        emit({
            "session_id": session.session_id,
            "command": command_text,
            "ok": False,
            "approval": "approval_required",
            "message": "approval required; rerun with --yes or --approval never",
        })
        return APPROVAL_EXIT_CODE
    if decision.action == "denied":
        emit({
            "session_id": session.session_id,
            "command": command_text,
            "ok": False,
            "approval": "denied",
            "error": "denied: {}".format(decision.reason),
        })
        return EXIT_ERROR
    if args.dry_run:
        emit({
            "session_id": session.session_id,
            "command": command_text,
            "ok": True,
            "approval": decision.action,
            "dry_run": True,
            "would_run": True,
            "provenance": "unmanaged",
        })
        return EXIT_OK
    started = None
    try:
        proc = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=max(1, int(args.timeout or 120)),
        )
        started = True
        stdout = (proc.stdout or "")[-STDOUT_TRUNCATE:]
        stderr = (proc.stderr or "")[-STDOUT_TRUNCATE:]
        emit({
            "session_id": session.session_id,
            "command": command_text,
            "ok": proc.returncode == 0,
            "exit_code": proc.returncode,
            "stdout": stdout,
            "stderr": stderr,
            "approval": decision.action,
            "provenance": "unmanaged",
        })
        session.record(
            command=command_text, ok=proc.returncode == 0,
            exit_code=proc.returncode, provenance="unmanaged", approval=decision.action,
        )
        return EXIT_OK if proc.returncode == 0 else EXIT_ERROR
    except subprocess.TimeoutExpired as exc:
        emit({
            "session_id": session.session_id,
            "command": command_text,
            "ok": False,
            "error": "command timed out after {}s".format(args.timeout),
            "stdout": (exc.stdout or "")[-STDOUT_TRUNCATE:],
            "stderr": (exc.stderr or "")[-STDOUT_TRUNCATE:],
            "approval": decision.action,
            "provenance": "unmanaged",
        })
        session.record(command=command_text, ok=False, error="timeout", provenance="unmanaged")
        return EXIT_ERROR
    except OSError as exc:
        emit({
            "session_id": session.session_id,
            "command": command_text,
            "ok": False,
            "error": "cannot start command: {}".format(exc),
            "approval": decision.action,
            "provenance": "unmanaged",
        })
        session.record(command=command_text, ok=False, error="os_error", provenance="unmanaged")
        return EXIT_ERROR


def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    _configure_logging(args.log_level)
    command = args.command
    try:
        if command == "capabilities":
            return _cmd_capabilities(args)
        if command == "policy":
            return _cmd_policy(args)
        if command == "run":
            return _cmd_run(args)
        if command == "task":
            return _cmd_task(args)
        if command == "shell":
            return _cmd_shell(args)
    except KeyboardInterrupt:
        emit({"ok": False, "error": "interrupted"})
        return EXIT_ERROR
    except Exception as exc:  # last-resort protocol error
        emit({"ok": False, "error": "{}: {}".format(type(exc).__name__, str(exc))})
        return EXIT_ERROR
    parser.error("unknown command: {}".format(command))
    return EXIT_USAGE
