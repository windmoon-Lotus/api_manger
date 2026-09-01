"""Deterministic fake tools used by tests and offline evaluations."""
from __future__ import annotations

from typing import Any, Dict

from .policy import (
    CAP_API_MUTATION,
    CAP_COMMAND_SHELL,
    CAP_FILESYSTEM_READ,
    CAP_FILESYSTEM_WRITE,
    CAP_NETWORK_REQUEST,
    CAP_PROJECT_READ,
)
from .registry import ToolRegistry, ToolSpec


_FAKE_STORE: Dict[str, Any] = {"writes": []}


def fake_echo(arguments: Dict[str, Any]) -> Dict[str, Any]:
    return {"echo": arguments.get("value")}


def fake_fs_read(arguments: Dict[str, Any]) -> Dict[str, Any]:
    path = str(arguments.get("path") or "")
    return {"path": path, "content": "fake content for {}".format(path)}


def fake_fs_write(arguments: Dict[str, Any]) -> Dict[str, Any]:
    path = str(arguments.get("path") or "")
    content = str(arguments.get("content") or "")
    _FAKE_STORE["writes"].append({"path": path, "content": content})
    return {"path": path, "written": True, "bytes": len(content.encode("utf-8"))}


def fake_net_get(arguments: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "url": arguments.get("url"),
        "status": 200,
        "body": {"ok": True, "sample": True},
    }


def fake_shell_run(arguments: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "command": arguments.get("command"),
        "exit_code": 0,
        "stdout": "fake stdout",
        "stderr": "",
    }


def fake_mutation(arguments: Dict[str, Any]) -> Dict[str, Any]:
    return {"mutation": "fake", "method": arguments.get("method", "POST"), "ok": True}


def register_fake_tools(registry: ToolRegistry) -> None:
    registry.register(ToolSpec(
        name="fake.echo",
        description="Return the supplied value unchanged.",
        parameters={
            "type": "object",
            "properties": {"value": {"type": "string"}},
        },
        function=fake_echo,
        capability=CAP_PROJECT_READ,
        risk="low",
        provenance="fake",
    ))
    registry.register(ToolSpec(
        name="fake.fs.read",
        description="Return canned file content for a path.",
        parameters={
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
        },
        function=fake_fs_read,
        capability=CAP_FILESYSTEM_READ,
        risk="low",
        provenance="fake",
    ))
    registry.register(ToolSpec(
        name="fake.fs.write",
        description="Record a canned file write in the in-memory fake store.",
        parameters={
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "content": {"type": "string"},
            },
            "required": ["path", "content"],
        },
        function=fake_fs_write,
        capability=CAP_FILESYSTEM_WRITE,
        writes=True,
        risk="medium",
        provenance="fake",
    ))
    registry.register(ToolSpec(
        name="fake.net.get",
        description="Return a canned HTTP 200 response without network access.",
        parameters={
            "type": "object",
            "properties": {"url": {"type": "string"}},
            "required": ["url"],
        },
        function=fake_net_get,
        capability=CAP_NETWORK_REQUEST,
        network=True,
        risk="medium",
        provenance="fake",
    ))
    registry.register(ToolSpec(
        name="fake.shell.run",
        description="Return canned shell output without executing anything.",
        parameters={
            "type": "object",
            "properties": {"command": {"type": "string"}},
            "required": ["command"],
        },
        function=fake_shell_run,
        capability=CAP_COMMAND_SHELL,
        shell=True,
        risk="high",
        provenance="fake",
    ))
    registry.register(ToolSpec(
        name="fake.mutation",
        description="Simulate a mutation API call.",
        parameters={
            "type": "object",
            "properties": {"method": {"type": "string", "default": "POST"}},
        },
        function=fake_mutation,
        capability=CAP_API_MUTATION,
        mutation=True,
        writes=True,
        risk="high",
        provenance="fake",
    ))
