"""Tests for the A0 AI CLI protocol and soft policy (apiAnalysis.ai_cli)."""
from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from apiAnalysis.ai_cli.policy import (
    ACCESS_PRESETS,
    APPROVAL_PREFERENCES,
    CAP_COMMAND_SHELL,
    CAP_FILESYSTEM_WRITE,
    AiPolicy,
    compose_policy,
    merge_fragments,
    policy_from_file,
    safe_default_policy_json,
    save_fragment,
)
from apiAnalysis.ai_cli.provider import (
    FakeProvider,
    OpenAICompatibleProvider,
    ProviderError,
    ToolCall,
    _parse_chat_completion,
    provider_factory,
)
from apiAnalysis.ai_cli.registry import ToolRegistry, ToolSpec
from apiAnalysis.ai_cli.session import (
    APPROVAL_EXIT_CODE,
    ApprovalGate,
    SessionLog,
    redact_arguments,
)
from apiAnalysis.ai_cli.tools_fake import register_fake_tools


REPO_ROOT = Path(__file__).resolve().parent.parent


def run_cli(*argv: str, stdin: str = "", cwd: Path = REPO_ROOT) -> subprocess.CompletedProcess:
    """Run the ai_cli module in a subprocess and capture stdout/stderr."""
    return subprocess.run(
        [sys.executable, "-m", "apiAnalysis.ai_cli"] + list(argv),
        cwd=str(cwd),
        input=stdin,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=120,
    )


def parse_jsonl(text: str):
    return [json.loads(line) for line in text.splitlines() if line.strip()]


def make_registry() -> ToolRegistry:
    registry = ToolRegistry()
    register_fake_tools(registry)
    return registry


def spec_shell() -> ToolSpec:
    return ToolSpec(
        name="test.shell",
        description="shell for tests",
        parameters={
            "type": "object",
            "properties": {"command": {"type": "string"}},
            "required": ["command"],
        },
        function=lambda args: {"ok": True},
        capability=CAP_COMMAND_SHELL,
        shell=True,
        risk="high",
        provenance="unmanaged",
    )


class PolicyTestCase(unittest.TestCase):
    def test_presets(self):
        self.assertEqual(
            compose_policy("read-only", "on-risk").capability_status(CAP_FILESYSTEM_WRITE),
            "denied",
        )
        self.assertEqual(
            compose_policy("full-access", "never").capability_status(CAP_COMMAND_SHELL),
            "allowed",
        )
        self.assertEqual(
            compose_policy("workspace-write", "on-risk").capability_status(
                CAP_COMMAND_SHELL
            ),
            "denied",
        )

    def test_presets_and_preferences_are_exposed(self):
        self.assertIn("custom", ACCESS_PRESETS)
        self.assertIn("never", APPROVAL_PREFERENCES)

    def test_policy_from_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "policy.json"
            path.write_text(
                json.dumps(
                    {
                        "schema_version": "ai.policy.v1",
                        "name": "custom-test",
                        "access": "custom",
                        "approval": "never",
                        "capabilities": {CAP_FILESYSTEM_WRITE: True},
                    }
                ),
                encoding="utf-8",
            )
            policy = policy_from_file(str(path))
            self.assertEqual(policy.name, "custom-test")
            self.assertEqual(policy.access, "custom")
            self.assertEqual(policy.approval, "never")
            self.assertTrue(policy.capabilities[CAP_FILESYSTEM_WRITE])
            # unknown capability stays unknown (prompted) in custom mode
            self.assertIsNone(policy.allows("command.shell"))

    def test_policy_from_file_rejects_toml(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "policy.toml"
            path.write_text("access = 'full-access'\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                policy_from_file(str(path))

    def test_policy_from_file_rejects_bad_access(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "policy.json"
            path.write_text('{"access": "root"}', encoding="utf-8")
            with self.assertRaises(ValueError):
                policy_from_file(str(path))

    def test_fragment_save_and_merge(self):
        with tempfile.TemporaryDirectory() as tmp:
            policy = compose_policy("full-access", "on-risk", policy_dir=tmp)
            saved = save_fragment("fake.fs.write", allow=True, policy_dir=tmp)
            self.assertTrue(Path(saved).is_file())
            merged = merge_fragments(policy, policy_dir=tmp)
            self.assertTrue(merged.allow_tools.get("fake.fs.write"))

    def test_compose_policy_merges_file_and_fragments(self):
        with tempfile.TemporaryDirectory() as tmp:
            policy_path = Path(tmp) / "policy.json"
            policy_path.write_text(
                json.dumps({"access": "full-access", "approval": "on-risk"}),
                encoding="utf-8",
            )
            save_fragment("fake.echo", allow=True, policy_dir=tmp)
            policy = compose_policy(
                "full-access", "on-risk", policy_file=str(policy_path), policy_dir=tmp
            )
            self.assertEqual(policy.access, "full-access")
            self.assertTrue(policy.allow_tools.get("fake.echo"))

    def test_safe_default_policy_json(self):
        payload = safe_default_policy_json()
        self.assertEqual(payload["schema_version"], "ai.policy.v1")
        self.assertEqual(payload["access"], "workspace-write")
        self.assertEqual(payload["approval"], "on-risk")
        self.assertFalse(payload["capabilities"][CAP_COMMAND_SHELL])

    def test_validate_rejects_non_boolean_capability(self):
        policy = AiPolicy(access="custom", approval="never", capabilities={"x": "yes"})
        with self.assertRaises(ValueError):
            policy.validate()


class RegistryTestCase(unittest.TestCase):
    def setUp(self):
        self.registry = make_registry()

    def test_register_and_list(self):
        names = [spec.name for spec in self.registry.list()]
        for expected in (
            "fake.echo",
            "fake.fs.read",
            "fake.fs.write",
            "fake.net.get",
            "fake.shell.run",
            "fake.mutation",
        ):
            self.assertIn(expected, names)

    def test_invoke_echo(self):
        result = self.registry.invoke("fake.echo", {"value": "hi"})
        self.assertTrue(result["ok"])
        self.assertEqual(result["output"], {"echo": "hi"})
        self.assertEqual(result["provenance"], "fake")

    def test_invoke_missing_required_argument(self):
        result = self.registry.invoke("fake.fs.write", {"path": "x"})
        self.assertFalse(result["ok"])
        self.assertIn("missing required argument", result["errors"][0])

    def test_invoke_wrong_type(self):
        result = self.registry.invoke("fake.fs.read", {"path": 123})
        self.assertFalse(result["ok"])
        self.assertIn("must be of type", result["errors"][0])

    def test_invoke_unknown_tool_raises(self):
        with self.assertRaises(KeyError):
            self.registry.invoke("no.such.tool", {})

    def test_register_rejects_invalid_risk(self):
        with self.assertRaises(ValueError):
            self.registry.register(ToolSpec(
                name="bad.risk",
                description="x",
                parameters={"type": "object", "properties": {}},
                function=lambda args: None,
                risk="extreme",
            ))

    def test_register_rejects_non_object_schema(self):
        with self.assertRaises(ValueError):
            self.registry.register(ToolSpec(
                name="bad.schema",
                description="x",
                parameters={"type": "array"},
                function=lambda args: None,
            ))


class ProviderTestCase(unittest.TestCase):
    def test_fake_provider_script(self):
        provider = FakeProvider(
            script=[ToolCall(name="fake.echo", arguments={"value": "x"}), "finished"]
        )
        first = provider.invoke([], tools=[])
        self.assertEqual([call.name for call in first.tool_calls], ["fake.echo"])
        second = provider.invoke([], tools=[])
        self.assertEqual(second.content, "finished")
        third = provider.invoke([], tools=[])
        self.assertEqual(third.content, "done")
        self.assertEqual(provider.invoke_count, 3)
        self.assertEqual(provider.last_request["tools"], [])

    def test_provider_factory(self):
        self.assertIsInstance(provider_factory("fake"), FakeProvider)
        self.assertIsInstance(
            provider_factory("openai-compatible", base_url="http://localhost:1"),
            OpenAICompatibleProvider,
        )
        with self.assertRaises(ProviderError):
            provider_factory("nope")

    def test_parse_chat_completion(self):
        body = {
            "model": "test-model",
            "choices": [
                {
                    "message": {
                        "content": "hello",
                        "tool_calls": [
                            {
                                "function": {
                                    "name": "fake.echo",
                                    "arguments": '{"value": "x"}',
                                }
                            }
                        ],
                    }
                }
            ],
        }
        result = _parse_chat_completion(body)
        self.assertEqual(result.content, "hello")
        self.assertEqual(result.model, "test-model")
        self.assertEqual(result.tool_calls[0].name, "fake.echo")
        self.assertEqual(result.tool_calls[0].arguments, {"value": "x"})

    def test_openai_provider_requires_endpoint(self):
        provider = OpenAICompatibleProvider(base_url="", api_key="")
        with self.assertRaises(ProviderError):
            provider.invoke([{"role": "user", "content": "hi"}])


class RedactTestCase(unittest.TestCase):
    def test_masks_sensitive_keys(self):
        redacted = redact_arguments(
            {
                "token": "abc",
                "password": "p",
                "safe": "ok",
                "nested": {"api_key": "k", "keep": 1},
                "items": [{"secret": "s"}],
            }
        )
        self.assertEqual(redacted["token"], "***")
        self.assertEqual(redacted["password"], "***")
        self.assertEqual(redacted["safe"], "ok")
        self.assertEqual(redacted["nested"], {"api_key": "***", "keep": 1})
        self.assertEqual(redacted["items"], [{"secret": "***"}])


class ApprovalGateTestCase(unittest.TestCase):
    def make_gate(self, policy: AiPolicy, **kwargs):
        return ApprovalGate(policy, **kwargs)

    def test_never_approves(self):
        gate = self.make_gate(compose_policy("full-access", "never"))
        decision = gate.decide(spec_shell(), {"command": "x"})
        self.assertEqual(decision.action, "approved")

    def test_yes_approves_high_risk(self):
        gate = self.make_gate(
            compose_policy("full-access", "on-risk"), yes=True
        )
        decision = gate.decide(spec_shell(), {"command": "x"})
        self.assertEqual(decision.action, "approved")

    def test_policy_denial_wins(self):
        gate = self.make_gate(compose_policy("read-only", "never"))
        decision = gate.decide(spec_shell(), {"command": "x"})
        self.assertEqual(decision.action, "denied")
        self.assertIn("policy_denied", decision.reason)

    def test_low_risk_auto_approved_on_risk(self):
        registry = make_registry()
        spec = registry.get("fake.echo")
        gate = self.make_gate(compose_policy("read-only", "on-risk"))
        decision = gate.decide(spec, {"value": "x"})
        self.assertEqual(decision.action, "approved")

    def test_high_risk_non_interactive_requires_approval(self):
        gate = self.make_gate(
            compose_policy("full-access", "on-risk"),
            interactive=False,
        )
        decision = gate.decide(spec_shell(), {"command": "x"})
        self.assertEqual(decision.action, "approval_required")

    def test_always_non_interactive_requires_approval_for_write(self):
        registry = make_registry()
        spec = registry.get("fake.fs.write")
        gate = self.make_gate(
            compose_policy("full-access", "always"),
            interactive=False,
        )
        decision = gate.decide(spec, {"path": "a", "content": "b"})
        self.assertEqual(decision.action, "approval_required")

    def test_interactive_once(self):
        gate = self.make_gate(
            compose_policy("full-access", "on-risk"),
            interactive=True,
            stdin=io.StringIO("1\n"),
            stdout=io.StringIO(),
        )
        decision = gate.decide(spec_shell(), {"command": "x"})
        self.assertEqual(decision.action, "approved")

    def test_interactive_session_allow(self):
        gate = self.make_gate(
            compose_policy("full-access", "on-risk"),
            interactive=True,
            stdin=io.StringIO("2\n"),
            stdout=io.StringIO(),
        )
        first = gate.decide(spec_shell(), {"command": "x"})
        self.assertEqual(first.action, "approved")
        second = gate.decide(spec_shell(), {"command": "y"})
        # session_allow short-circuits before prompting again
        self.assertEqual(second.action, "approved")

    def test_interactive_deny(self):
        gate = self.make_gate(
            compose_policy("full-access", "on-risk"),
            interactive=True,
            stdin=io.StringIO("4\n"),
            stdout=io.StringIO(),
        )
        decision = gate.decide(spec_shell(), {"command": "x"})
        self.assertEqual(decision.action, "denied")
        self.assertEqual(decision.reason, "user_denied")

    def test_interactive_always_rule_writes_fragment(self):
        with tempfile.TemporaryDirectory() as tmp:
            policy = compose_policy("full-access", "on-risk", policy_dir=tmp)
            gate = self.make_gate(
                policy,
                interactive=True,
                stdin=io.StringIO("3\n"),
                stdout=io.StringIO(),
            )
            decision = gate.decide(spec_shell(), {"command": "x"})
            self.assertEqual(decision.action, "approved")
            self.assertTrue(Path(tmp).joinpath("test.shell.json").is_file())

    def test_fragment_allow_short_circuits_prompt(self):
        with tempfile.TemporaryDirectory() as tmp:
            save_fragment("test.shell", allow=True, policy_dir=tmp)
            policy = merge_fragments(
                compose_policy("full-access", "on-risk"), policy_dir=tmp
            )
            gate = self.make_gate(policy, interactive=False)
            decision = gate.decide(spec_shell(), {"command": "x"})
            self.assertEqual(decision.action, "approved")

    def test_session_log_records(self):
        session = SessionLog("abc")
        session.record(tool="fake.echo", ok=True)
        self.assertEqual(len(session.entries), 1)
        self.assertEqual(session.entries[0]["session_id"], "abc")
        self.assertIn("ts", session.entries[0])


class CliSubprocessTestCase(unittest.TestCase):
    def test_capabilities_json(self):
        proc = run_cli("capabilities", "--json")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["schema_version"], "ai.cli.capabilities.v1")
        self.assertIn("fake", [p["id"] for p in payload["providers"]])
        tool_names = [t["name"] for t in payload["tools"]]
        self.assertIn("fake.echo", tool_names)
        self.assertIn("audit.boundary", tool_names)
        self.assertIn("audit.evidence_verify", tool_names)
        self.assertIn("audit.coverage", tool_names)
        audit_specs = {t["name"]: t for t in payload["tools"]
                       if t["name"].startswith("audit.")}
        self.assertTrue(all(not spec["network"] for spec in audit_specs.values()))
        self.assertTrue(all(not spec["writes"] for spec in audit_specs.values()))
        self.assertIn("project.list_plans", tool_names)
        self.assertEqual(payload["policy"]["access"], "read-only")

    def test_run_offline_coverage_audit(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            total = root / "total.json"
            candidates = root / "candidates.json"
            tested = root / "tested.json"
            total.write_text('["GET /a", "GET /b"]', encoding="utf-8")
            candidates.write_text('["GET /a"]', encoding="utf-8")
            tested.write_text('["GET /a"]', encoding="utf-8")
            request = json.dumps({
                "tool": "audit.coverage",
                "arguments": {
                    "total": str(total),
                    "candidates": str(candidates),
                    "tested": str(tested),
                },
            })
            proc = run_cli("run", "--access", "read-only",
                           "--approval", "never", stdin=request)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        result = parse_jsonl(proc.stdout)[0]
        self.assertTrue(result["ok"])
        self.assertEqual(result["output"]["counts"]["tested_in_candidate"], 1)

    def test_coverage_audit_requires_all_denominators(self):
        request = json.dumps({
            "tool": "audit.coverage",
            "arguments": {"tested": "tested.json"},
        })
        proc = run_cli("run", "--access", "read-only",
                       "--approval", "never", stdin=request)
        self.assertEqual(proc.returncode, 1, proc.stderr)
        result = parse_jsonl(proc.stdout)[0]
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"], "invalid arguments")

    def test_run_jsonl_ok(self):
        request = json.dumps({"tool": "fake.echo", "arguments": {"value": "hi"}})
        proc = run_cli("run", "--access", "read-only", "--approval", "on-risk", stdin=request)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        lines = parse_jsonl(proc.stdout)
        self.assertEqual(len(lines), 1)
        self.assertTrue(lines[0]["ok"])
        self.assertEqual(lines[0]["tool"], "fake.echo")
        self.assertEqual(lines[0]["output"], {"echo": "hi"})

    def test_run_policy_denied(self):
        request = json.dumps(
            {"tool": "fake.fs.write", "arguments": {"path": "a", "content": "b"}}
        )
        proc = run_cli("run", "--access", "read-only", "--approval", "never", stdin=request)
        self.assertEqual(proc.returncode, 1, proc.stderr)
        lines = parse_jsonl(proc.stdout)
        self.assertFalse(lines[0]["ok"])
        self.assertIn("policy_denied", lines[0]["error"])

    def test_run_full_access_never_executes_write(self):
        request = json.dumps(
            {"tool": "fake.fs.write", "arguments": {"path": "a", "content": "b"}}
        )
        proc = run_cli("run", "--access", "full-access", "--approval", "never", stdin=request)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        lines = parse_jsonl(proc.stdout)
        self.assertTrue(lines[0]["ok"])
        self.assertTrue(lines[0]["output"]["written"])

    def test_run_dry_run_does_not_execute(self):
        request = json.dumps(
            {"tool": "fake.fs.write", "arguments": {"path": "a", "content": "b"}}
        )
        proc = run_cli(
            "run",
            "--access",
            "full-access",
            "--approval",
            "never",
            "--dry-run",
            stdin=request,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        lines = parse_jsonl(proc.stdout)
        self.assertTrue(lines[0]["dry_run"])
        self.assertNotIn("output", lines[0])

    def test_run_approval_required_exit_10(self):
        request = json.dumps({"tool": "fake.mutation", "arguments": {}})
        proc = run_cli(
            "run",
            "--access",
            "full-access",
            "--approval",
            "on-risk",
            stdin=request,
        )
        self.assertEqual(proc.returncode, APPROVAL_EXIT_CODE, proc.stderr)
        lines = parse_jsonl(proc.stdout)
        self.assertEqual(lines[0]["approval"], "approval_required")

    def test_run_unknown_tool(self):
        request = json.dumps({"tool": "no.such", "arguments": {}})
        proc = run_cli("run", "--access", "full-access", "--approval", "never", stdin=request)
        self.assertEqual(proc.returncode, 1, proc.stderr)
        lines = parse_jsonl(proc.stdout)
        self.assertIn("unknown tool", lines[0]["error"])

    def test_run_invalid_input(self):
        proc = run_cli("run", "--access", "read-only", stdin="{not json")
        self.assertEqual(proc.returncode, 1, proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertFalse(payload["ok"])
        self.assertIn("invalid input", payload["error"])

    def test_run_reads_tool_calls_wrapper(self):
        request = json.dumps(
            {
                "tool_calls": [
                    {"name": "fake.echo", "arguments": {"value": "wrapped"}}
                ]
            }
        )
        proc = run_cli("run", "--access", "read-only", "--approval", "never", stdin=request)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        lines = parse_jsonl(proc.stdout)
        self.assertEqual(lines[0]["tool"], "fake.echo")
        self.assertEqual(lines[0]["output"], {"echo": "wrapped"})

    def test_policy_show_validate(self):
        proc = run_cli("policy", "show", "--json")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["schema_version"], "ai.policy.v1")
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "policy.json"
            path.write_text('{"access": "full-access", "approval": "never"}', encoding="utf-8")
            proc = run_cli("policy", "validate", str(path))
            self.assertEqual(proc.returncode, 0, proc.stderr)
            payload = json.loads(proc.stdout)
            self.assertTrue(payload["ok"])
            self.assertEqual(payload["policy"]["access"], "full-access")

    def test_shell_denied_read_only(self):
        proc = run_cli(
            "shell", "--approval", "never", "--", sys.executable, "-c", "print('x')"
        )
        self.assertEqual(proc.returncode, 1, proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertFalse(payload["ok"])
        self.assertIn("policy_denied", payload["error"])

    def test_shell_full_access_never(self):
        proc = run_cli(
            "shell",
            "--access",
            "full-access",
            "--approval",
            "never",
            "--",
            sys.executable,
            "-c",
            "print('cli-ok')",
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["exit_code"], 0)
        self.assertIn("cli-ok", payload["stdout"])
        self.assertEqual(payload["provenance"], "unmanaged")

    def test_shell_approval_required_exit_10(self):
        proc = run_cli(
            "shell",
            "--access",
            "full-access",
            "--approval",
            "on-risk",
            "--",
            sys.executable,
            "-c",
            "print('x')",
        )
        self.assertEqual(proc.returncode, APPROVAL_EXIT_CODE, proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["approval"], "approval_required")

    def test_shell_dry_run(self):
        proc = run_cli(
            "shell",
            "--access",
            "full-access",
            "--approval",
            "never",
            "--dry-run",
            "--",
            sys.executable,
            "-c",
            "print('x')",
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertTrue(payload["dry_run"])
        self.assertNotIn("stdout", payload)

    def test_task_dry_run_no_mongo(self):
        proc = run_cli(
            "task",
            "list-plans",
            "--project-id",
            "none",
            "--dry-run",
            "--json",
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        lines = parse_jsonl(proc.stdout)
        self.assertTrue(lines[0]["dry_run"])
        self.assertEqual(lines[0]["tool"], "project.list_plans")

    def test_provider_fake_loop(self):
        with tempfile.TemporaryDirectory() as tmp:
            script_path = Path(tmp) / "script.json"
            script_path.write_text(
                json.dumps(
                    [
                        {
                            "tool_call": {
                                "name": "fake.echo",
                                "arguments": {"value": "loop-ok"},
                            }
                        },
                        {"text": "done"},
                    ]
                ),
                encoding="utf-8",
            )
            proc = run_cli(
                "run",
                "--access",
                "read-only",
                "--approval",
                "never",
                "--provider",
                "fake",
                "--goal",
                "test loop",
                "--script",
                str(script_path),
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            lines = parse_jsonl(proc.stdout)
            self.assertEqual(lines[0]["tool"], "fake.echo")
            self.assertTrue(lines[0]["ok"])
            self.assertEqual(lines[0]["output"], {"echo": "loop-ok"})
            self.assertTrue(lines[1]["finish"])
            self.assertEqual(lines[1]["content"], "done")

    def test_session_log_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            log_path = Path(tmp) / "audit.jsonl"
            request = json.dumps({"tool": "fake.echo", "arguments": {"value": "x"}})
            proc = run_cli(
                "run",
                "--access",
                "read-only",
                "--approval",
                "never",
                "--session-log",
                str(log_path),
                stdin=request,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            lines = log_path.read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(lines), 1)
            entry = json.loads(lines[0])
            self.assertEqual(entry["tool"], "fake.echo")
            self.assertTrue(entry["ok"])


if __name__ == "__main__":
    unittest.main()
