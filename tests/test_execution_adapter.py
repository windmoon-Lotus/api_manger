import unittest
from types import SimpleNamespace

from apiAnalysis.tool.execution_adapter import (
    ExecutionAdapter,
    ExecutionAdapterAuthModeMismatch,
    UnsupportedExecutionAdapterVersion,
    adapter_registry,
    builtin_execution_adapters,
)
from apiAnalysis.tool.sqli_screen import build_sqli_screen_adapter


def replay(*_, **__):
    return {}


def judge(*_, **__):
    return "not_evaluable", [], 0.0


class ExecutionAdapterTests(unittest.TestCase):
    def setUp(self):
        self.adapters = builtin_execution_adapters(replay, judge)

    def test_builtin_adapters_separate_anonymous_and_account_modes(self):
        anonymous = SimpleNamespace(
            adapter_id="snapshot_batch", adapter_version="1", auth_mode="anonymous",
        )
        account = SimpleNamespace(
            adapter_id="authenticated_snapshot_batch", adapter_version="1", auth_mode="account",
        )
        self.adapters["snapshot_batch"].validate(anonymous)
        self.adapters["authenticated_snapshot_batch"].validate(account)
        self.assertTrue(self.adapters["authenticated_snapshot_batch"].requires_account_context)

    def test_authenticated_adapter_rejects_anonymous_mode(self):
        run = SimpleNamespace(
            adapter_id="authenticated_snapshot_batch", adapter_version="1", auth_mode="anonymous",
        )
        with self.assertRaises(ExecutionAdapterAuthModeMismatch):
            self.adapters["authenticated_snapshot_batch"].validate(run)

    def test_adapter_version_is_exact(self):
        run = SimpleNamespace(
            adapter_id="snapshot_batch", adapter_version="2", auth_mode="anonymous",
        )
        with self.assertRaises(UnsupportedExecutionAdapterVersion):
            self.adapters["snapshot_batch"].validate(run)

    def test_generic_adapters_accept_acknowledged_mutation_policy(self):
        run = SimpleNamespace(
            adapter_id="snapshot_batch", adapter_version="1", auth_mode="anonymous",
        )
        self.adapters["snapshot_batch"].validate(run, allow_mutation=True)
        self.assertTrue(self.adapters["authenticated_snapshot_batch"].supports_mutation)

    def test_request_policy_scope_defaults_and_is_validated(self):
        self.assertEqual(
            self.adapters["snapshot_batch"].request_policy_scope,
            "checkpoint",
        )
        invalid = ExecutionAdapter(
            adapter_id="invalid",
            adapter_version="1",
            replay=replay,
            judge=judge,
            auth_modes=frozenset({"anonymous"}),
            request_policy_scope="invalid",
        )
        with self.assertRaisesRegex(ValueError, "request_policy_scope"):
            adapter_registry([invalid])

    def test_sqli_adapter_accepts_explicitly_acknowledged_mutation(self):
        adapter = build_sqli_screen_adapter()
        run = SimpleNamespace(
            adapter_id=adapter.adapter_id,
            adapter_version=adapter.adapter_version,
            auth_mode="account",
        )
        adapter.validate(run, allow_mutation=True)
        self.assertTrue(adapter.supports_mutation)
        self.assertEqual(adapter.request_policy_scope, "request")


if __name__ == "__main__":
    unittest.main()
