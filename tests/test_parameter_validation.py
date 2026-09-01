import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from apiAnalysis.tool.account_context import AccountContext
from apiAnalysis.tool.parameter_locator import locator_from_path
from apiAnalysis.tool.parameter_validation import (
    _context_with_cookie_overlay,
    _mutation_host_retryable,
    _replace_origin,
    replay_parameter_validation,
)


def _snapshot(snapshot_id, pathid, body=None, method="GET"):
    return SimpleNamespace(
        id=snapshot_id, pathid=pathid, raw_data=None, source="template",
        project_id="p1", import_run_id="", env_id="test", account_id="owner",
        auth_mode="account", auth_provider_id="database_sso",
        auth_context_ref="owner-current", method=method,
        url="https://api.example.test/items", path="/items",
        domain="api.example.test", query={}, headers={}, cookies={},
        path_params={}, body=body, content_type="application/json",
        expected_status_codes=[200], parameter_sources={}, metadata={},
    )


class ParameterValidationTests(unittest.TestCase):
    def test_environment_base_path_is_applied_once(self):
        self.assertEqual(
            _replace_origin("https://old.invalid/users?id=1", "https://new.invalid/v2"),
            "https://new.invalid/v2/users?id=1",
        )
        self.assertEqual(
            _replace_origin("https://old.invalid/v2/users", "https://new.invalid/v2"),
            "https://new.invalid/v2/users",
        )

    def test_cookie_parameter_overlay_keeps_runtime_session_in_memory(self):
        context = AccountContext(
            project_id="p1", env_id="test", account_id="owner",
            provider_id="database_sso", context_ref="owner-current",
            headers={"Authorization": "Bearer secret"},
            cookies={"session": "secret-session"},
            allowed_hosts=["api.example.test"],
        )
        merged = _context_with_cookie_overlay(context, {"tenant": 42})
        self.assertEqual(merged.cookies["session"], "secret-session")
        self.assertEqual(merged.cookies["tenant"], "42")
        self.assertNotIn("secret-session", repr(merged))

    @patch("apiAnalysis.tool.parameter_validation.replay_snapshot")
    @patch("apiAnalysis.tool.parameter_validation.replay_snapshot_with_json")
    @patch("apiAnalysis.tool.parameter_validation.request_snapshot")
    def test_relation_adapter_extracts_and_injects_without_persisting_raw_value(
        self, snapshot_model, replay_with_json, replay,
    ):
        source = _snapshot("source-1", 10)
        consumer = _snapshot("consumer-1", 20, body={"filter": {}})

        class Query:
            def __init__(self, value):
                self.value = value
            def first(self):
                return self.value

        snapshot_model.objects.side_effect = lambda **query: Query(
            source if query.get("id") == "source-1" else consumer
        )
        replay_with_json.return_value = (
            {"ok": True, "status_code": 200, "elapsed_ms": 3, "response_len": 30},
            {"items": [{"id": 9}]},
        )
        replay.return_value = {
            "ok": True, "status_code": 200, "elapsed_ms": 4,
            "response_len": 12, "response_sha256": "abc",
            "response_content_type": "application/json", "response_json_type": "object",
            "error_type": "",
        }
        auth = {
            "project_id": "p1", "env_id": "test", "account_id": "owner",
            "auth_provider_id": "database_sso", "auth_context_ref": "owner-current",
        }
        plan_snapshot = SimpleNamespace(
            metadata={"validation_plan": {
                "source_snapshot_id": "source-1",
                "consumer_snapshot_id": "consumer-1",
                "source_auth": auth,
                "consumer_auth": auth,
                "source_host": "api.example.test",
                "consumer_host": "api.example.test",
                "source_base_url": "https://api.example.test",
                "consumer_base_url": "https://api.example.test",
                "source_locator": locator_from_path(
                    "items[].id", direction="response", position="body", schema=True,
                ),
                "target_locator": locator_from_path(
                    "filter.id", direction="request", position="body", schema=True,
                ),
                "target_parameter": "filter.id",
                "target_position": "body",
                "canonical_name": "id",
                "relation_id": "relation-1",
            }}
        )
        context = AccountContext(
            project_id="p1", env_id="test", account_id="owner",
            provider_id="database_sso", context_ref="owner-current",
            headers={"Authorization": "Bearer secret"},
            allowed_hosts=["api.example.test"],
        )
        resolver = MagicMock()
        progress = []
        result = replay_parameter_validation(
            plan_snapshot, resolver, account_context=context,
            request_options={"timeout": 5, "allow_redirects": False},
            progress_callback=progress.append,
        )
        consumer_view = replay.call_args.args[0]
        self.assertEqual(consumer_view.body, {"filter": {"id": 9}})
        self.assertEqual(result["validation_status"], "verified")
        self.assertEqual(result["value_type"], "int")
        self.assertIn("value_digest", result)
        self.assertNotIn("value", result)
        phases = [item["phase"] for item in progress]
        self.assertEqual(phases[0], "preparing")
        self.assertIn("source_request", phases)
        self.assertIn("field_extraction", phases)
        self.assertIn("consumer_request", phases)
        self.assertEqual(phases[-1], "writing_results")
        self.assertEqual(progress[-1]["request_count"], 2)
        resolver.resolve.assert_not_called()

    @patch("apiAnalysis.tool.parameter_validation.replay_snapshot")
    @patch("apiAnalysis.tool.parameter_validation.replay_snapshot_with_json")
    @patch("apiAnalysis.tool.parameter_validation.request_snapshot")
    def test_grouped_case_extracts_many_values_once_and_keeps_fixture_fields(
        self, snapshot_model, replay_with_json, replay,
    ):
        source = _snapshot("source-1", 10)
        consumer = _snapshot("consumer-1", 20, body={"generated": True})

        class Query:
            def __init__(self, value):
                self.value = value
            def first(self):
                return self.value

        snapshot_model.objects.side_effect = lambda **query: Query(
            source if query.get("id") == "source-1" else consumer
        )
        replay_with_json.return_value = (
            {"ok": True, "status_code": 200, "elapsed_ms": 3, "response_len": 40},
            {"items": [{"id": 9}], "meta": {"tenant_id": 3}},
        )
        replay.return_value = {
            "ok": True, "status_code": 200, "elapsed_ms": 4,
            "response_len": 12, "response_sha256": "abc", "error_type": "",
        }
        auth = {
            "project_id": "p1", "env_id": "test", "account_id": "owner",
            "auth_provider_id": "database_sso", "auth_context_ref": "owner-current",
        }
        plan_snapshot = SimpleNamespace(metadata={"validation_plan": {
            "source_snapshot_id": "source-1", "consumer_snapshot_id": "consumer-1",
            "source_auth": auth, "consumer_auth": auth,
            "source_host": "api.example.test", "consumer_host": "api.example.test",
            "source_base_url": "https://api.example.test",
            "consumer_base_url": "https://api.example.test",
            "source_url_template": "https://api.example.test/items",
            "consumer_url_template": "https://api.example.test/items",
            "source_fixture": {
                "query": {"page": 1}, "headers": {}, "path_params": {}, "body": None,
            },
            "consumer_fixture": {
                "query": {"dry_run": True}, "headers": {}, "path_params": {},
                "body": {"name": "可复用测试数据", "nested": {"keep": True}},
            },
            "relations": [
                {
                    "relation_id": "relation-id", "canonical_name": "id",
                    "source_parameter": "items[].id", "target_parameter": "filter.id",
                    "source_locator": locator_from_path(
                        "items[].id", direction="response", position="body", schema=True,
                    ),
                    "target_locator": locator_from_path(
                        "filter.id", direction="request", position="body", schema=True,
                    ),
                    "target_position": "body", "manual_value_provided": False,
                },
                {
                    "relation_id": "relation-tenant", "canonical_name": "tenant_id",
                    "source_parameter": "meta.tenant_id", "target_parameter": "tenant_id",
                    "source_locator": locator_from_path(
                        "meta.tenant_id", direction="response", position="body", schema=True,
                    ),
                    "target_locator": locator_from_path(
                        "tenant_id", direction="request", position="query", schema=True,
                    ),
                    "target_position": "query", "manual_value_provided": False,
                },
            ],
            "request_budget": 3,
        }})
        context = AccountContext(
            project_id="p1", env_id="test", account_id="owner",
            provider_id="database_sso", context_ref="owner-current",
            headers={"Authorization": "Bearer secret"},
            allowed_hosts=["api.example.test"],
        )

        result = replay_parameter_validation(
            plan_snapshot, MagicMock(), account_context=context,
            request_options={"timeout": 5, "allow_redirects": False},
        )

        self.assertEqual(replay_with_json.call_count, 1)
        self.assertEqual(replay.call_count, 1)
        source_view = replay_with_json.call_args.args[0]
        consumer_view = replay.call_args.args[0]
        self.assertEqual(source_view.query, {"page": 1})
        self.assertEqual(consumer_view.body, {
            "generated": True,
            "name": "可复用测试数据",
            "nested": {"keep": True},
            "filter": {"id": 9},
        })
        self.assertEqual(consumer_view.query, {"dry_run": True, "tenant_id": 3})
        self.assertEqual(result["validation_status"], "verified")
        self.assertEqual(result["request_count"], 2)
        self.assertEqual(
            {item["relation_id"] for item in result["relation_results"]},
            {"relation-id", "relation-tenant"},
        )
        self.assertTrue(all(
            item["validation_status"] == "verified"
            for item in result["relation_results"]
        ))
        self.assertNotIn("value", result)

    @patch("apiAnalysis.tool.parameter_validation.replay_snapshot")
    @patch("apiAnalysis.tool.parameter_validation.replay_snapshot_with_json")
    @patch("apiAnalysis.tool.parameter_validation.request_snapshot")
    def test_grouped_case_records_missing_mapping_without_blocking_valid_mapping(
        self, snapshot_model, replay_with_json, replay,
    ):
        source = _snapshot("source-1", 10)
        consumer = _snapshot("consumer-1", 20, body={})

        class Query:
            def __init__(self, value):
                self.value = value
            def first(self):
                return self.value

        snapshot_model.objects.side_effect = lambda **query: Query(
            source if query.get("id") == "source-1" else consumer
        )
        replay_with_json.return_value = (
            {"ok": True, "status_code": 200, "elapsed_ms": 2, "response_len": 20},
            {"id": 9},
        )
        replay.return_value = {"ok": True, "status_code": 200, "error_type": ""}
        auth = {
            "project_id": "p1", "env_id": "test", "account_id": "owner",
            "auth_provider_id": "database_sso", "auth_context_ref": "owner-current",
        }
        mappings = []
        for relation_id, name in (("found", "id"), ("missing", "unknown_id")):
            mappings.append({
                "relation_id": relation_id, "canonical_name": name,
                "source_parameter": name, "target_parameter": name,
                "source_locator": locator_from_path(
                    name, direction="response", position="body", schema=True,
                ),
                "target_locator": locator_from_path(
                    name, direction="request", position="body", schema=True,
                ),
                "target_position": "body", "manual_value_provided": False,
            })
        plan_snapshot = SimpleNamespace(metadata={"validation_plan": {
            "source_snapshot_id": "source-1", "consumer_snapshot_id": "consumer-1",
            "source_auth": auth, "consumer_auth": auth,
            "source_host": "api.example.test", "consumer_host": "api.example.test",
            "relations": mappings, "request_budget": 3,
        }})
        context = AccountContext(
            project_id="p1", env_id="test", account_id="owner",
            provider_id="database_sso", context_ref="owner-current",
            headers={"Authorization": "Bearer secret"},
            allowed_hosts=["api.example.test"],
        )

        result = replay_parameter_validation(
            plan_snapshot, MagicMock(), account_context=context,
        )

        statuses = {
            item["relation_id"]: item["validation_status"]
            for item in result["relation_results"]
        }
        self.assertEqual(result["validation_status"], "partially_verified")
        self.assertEqual(statuses, {"found": "verified", "missing": "value_not_found"})
        self.assertEqual(replay.call_args.args[0].body, {"id": 9})

    def test_mutation_host_retry_only_uses_deterministic_non_execution_errors(self):
        self.assertTrue(_mutation_host_retryable({"status_code": 404, "error_type": ""}))
        self.assertTrue(_mutation_host_retryable({"status_code": None, "error_type": "ConnectionError"}))
        self.assertFalse(_mutation_host_retryable({"status_code": 500, "error_type": ""}))
        self.assertFalse(_mutation_host_retryable({"status_code": None, "error_type": "ReadTimeout"}))

    @patch("apiAnalysis.tool.parameter_validation.replay_snapshot")
    @patch("apiAnalysis.tool.parameter_validation.replay_snapshot_with_json")
    @patch("apiAnalysis.tool.parameter_validation.request_snapshot")
    def test_source_host_approval_reports_full_authorized_scope_not_snapshot_slice(
        self, snapshot_model, replay_with_json, replay,
    ):
        source = _snapshot("source-1", 10)
        consumer = _snapshot("consumer-1", 20)

        class Query:
            def __init__(self, value):
                self.value = value
            def first(self):
                return self.value

        snapshot_model.objects.side_effect = lambda **query: Query(
            source if query.get("id") == "source-1" else consumer
        )
        replay_with_json.return_value = (
            {
                "ok": False,
                "status_code": 404,
                "elapsed_ms": 3,
                "response_len": 12,
                "error_type": "",
            },
            {"error": "route not found"},
        )
        auth = {
            "project_id": "p1", "env_id": "test", "account_id": "owner",
            "auth_provider_id": "database_sso", "auth_context_ref": "owner-current",
        }
        plan_snapshot = SimpleNamespace(metadata={"validation_plan": {
            "source_snapshot_id": "source-1",
            "consumer_snapshot_id": "consumer-1",
            "source_auth": auth,
            "consumer_auth": auth,
            "source_hosts": [
                {"host": "source-1.test", "base_url": "https://source-1.test"},
                {"host": "source-2.test", "base_url": "https://source-2.test"},
            ],
            "consumer_hosts": [
                {"host": "consumer.test", "base_url": "https://consumer.test"},
            ],
            "available_source_host_count": 4,
            "available_consumer_host_count": 1,
            "source_locator": locator_from_path(
                "items[].id", direction="response", position="body", schema=True,
            ),
            "target_locator": locator_from_path(
                "id", direction="request", position="query", schema=True,
            ),
            "target_parameter": "id",
            "target_position": "query",
            "canonical_name": "id",
            "relation_id": "relation-1",
            "request_budget": 3,
        }})
        context = AccountContext(
            project_id="p1", env_id="test", account_id="owner",
            provider_id="database_sso", context_ref="owner-current",
            headers={"Authorization": "Bearer secret"},
            allowed_hosts=[
                "source-1.test", "source-2.test", "consumer.test",
            ],
        )

        result = replay_parameter_validation(
            plan_snapshot, MagicMock(), account_context=context,
            request_options={"timeout": 5, "allow_redirects": False},
        )

        self.assertEqual(result["validation_status"], "host_scope_approval_required")
        self.assertEqual(result["request_count"], 2)
        self.assertEqual(result["remaining_host_count"], 2)
        self.assertEqual(result["source_untried_host_count"], 2)
        self.assertEqual(result["approval_stage"], "source")
        self.assertEqual(replay_with_json.call_count, 2)
        replay.assert_not_called()

    @patch("apiAnalysis.tool.parameter_validation.replay_snapshot")
    @patch("apiAnalysis.tool.parameter_validation.replay_snapshot_with_json")
    @patch("apiAnalysis.tool.parameter_validation.request_snapshot")
    def test_source_400_stops_host_sweep_and_returns_safe_fixture_guidance(
        self, snapshot_model, replay_with_json, replay,
    ):
        source = _snapshot("source-1", 10)
        consumer = _snapshot("consumer-1", 20)

        class Query:
            def __init__(self, value):
                self.value = value
            def first(self):
                return self.value

        snapshot_model.objects.side_effect = lambda **query: Query(
            source if query.get("id") == "source-1" else consumer
        )
        replay_with_json.return_value = (
            {
                "ok": False,
                "status_code": 400,
                "elapsed_ms": 3,
                "response_len": 80,
                "response_json_type": "object",
                "response_top_level_keys": ["error", "errors", "message"],
                "error_type": "",
                "request_method": "GET",
                "request_origin": "https://source-1.test",
                "request_path": "/items",
                "request_query_names": ["tenant_id"],
                "request_header_names": ["Authorization", "Cookie"],
                "request_cookie_names": ["session"],
                "request_auth_header_names": ["Authorization"],
                "request_auth_cookie_names": ["session"],
                "request_body_bytes": 0,
                "request_content_type": "",
                "request_timeout_seconds": 5,
                "request_allow_redirects": False,
                "request_tls_verify": True,
                "auth_request_count": 3,
            },
            {
                "error": "parameter/missing_required",
                "message": "account 998877 secret detail",
                "errors": {"vpnid": "must be provided"},
            },
        )
        auth = {
            "project_id": "p1", "env_id": "test", "account_id": "owner",
            "auth_provider_id": "database_sso", "auth_context_ref": "owner-current",
        }
        plan_snapshot = SimpleNamespace(metadata={"validation_plan": {
            "source_snapshot_id": "source-1",
            "consumer_snapshot_id": "consumer-1",
            "source_auth": auth,
            "consumer_auth": auth,
            "source_hosts": [
                {"host": "source-1.test", "base_url": "https://source-1.test"},
                {"host": "source-2.test", "base_url": "https://source-2.test"},
                {"host": "source-3.test", "base_url": "https://source-3.test"},
            ],
            "consumer_hosts": [
                {"host": "consumer.test", "base_url": "https://consumer.test"},
            ],
            "available_source_host_count": 3,
            "available_consumer_host_count": 1,
            "source_locator": locator_from_path(
                "items[].id", direction="response", position="body", schema=True,
            ),
            "target_locator": locator_from_path(
                "id", direction="request", position="query", schema=True,
            ),
            "target_parameter": "id",
            "target_position": "query",
            "canonical_name": "id",
            "relation_id": "relation-1",
            "request_budget": 3,
        }})
        context = AccountContext(
            project_id="p1", env_id="test", account_id="owner",
            provider_id="database_sso", context_ref="owner-current",
            headers={"Authorization": "Bearer secret"},
            allowed_hosts=[
                "source-1.test", "source-2.test", "source-3.test",
                "consumer.test",
            ],
        )

        result = replay_parameter_validation(
            plan_snapshot, MagicMock(), account_context=context,
            request_options={"timeout": 5, "allow_redirects": False},
        )

        self.assertEqual(result["validation_status"], "source_request_rejected")
        self.assertEqual(result["request_count"], 1)
        self.assertEqual(result["remaining_host_count"], 0)
        self.assertEqual(result["source_untried_host_count"], 2)
        self.assertEqual(result["approval_stage"], "")
        self.assertEqual(replay_with_json.call_count, 1)
        replay.assert_not_called()
        self.assertEqual(
            result["source_error_summary"]["error_code"],
            "parameter/missing_required",
        )
        self.assertEqual(
            result["source_error_summary"]["error_fields"],
            ["vpnid"],
        )
        attempt = result["source_attempts"][0]
        self.assertEqual(attempt["request_method"], "GET")
        self.assertEqual(attempt["request_origin"], "https://source-1.test")
        self.assertEqual(attempt["request_query_names"], ["tenant_id"])
        self.assertEqual(attempt["request_header_names"], ["Authorization", "Cookie"])
        self.assertEqual(attempt["request_cookie_names"], ["session"])
        self.assertTrue(attempt["request_tls_verify"])
        self.assertFalse(attempt["request_allow_redirects"])
        self.assertEqual(attempt["auth_request_count"], 3)
        serialized = repr(result)
        self.assertNotIn("998877", serialized)
        self.assertNotIn("must be provided", serialized)
        self.assertNotIn("Bearer secret", serialized)

    @patch("apiAnalysis.tool.parameter_validation.replay_snapshot")
    @patch("apiAnalysis.tool.parameter_validation.replay_snapshot_with_json")
    @patch("apiAnalysis.tool.parameter_validation.request_snapshot")
    def test_ambiguous_source_400_retries_next_authorized_host(
        self, snapshot_model, replay_with_json, replay,
    ):
        source = _snapshot("source-1", 10)
        consumer = _snapshot("consumer-1", 20)

        class Query:
            def __init__(self, value):
                self.value = value
            def first(self):
                return self.value

        snapshot_model.objects.side_effect = lambda **query: Query(
            source if query.get("id") == "source-1" else consumer
        )
        replay_with_json.side_effect = [
            (
                {
                    "ok": False,
                    "status_code": 400,
                    "elapsed_ms": 3,
                    "response_len": 40,
                    "response_json_type": "object",
                    "response_top_level_keys": ["error", "message"],
                    "error_type": "",
                },
                {"error": "Bad Request", "message": "invalid request"},
            ),
            (
                {
                    "ok": True,
                    "status_code": 200,
                    "elapsed_ms": 4,
                    "response_len": 30,
                    "response_json_type": "object",
                    "response_top_level_keys": ["items"],
                    "error_type": "",
                },
                {"items": [{"id": 9}]},
            ),
        ]
        replay.return_value = {
            "ok": True,
            "status_code": 200,
            "elapsed_ms": 2,
            "response_len": 20,
            "response_json_type": "object",
            "error_type": "",
        }
        auth = {
            "project_id": "p1", "env_id": "test", "account_id": "owner",
            "auth_provider_id": "database_sso", "auth_context_ref": "owner-current",
        }
        plan_snapshot = SimpleNamespace(metadata={"validation_plan": {
            "source_snapshot_id": "source-1",
            "consumer_snapshot_id": "consumer-1",
            "source_auth": auth,
            "consumer_auth": auth,
            "source_hosts": [
                {"host": "source-1.test", "base_url": "https://source-1.test"},
                {"host": "source-2.test", "base_url": "https://source-2.test"},
            ],
            "consumer_hosts": [
                {"host": "consumer.test", "base_url": "https://consumer.test"},
            ],
            "available_source_host_count": 2,
            "available_consumer_host_count": 1,
            "source_locator": locator_from_path(
                "items[].id", direction="response", position="body", schema=True,
            ),
            "target_locator": locator_from_path(
                "id", direction="request", position="query", schema=True,
            ),
            "target_parameter": "id",
            "target_position": "query",
            "canonical_name": "id",
            "relation_id": "relation-1",
            "request_budget": 3,
        }})
        context = AccountContext(
            project_id="p1", env_id="test", account_id="owner",
            provider_id="database_sso", context_ref="owner-current",
            headers={"Authorization": "Bearer secret"},
            allowed_hosts=[
                "source-1.test", "source-2.test", "consumer.test",
            ],
        )

        result = replay_parameter_validation(
            plan_snapshot, MagicMock(), account_context=context,
            request_options={"timeout": 5, "allow_redirects": False},
        )

        self.assertEqual(result["validation_status"], "verified")
        self.assertEqual(result["request_count"], 3)
        self.assertEqual(replay_with_json.call_count, 2)
        self.assertEqual(
            [item["host"] for item in result["source_attempts"]],
            ["source-1.test", "source-2.test"],
        )
        self.assertFalse(
            result["source_attempts"][0]["explicit_business_rejection"],
        )
        self.assertEqual(replay.call_count, 1)

    @patch("apiAnalysis.tool.parameter_validation.replay_snapshot")
    @patch("apiAnalysis.tool.parameter_validation.replay_snapshot_with_json")
    @patch("apiAnalysis.tool.parameter_validation.request_snapshot")
    def test_mutation_crosses_host_after_404_within_three_request_budget(
        self, snapshot_model, replay_with_json, replay,
    ):
        source = _snapshot("source-1", 10)
        consumer = _snapshot("consumer-1", 20, body={"parent_id": None}, method="DELETE")

        class Query:
            def __init__(self, value):
                self.value = value
            def first(self):
                return self.value

        snapshot_model.objects.side_effect = lambda **query: Query(
            source if query.get("id") == "source-1" else consumer
        )
        replay_with_json.return_value = (
            {"ok": True, "status_code": 200, "elapsed_ms": 3, "response_len": 30},
            {"items": [{"parent_id": 9}]},
        )
        replay.side_effect = [
            {"ok": False, "status_code": 404, "elapsed_ms": 2, "error_type": ""},
            {"ok": True, "status_code": 204, "elapsed_ms": 4, "response_len": 0,
             "response_sha256": "abc", "response_content_type": "", "response_json_type": "null",
             "error_type": ""},
        ]
        auth = {
            "project_id": "p1", "env_id": "test", "account_id": "owner",
            "auth_provider_id": "database_sso", "auth_context_ref": "owner-current",
        }
        plan_snapshot = SimpleNamespace(metadata={"validation_plan": {
            "source_snapshot_id": "source-1", "consumer_snapshot_id": "consumer-1",
            "source_auth": auth, "consumer_auth": auth,
            "source_hosts": [{"host": "source.test", "base_url": "https://source.test"}],
            "consumer_hosts": [
                {"host": "wrong.test", "base_url": "https://wrong.test"},
                {"host": "right.test", "base_url": "https://right.test"},
            ],
            "source_locator": locator_from_path(
                "items[].parent_id", direction="response", position="body", schema=True,
            ),
            "target_locator": locator_from_path(
                "parent_id", direction="request", position="body", schema=True,
            ),
            "target_parameter": "parent_id", "target_position": "body",
            "canonical_name": "parent_id", "relation_id": "relation-1",
            "request_budget": 3, "mutation": True,
        }})
        context = AccountContext(
            project_id="p1", env_id="test", account_id="owner",
            provider_id="database_sso", context_ref="owner-current",
            headers={"Authorization": "Bearer secret"},
            allowed_hosts=["source.test", "wrong.test", "right.test"],
        )
        result = replay_parameter_validation(
            plan_snapshot, MagicMock(), account_context=context,
            request_options={"timeout": 5, "allow_redirects": False},
        )
        self.assertEqual(result["validation_status"], "mutation_accepted")
        self.assertEqual(result["request_count"], 3)
        self.assertEqual([item["status_code"] for item in result["consumer_attempts"]], [404, 204])
        self.assertEqual(replay.call_count, 2)
        self.assertNotIn("value", result)

    @patch("apiAnalysis.tool.parameter_validation.replay_snapshot")
    @patch("apiAnalysis.tool.parameter_validation.replay_snapshot_with_json")
    @patch("apiAnalysis.tool.parameter_validation.request_snapshot")
    def test_mutation_5xx_stops_cross_host_and_detects_effect_by_readback(
        self, snapshot_model, replay_with_json, replay,
    ):
        source = _snapshot("source-1", 10)
        consumer = _snapshot("consumer-1", 20, body={"id": None}, method="DELETE")

        class Query:
            def __init__(self, value):
                self.value = value
            def first(self):
                return self.value

        snapshot_model.objects.side_effect = lambda **query: Query(
            source if query.get("id") == "source-1" else consumer
        )
        replay_with_json.side_effect = [
            (
                {"ok": True, "status_code": 200, "elapsed_ms": 3, "response_len": 30},
                {"items": [{"id": 9}]},
            ),
            (
                {"ok": True, "status_code": 200, "elapsed_ms": 3, "response_len": 12},
                {"items": []},
            ),
        ]
        replay.return_value = {
            "ok": False, "status_code": 500, "elapsed_ms": 4,
            "response_len": 0, "error_type": "",
        }
        auth = {
            "project_id": "p1", "env_id": "test", "account_id": "owner",
            "auth_provider_id": "database_sso", "auth_context_ref": "owner-current",
        }
        plan_snapshot = SimpleNamespace(metadata={"validation_plan": {
            "source_snapshot_id": "source-1", "consumer_snapshot_id": "consumer-1",
            "source_auth": auth, "consumer_auth": auth,
            "source_hosts": [{"host": "source.test", "base_url": "https://source.test"}],
            "consumer_hosts": [
                {"host": "buggy.test", "base_url": "https://buggy.test"},
                {"host": "unused.test", "base_url": "https://unused.test"},
            ],
            "source_locator": locator_from_path(
                "items[].id", direction="response", position="body", schema=True,
            ),
            "target_locator": locator_from_path(
                "id", direction="request", position="body", schema=True,
            ),
            "target_parameter": "id", "target_position": "body",
            "canonical_name": "id", "relation_id": "relation-1",
            "request_budget": 3, "mutation": True,
        }})
        context = AccountContext(
            project_id="p1", env_id="test", account_id="owner",
            provider_id="database_sso", context_ref="owner-current",
            headers={"Authorization": "Bearer secret"},
            allowed_hosts=["source.test", "buggy.test", "unused.test"],
        )
        result = replay_parameter_validation(
            plan_snapshot, MagicMock(), account_context=context,
            request_options={"timeout": 5, "allow_redirects": False},
        )
        self.assertEqual(result["validation_status"], "mutation_effect_after_error")
        self.assertTrue(result["ok"])
        self.assertEqual(result["effect_status"], "delete_observed")
        self.assertEqual(result["request_count"], 3)
        self.assertEqual(replay.call_count, 1)
        self.assertEqual(replay_with_json.call_count, 2)
        self.assertEqual([item["host"] for item in result["consumer_attempts"]], ["buggy.test"])


if __name__ == "__main__":
    unittest.main()
