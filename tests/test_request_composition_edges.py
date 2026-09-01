import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from apiAnalysis.tool.api_signature import api_signature, normalize_signature_path, route_query_signature
from apiAnalysis.tool.compose_request import build_request_payload, render_request_url
from apiAnalysis.tool.parameter_dependency import trusted_relation_value
from apiAnalysis.tool.parameter_locator import locator_from_path
from apiAnalysis.tool.snapshot_runner import _request_kwargs
from apiAnalysis.tool.tool import flatten_json, unflatten_json


class RequestCompositionEdgesTest(unittest.TestCase):
    def test_relation_metadata_is_never_used_as_request_value(self):
        untrusted = SimpleNamespace(
            verified=False, manual_decision="", evidence=["resource-1"],
        )
        metadata = SimpleNamespace(
            verified=True, manual_decision="", evidence=[{"kind": "discovery"}],
        )
        trusted = SimpleNamespace(
            verified=True, manual_decision="", evidence=["resource-1"],
        )
        manual = SimpleNamespace(
            verified=False, manual_decision="trusted", evidence=[42],
        )
        self.assertIsNone(trusted_relation_value(untrusted))
        self.assertIsNone(trusted_relation_value(metadata))
        self.assertEqual(trusted_relation_value(trusted), "resource-1")
        self.assertEqual(trusted_relation_value(manual), 42)

    def test_query_route_signature_splits_thinkphp_routes_without_pagination_noise(self):
        query_a = {"m": "admin", "c": "user", "a": "list", "page": "1"}
        query_b = {"m": "admin", "c": "order", "a": "list", "page": "2"}

        self.assertNotEqual(
            api_signature("GET", "https://a.test/index.php", "/index.php", query_a, None),
            api_signature("GET", "https://a.test/index.php", "/index.php", query_b, None),
        )
        self.assertEqual(route_query_signature("/index.php", query_a)["c"], ["user"])

    def test_pagination_values_do_not_split_same_api_signature(self):
        query_a = {"status": "open", "page": "1"}
        query_b = {"status": "closed", "page": "2"}

        self.assertEqual(
            api_signature("GET", "https://api.a.test/api/list", "/api/list", query_a, None),
            api_signature("GET", "https://web.a.test/api/list", "/api/list", query_b, None),
        )

    def test_unflatten_preserves_arrays(self):
        original = {"items": [{"id": 1}, {"id": 2}], "name": "demo"}
        self.assertEqual(unflatten_json(flatten_json(original), value_selector=lambda value: value), original)

    def test_render_request_url_preserves_repeated_query_values(self):
        payload = {
            "url": "https://example.test/api?ids=1&ids=2&page=1",
            "query": {"status": "open"},
        }
        rendered = render_request_url(payload)
        self.assertIn("ids=1", rendered)
        self.assertIn("ids=2", rendered)
        self.assertIn("status=open", rendered)

    def test_form_snapshot_uses_urlencoded_body(self):
        snapshot = SimpleNamespace(
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            body={"a": "1", "b": ["2", "3"]},
            content_type="application/x-www-form-urlencoded",
        )
        kwargs = _request_kwargs(snapshot)
        self.assertEqual(kwargs["data"], "a=1&b=2&b=3")
        self.assertNotIn("json", kwargs)

    def test_openapi_path_template_matches_traffic_numeric_path(self):
        self.assertEqual(normalize_signature_path("/users/{id}.json"), "/users/[PARAM].json")
        self.assertEqual(
            api_signature("GET", "https://api.example.test/users/123.json", "/users/[NUMBER].json", {}, None),
            api_signature("GET", "https://api.example.test/users/{id}.json", "/users/{id}.json", {}, None),
        )

    @patch("apiAnalysis.tool.compose_request.best_request_sample", return_value=None)
    @patch("apiAnalysis.tool.compose_request.asset_context")
    @patch("apiAnalysis.tool.compose_request.req_data")
    @patch("apiAnalysis.tool.compose_request.raw_data")
    def test_payload_routes_cookie_and_materializes_schema_body(
        self, raw_model, req_model, asset_context, _best_sample,
    ):
        data = SimpleNamespace(
            id="raw-1", ptah_id=77, url="https://api.example.test/users/{id}",
            query={}, headers={}, raw_req=[], raw_res=[], response_status_code=[200],
            method="POST", path="/users/{id}", domain="api.example.test",
            action="", rule="path", tags="", des="",
        )
        raw_model.objects.return_value.first.return_value = data
        asset_context.return_value = {
            "project_id": "p1", "env_id": "test", "import_run_id": "r1",
        }

        def entry(name, position, value, locator=None):
            return SimpleNamespace(
                parameter=name, position=position, value=[value], required=True,
                type="string", Content_type="application/json", source_meta={},
                direction="request", canonical_name=name.split(".")[-1],
                schema_path=name, locator=locator or {},
            )

        req_model.objects.return_value = [
            entry("id", "path", "42"),
            entry("X-Tenant", "header", "tenant-a"),
            entry("session", "cookie", "cookie-a"),
            entry(
                "remote_users[].remote_id", "body", 7,
                locator_from_path(
                    "remote_users[].remote_id", direction="request",
                    position="body", schema=True,
                ),
            ),
        ]
        payload = build_request_payload(77, project_id="p1", env_id="test")
        self.assertEqual(payload["cookies"], {"session": "cookie-a"})
        self.assertEqual(payload["headers"]["X-Tenant"], "tenant-a")
        self.assertEqual(payload["body"], {"remote_users": [{"remote_id": 7}]})
        self.assertEqual(payload["rendered_url"], "https://api.example.test/users/42")


if __name__ == "__main__":
    unittest.main()
