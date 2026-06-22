import unittest
from types import SimpleNamespace

from apiAnalysis.tool.api_signature import api_signature, normalize_signature_path, route_query_signature
from apiAnalysis.tool.compose_request import render_request_url
from apiAnalysis.tool.snapshot_runner import _request_kwargs
from apiAnalysis.tool.tool import flatten_json, unflatten_json


class RequestCompositionEdgesTest(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
