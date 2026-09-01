import unittest
from types import SimpleNamespace

from apiAnalysis.tool.request_fixture import apply_request_fixture, save_request_fixture


class RequestFixtureTests(unittest.TestCase):
    def test_fixture_merges_business_data_without_discarding_generated_fields(self):
        snapshot = SimpleNamespace(
            url="https://api.example.test/departments/{department_id}",
            query={"generated": "yes"},
            headers={"Accept": "application/json"},
            path_params={},
            body={"generated": True, "nested": {"keep": 1}},
            parameter_sources={},
        )
        fixture = {
            "query": {"dry_run": True},
            "headers": {"X-Test-Tenant": "qa"},
            "path_params": {"department_id": 42},
            "body": {"name": "测试部门", "nested": {"extra": 2}},
        }

        result = apply_request_fixture(snapshot, fixture)

        self.assertEqual(result.query, {"generated": "yes", "dry_run": True})
        self.assertEqual(result.headers, {
            "Accept": "application/json", "X-Test-Tenant": "qa",
        })
        self.assertEqual(result.path_params, {"department_id": 42})
        self.assertEqual(result.body, {
            "generated": True,
            "name": "测试部门",
            "nested": {"keep": 1, "extra": 2},
        })
        self.assertIn("/departments/42", result.url)
        self.assertIn("dry_run=True", result.url)
        self.assertEqual(
            result.parameter_sources["department_id"]["source"],
            "request_fixture",
        )

    def test_fixture_rejects_auth_headers_before_storage(self):
        with self.assertRaisesRegex(ValueError, "认证 Header"):
            save_request_fixture(
                "p1", "test", 10,
                headers={"Authorization": "Bearer should-not-be-stored"},
            )

    def test_fixture_rejects_nested_auth_material_before_storage(self):
        with self.assertRaisesRegex(ValueError, "认证字段"):
            save_request_fixture(
                "p1", "test", 10,
                body={"business": {"access_token": "must-stay-in-auth-context"}},
            )

    def test_fixture_rejects_bearer_values_even_under_generic_field(self):
        with self.assertRaisesRegex(ValueError, "疑似认证材料"):
            save_request_fixture(
                "p1", "test", 10,
                query={"value": "Bearer must-stay-in-memory"},
            )


if __name__ == "__main__":
    unittest.main()
