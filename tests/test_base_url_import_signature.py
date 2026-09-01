import unittest

from apiAnalysis.db.save import _join_base_url, _openapi_servers
from apiAnalysis.tool.api_signature import abstract_signature, api_signature, api_signature_object_id


class BaseUrlImportSignatureTest(unittest.TestCase):
    def test_openapi_base_url_override_is_used_when_servers_missing(self):
        self.assertEqual(_openapi_servers({}, base_url="api.example.com"), "https://api.example.com")

    def test_join_base_url_normalizes_relative_paths(self):
        self.assertEqual(
            _join_base_url("api.example.com", "/api/v1/users"),
            "https://api.example.com/api/v1/users",
        )

    def test_openapi_abstract_and_har_concrete_are_separate_but_linkable(self):
        openapi_sig = api_signature(
            "GET",
            "https://api.example.com/api/v1/users/{id}.json",
            "/api/v1/users/{id}.json",
            {},
            None,
            asset_kind="abstract",
        )
        har_sig = api_signature(
            "GET",
            "https://api.example.com/api/v1/users/123.json",
            "/api/v1/users/[NUMBER].json",
            {},
            None,
            asset_kind="concrete",
        )
        self.assertNotEqual(openapi_sig, har_sig)
        self.assertEqual(
            abstract_signature("GET", "/api/v1/users/{id}.json"),
            abstract_signature("GET", "/api/v1/users/[NUMBER].json"),
        )

    def test_concrete_identity_can_be_project_scoped_without_changing_signature(self):
        args = ("GET", "https://api.example.com/users/1", "/users/1", {}, None)
        self.assertNotEqual(
            api_signature_object_id(*args, identity_scope="project-a"),
            api_signature_object_id(*args, identity_scope="project-b"),
        )
        self.assertEqual(api_signature(*args), api_signature(*args))


if __name__ == "__main__":
    unittest.main()
