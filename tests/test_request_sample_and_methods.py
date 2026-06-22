import unittest

from apiAnalysis.model.model import HeaderModel
from apiAnalysis.tool.request_sample_store import sample_signature


class RequestSampleAndMethodsTest(unittest.TestCase):
    def test_sample_signature_ignores_pagination_values(self):
        sig_a = sample_signature(
            "GET",
            "https://api.example.test/items?page=1",
            "/items",
            {"page": "1", "status": "open"},
            None,
        )
        sig_b = sample_signature(
            "GET",
            "https://api.example.test/items?page=2",
            "/items",
            {"page": "2", "status": "closed"},
            None,
        )
        self.assertEqual(sig_a, sig_b)

    def test_sample_signature_splits_route_query(self):
        sig_a = sample_signature("GET", "https://api.example.test/index.php", "/index.php", {"m": "admin", "c": "user"}, None)
        sig_b = sample_signature("GET", "https://api.example.test/index.php", "/index.php", {"m": "admin", "c": "order"}, None)
        self.assertNotEqual(sig_a, sig_b)

    def test_header_model_accepts_common_real_methods(self):
        for method in ["PATCH", "OPTIONS", "CONNECT", "TRACE"]:
            model = HeaderModel(header={}, url="https://example.test", method=method)
            self.assertEqual(model.method, method)


if __name__ == "__main__":
    unittest.main()
