import unittest

from apiAnalysis.tool.request_mutator import mutate_many, mutate_request


class RequestMutatorTest(unittest.TestCase):
    def test_mutate_query_updates_query_and_url(self):
        payload = {"url": "https://example.test/api/items?page=1", "query": {"page": "1"}}
        mutated = mutate_request(payload, "query", "q", "demo")
        self.assertEqual(mutated["query"]["q"], "demo")
        self.assertIn("q=demo", mutated["url"])
        self.assertNotIn("q", payload["query"])

    def test_mutate_nested_json_body(self):
        payload = {"body": {"user": {"id": 1}}}
        mutated = mutate_request(payload, "json", "user.name", "alice")
        self.assertEqual(mutated["body"]["user"]["id"], 1)
        self.assertEqual(mutated["body"]["user"]["name"], "alice")

    def test_mutate_many(self):
        payload = {"headers": {}, "body": {}}
        mutated = mutate_many(payload, [
            {"position": "header", "name": "X-Test", "value": "1"},
            {"position": "body", "name": "profile.role", "value": "admin"},
        ])
        self.assertEqual(mutated["headers"]["X-Test"], "1")
        self.assertEqual(mutated["body"]["profile"]["role"], "admin")


if __name__ == "__main__":
    unittest.main()
