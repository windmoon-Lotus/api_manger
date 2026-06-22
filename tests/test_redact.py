import unittest

from apiAnalysis.tool.redact import redact_url


class RedactUrlTestCase(unittest.TestCase):
    def test_redacts_token_query_values(self):
        url = "https://example.test/api?_token=abc&provider_id=1&access_token=secret"

        redacted = redact_url(url)

        self.assertIn("_token=%2A%2A%2AREDACTED%2A%2A%2A", redacted)
        self.assertIn("access_token=%2A%2A%2AREDACTED%2A%2A%2A", redacted)
        self.assertIn("provider_id=1", redacted)
        self.assertNotIn("abc", redacted)
        self.assertNotIn("secret", redacted)


if __name__ == "__main__":
    unittest.main()
