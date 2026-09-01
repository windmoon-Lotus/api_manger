import unittest

from apiAnalysis.tool.endpoint_evidence import REDACTED, sanitize_sample_value


class EndpointEvidenceSanitizationTest(unittest.TestCase):
    def test_nested_credentials_are_redacted_but_business_values_remain(self):
        value = sanitize_sample_value({
            "Authorization": "Bearer top-secret",
            "body": {
                "password": "plain-test-password",
                "department_id": 42,
                "owner": {"user_id": 7},
            },
            "cookies": {"session": "abc"},
        })

        self.assertEqual(value["Authorization"], REDACTED)
        self.assertEqual(value["body"]["password"], REDACTED)
        self.assertEqual(value["body"]["department_id"], 42)
        self.assertEqual(value["body"]["owner"]["user_id"], 7)
        self.assertEqual(value["cookies"]["session"], REDACTED)

    def test_json_string_is_projected_as_structured_sanitized_data(self):
        value = sanitize_sample_value(
            '{"access_token":"secret","items":[{"id":9,"name":"test"}]}'
        )

        self.assertEqual(value["access_token"], REDACTED)
        self.assertEqual(value["items"][0], {"id": 9, "name": "test"})

    def test_inline_bearer_value_is_redacted_even_without_sensitive_key(self):
        value = sanitize_sample_value("received Bearer abc.def.ghi from upstream")
        self.assertNotIn("abc.def.ghi", value)
        self.assertIn("Bearer ***", value)

    def test_form_encoded_password_is_redacted(self):
        value = sanitize_sample_value("username=tester&password=plain&department_id=42")
        self.assertEqual(value["username"], "tester")
        self.assertEqual(value["password"], REDACTED)
        self.assertEqual(value["department_id"], "42")


if __name__ == "__main__":
    unittest.main()
