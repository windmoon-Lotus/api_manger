import unittest
from types import SimpleNamespace
from unittest.mock import patch

from flask import Flask, session

from apiAnalysis.web.views_auth_profile import _create_auth_repair_from_form


class AuthProfileFormTests(unittest.TestCase):
    def test_guided_rsa_fields_reach_password_recipe_and_realm_secret(self):
        app = Flask(__name__)
        app.secret_key = "auth-profile-form-test"
        profile = SimpleNamespace(profile_id="profile-test", auth_kind="bearer")
        form = {
            "recipe_mode": "guided",
            "login_url": "https://auth.example.test/login",
            "password_transform": "rsa_pkcs1v15",
            "rsa_public_key_secret_name": "login_rsa_public_key",
            "rsa_public_key": "synthetic-public-key",
            "rsa_append_timestamp": "1",
            "rsa_timestamp_delimiter": "###",
            "rsa_timestamp_unit": "milliseconds",
            "token_source": "json",
            "token_path": "access_token",
            "token_prefix": "Bearer",
            "repair_auth_kind": "bearer",
            "success_statuses": "200",
            "tls_verify": "1",
        }

        candidate = object()
        with app.test_request_context("/", method="POST", data=form):
            session["username"] = "tester"
            with patch(
                "apiAnalysis.web.views_auth_profile.create_auth_repair_candidate",
                return_value=candidate,
            ) as create_candidate:
                returned_candidate, recipe = _create_auth_repair_from_form(profile)

        self.assertIs(returned_candidate, candidate)
        operations = [
            step.get("operation") for step in recipe["steps"]
            if step.get("type") == "set"
        ]
        self.assertEqual(operations, ["unix_time", "concat", "rsa_encrypt"])
        self.assertEqual(recipe["steps"][0]["unit"], "milliseconds")
        self.assertEqual(recipe["steps"][1]["values"][1], "###")
        self.assertEqual(
            recipe["steps"][2]["public_key"],
            "{{secret.login_rsa_public_key}}",
        )
        self.assertEqual(
            create_candidate.call_args.kwargs["realm_secret_data"],
            {"login_rsa_public_key": "synthetic-public-key"},
        )


if __name__ == "__main__":
    unittest.main()
