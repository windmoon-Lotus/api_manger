import unittest
import hashlib
import base64
import re
import threading
import time
from types import SimpleNamespace

import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from apiAnalysis.tool.auth_recipe import (
    AuthRecipeExecutor,
    AuthRecipeFailure,
    canonical_json_sha256,
    normalize_origin,
)
from apiAnalysis.tool.project_auth import (
    build_password_login_recipe,
    build_sso_product_token_recipe,
    recipe_output_credential_stage,
    validate_repair_recipe,
)
from apiAnalysis.tool.mfa_receiver import MfaPushBroker


def _recipe(url="https://auth.example.test/login"):
    return {
        "schema_version": 1,
        "steps": [{
            "id": "login",
            "type": "http",
            "method": "POST",
            "url": url,
            "json": {
                "account": "{{credential.username}}",
                "password": "{{credential.password}}",
            },
            "success_statuses": [200],
            "extract": {
                "access_token": {"source": "json", "path": "access_token", "required": True},
            },
        }],
        "output": {
            "auth_kind": "bearer",
            "headers": {"Authorization": "Bearer {{vars.access_token}}"},
            "include_session_cookies": False,
            "expires_in_seconds": 300,
        },
    }


class FakeResponse:
    def __init__(self, status_code=200, payload=None,
                 url="https://auth.example.test/login", cookies=None):
        self.status_code = status_code
        self._payload = payload or {}
        self.url = url
        self.headers = {}
        self.is_redirect = False
        self.cookies = dict(cookies or {})
        self.text = ""

    def json(self):
        return self._payload


class FakeSession:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []
        self.cookies = requests.cookies.RequestsCookieJar()

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        response = self.responses.pop(0)
        for name, value in response.cookies.items():
            self.cookies.set(name, value)
        return response


class AuthRecipeTests(unittest.TestCase):
    @staticmethod
    def _rsa_key_pair():
        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048,
        )
        public_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")
        return private_key, public_pem

    def test_success_returns_only_in_memory_output_and_safe_repr(self):
        session = FakeSession([FakeResponse(payload={"access_token": "token-secret"})])
        result = AuthRecipeExecutor(session=session).execute(
            _recipe(),
            {"username": "owner", "password": "password-secret"},
            realm_auth_origins=["https://auth.example.test"],
            adapter_auth_origins=["https://auth.example.test"],
        )

        self.assertEqual(result.headers, {"Authorization": "Bearer token-secret"})
        self.assertEqual(result.request_count, 1)
        self.assertNotIn("token-secret", repr(result))
        self.assertNotIn("password-secret", repr(result))
        self.assertEqual(session.calls[0][2]["json"]["password"], "password-secret")

    def test_extracted_business_identity_is_projected_without_tokens(self):
        recipe = _recipe()
        recipe["steps"][0]["extract"]["enterprise_id"] = {
            "source": "json", "path": "enterprise.id", "required": True,
        }
        session = FakeSession([FakeResponse(payload={
            "access_token": "token-secret",
            "enterprise": {"id": 42},
        })])

        result = AuthRecipeExecutor(session=session).execute(
            recipe,
            {"username": "owner", "password": "password-secret"},
            realm_auth_origins=["https://auth.example.test"],
            adapter_auth_origins=["https://auth.example.test"],
        )

        self.assertEqual(result.business_identity, {"enterprise_id": "42"})
        self.assertNotIn("access_token", result.business_identity)
        self.assertNotIn("token-secret", repr(result))

    def test_origin_intersection_blocks_request_before_network(self):
        session = FakeSession([])
        with self.assertRaises(AuthRecipeFailure) as raised:
            AuthRecipeExecutor(session=session).execute(
                _recipe("https://other.example.test/login"),
                {"username": "owner", "password": "password-secret"},
                realm_auth_origins=["https://auth.example.test"],
                adapter_auth_origins=["https://auth.example.test"],
            )
        self.assertEqual(raised.exception.code, "CONFIG_INVALID")
        self.assertEqual(session.calls, [])
        self.assertNotIn("password-secret", str(raised.exception))

    def test_401_is_structured_as_credential_rejected(self):
        session = FakeSession([FakeResponse(status_code=401)])
        with self.assertRaises(AuthRecipeFailure) as raised:
            AuthRecipeExecutor(session=session).execute(
                _recipe(),
                {"username": "owner", "password": "password-secret"},
                realm_auth_origins=["https://auth.example.test"],
                adapter_auth_origins=["https://auth.example.test"],
            )
        self.assertEqual(raised.exception.code, "CREDENTIAL_REJECTED")
        self.assertEqual(raised.exception.request_count, 1)

    def test_json_error_rule_can_request_interaction(self):
        recipe = _recipe()
        recipe["steps"][0].update({
            "json_error_path": "error",
            "json_error_code_map": {"captcha_required": "MFA_OR_INTERACTION_REQUIRED"},
        })
        session = FakeSession([FakeResponse(payload={"error": "captcha_required"})])
        with self.assertRaises(AuthRecipeFailure) as raised:
            AuthRecipeExecutor(session=session).execute(
                recipe,
                {"username": "owner", "password": "password-secret"},
                realm_auth_origins=["https://auth.example.test"],
                adapter_auth_origins=["https://auth.example.test"],
            )
        self.assertEqual(raised.exception.code, "MFA_OR_INTERACTION_REQUIRED")

    def test_origin_and_content_hash_are_canonical(self):
        self.assertEqual(normalize_origin("HTTPS://AUTH.EXAMPLE.TEST:443/path"), "https://auth.example.test")
        self.assertEqual(canonical_json_sha256({"b": 2, "a": 1}), canonical_json_sha256({"a": 1, "b": 2}))

    def test_guided_repair_recipe_supports_form_and_password_transform(self):
        recipe = build_password_login_recipe(
            "https://auth.example.test/login",
            request_format="form",
            username_field="login_name",
            password_field="password_md5",
            password_transform="md5",
            token_path="data.token",
            extra_fields={"ismd5": 1},
        )
        session = FakeSession([
            FakeResponse(payload={"data": {"token": "token-secret"}}),
        ])

        result = AuthRecipeExecutor(session=session).execute(
            recipe,
            {"username": "owner", "password": "password-secret"},
            realm_auth_origins=["https://auth.example.test"],
            adapter_auth_origins=["https://auth.example.test"],
        )

        sent = session.calls[0][2]["data"]
        self.assertEqual(sent["login_name"], "owner")
        self.assertEqual(
            sent["password_md5"],
            hashlib.md5(b"password-secret").hexdigest(),
        )
        self.assertEqual(sent["ismd5"], 1)
        self.assertEqual(result.headers, {"Authorization": "Bearer token-secret"})

    def test_rsa_password_transform_encrypts_timestamped_plaintext(self):
        private_key, public_pem = self._rsa_key_pair()
        recipe = build_password_login_recipe(
            "https://auth.example.test/login",
            password_transform="rsa_pkcs1v15",
            rsa_public_key_secret_name="login_rsa_public_key",
            rsa_append_timestamp=True,
            rsa_timestamp_delimiter="###",
            rsa_timestamp_unit="seconds",
            extra_fields={"algo": "rsa"},
        )
        session = FakeSession([
            FakeResponse(payload={"access_token": "token-secret"}),
        ])

        result = AuthRecipeExecutor(session=session).execute(
            recipe,
            {"username": "owner", "password": "password-secret"},
            realm_auth_origins=["https://auth.example.test"],
            adapter_auth_origins=["https://auth.example.test"],
            realm_secrets={"login_rsa_public_key": public_pem},
        )

        encrypted = session.calls[0][2]["json"]["password"]
        plaintext = private_key.decrypt(
            base64.b64decode(encrypted), padding.PKCS1v15(),
        ).decode("utf-8")
        self.assertRegex(plaintext, r"^password-secret###\d{10}$")
        self.assertEqual(session.calls[0][2]["json"]["algo"], "rsa")
        self.assertEqual(result.headers, {"Authorization": "Bearer token-secret"})
        self.assertNotIn("password-secret", repr(result))

    def test_rsa_password_transform_does_not_add_timestamp_by_default(self):
        recipe = build_password_login_recipe(
            "https://auth.example.test/login",
            password_transform="rsa_pkcs1v15",
            token_path="access_token",
        )
        set_steps = [
            step for step in recipe["steps"] if step.get("type") == "set"
        ]
        self.assertEqual(len(set_steps), 1)
        self.assertEqual(set_steps[0]["operation"], "rsa_encrypt")
        self.assertEqual(set_steps[0]["value"], "{{credential.password}}")

    def test_pull_mfa_receiver_completes_final_token_chain(self):
        recipe = {
            "schema_version": 1,
            "steps": [
                {
                    "id": "login",
                    "type": "http",
                    "method": "POST",
                    "url": "https://auth.example.test/login",
                    "json": {"account": "{{credential.username}}"},
                    "success_statuses": [200],
                    "extract": {
                        "auth_code": {"source": "json", "path": "two_factor.auth_code"},
                        "authorization_code": {"source": "json", "path": "two_factor.authorization_code"},
                    },
                },
                {
                    "id": "send_mfa",
                    "type": "http",
                    "method": "POST",
                    "url": "https://auth.example.test/send-code",
                    "json": {"auth_code": "{{vars.auth_code}}"},
                    "success_statuses": [204],
                },
                {
                    "id": "receive_mfa",
                    "type": "mfa_receive",
                    "mode": "pull",
                    "target": "mfa_code",
                    "method": "POST",
                    "url": "https://receiver.example.test/code",
                    "json": {"account": "{{credential.username}}"},
                    "success_statuses": [200],
                    "extract": {
                        "source": "json", "list_path": "data",
                        "match_path": "type", "match_value": "login-2fa",
                        "path": "code",
                    },
                },
                {
                    "id": "verify",
                    "type": "http",
                    "method": "POST",
                    "url": "https://auth.example.test/verify",
                    "json": {
                        "auth_code": "{{vars.auth_code}}",
                        "authorization_code": "{{vars.authorization_code}}",
                        "verify_code": "{{vars.mfa_code}}",
                    },
                    "success_statuses": [200],
                    "extract": {
                        "access_token": {"source": "json", "path": "access_token"},
                    },
                },
            ],
            "output": {
                "auth_kind": "bearer",
                "headers": {"Authorization": "Bearer {{vars.access_token}}"},
                "expires_in_seconds": 300,
            },
        }
        session = FakeSession([
            FakeResponse(payload={"two_factor": {
                "auth_code": "challenge-auth",
                "authorization_code": "challenge-authorization",
            }}),
            FakeResponse(status_code=204, payload={}),
            FakeResponse(payload={"data": [
                {"type": "other-scene", "code": "111111"},
                {"type": "login-2fa", "code": "654321"},
            ]}),
            FakeResponse(payload={"access_token": "final-token"}),
        ])

        result = AuthRecipeExecutor(session=session, max_requests=4).execute(
            recipe,
            {"username": "owner", "password": "password-secret"},
            realm_auth_origins=[
                "https://auth.example.test", "https://receiver.example.test",
            ],
            adapter_auth_origins=[
                "https://auth.example.test", "https://receiver.example.test",
            ],
        )

        self.assertEqual(result.headers, {"Authorization": "Bearer final-token"})
        self.assertEqual(result.request_count, 4)
        self.assertEqual(
            session.calls[1][2]["json"]["auth_code"], "challenge-auth",
        )
        self.assertEqual(session.calls[3][2]["json"]["verify_code"], "654321")
        self.assertNotIn("654321", repr(result))
        self.assertNotIn("654321", str(result.diagnostics))

    def test_push_mfa_receiver_completes_final_token_chain(self):
        broker = MfaPushBroker()
        recipe = {
            "schema_version": 1,
            "steps": [
                {
                    "id": "login", "type": "http", "method": "POST",
                    "url": "https://auth.example.test/login",
                    "json": {"account": "{{credential.username}}"},
                    "success_statuses": [200],
                    "extract": {"auth_code": {"source": "json", "path": "auth_code"}},
                },
                {
                    "id": "receive_mfa", "type": "mfa_receive",
                    "mode": "push", "receiver_id": "company-otp",
                    "correlation": "{{credential.username}}",
                    "target": "mfa_code", "timeout_seconds": 3,
                },
                {
                    "id": "verify", "type": "http", "method": "POST",
                    "url": "https://auth.example.test/verify",
                    "json": {"auth_code": "{{vars.auth_code}}", "code": "{{vars.mfa_code}}"},
                    "success_statuses": [200],
                    "extract": {"access_token": {"source": "json", "path": "access_token"}},
                },
            ],
            "output": {
                "auth_kind": "bearer",
                "headers": {"Authorization": "Bearer {{vars.access_token}}"},
                "expires_in_seconds": 300,
            },
        }
        session = FakeSession([
            FakeResponse(payload={"auth_code": "challenge"}),
            FakeResponse(payload={"access_token": "final-token"}),
        ])
        outcome = {}

        def run_recipe():
            try:
                outcome["result"] = AuthRecipeExecutor(
                    session=session, max_requests=2, mfa_push_broker=broker,
                ).execute(
                    recipe,
                    {"username": "owner", "password": "password-secret"},
                    realm_auth_origins=["https://auth.example.test"],
                    adapter_auth_origins=["https://auth.example.test"],
                )
            except Exception as exc:  # pragma: no cover - assertion reports detail
                outcome["error"] = exc

        worker = threading.Thread(target=run_recipe, daemon=True)
        worker.start()
        pending = []
        deadline = time.time() + 2
        while time.time() < deadline and not pending:
            pending = broker.pending("company-otp")
            if not pending:
                time.sleep(0.01)
        self.assertEqual(len(pending), 1)
        self.assertEqual(pending[0]["correlation"], "owner")
        self.assertTrue(broker.deliver(pending[0]["transaction_id"], "123456"))
        worker.join(timeout=2)

        self.assertFalse(worker.is_alive())
        self.assertNotIn("error", outcome)
        self.assertEqual(
            outcome["result"].headers,
            {"Authorization": "Bearer final-token"},
        )
        self.assertEqual(session.calls[1][2]["json"]["code"], "123456")
        self.assertEqual(broker.pending(), [])

    def test_advanced_repair_recipe_rejects_literal_token(self):
        recipe = _recipe()
        recipe["output"]["headers"]["Authorization"] = "Bearer persisted-secret"
        with self.assertRaisesRegex(ValueError, "literal"):
            validate_repair_recipe(recipe)

    def test_sso_product_recipe_uses_only_final_token_for_business_context(self):
        recipe = build_sso_product_token_recipe(
            "https://identity.example.test/authorization",
            "https://login.example.test/login/token-login",
            "https://product.example.test/product/verification",
            browser_id="browser-fixture",
        )
        session = FakeSession([
            FakeResponse(
                payload={"access_token": "sso-fixture"},
                url="https://identity.example.test/authorization",
            ),
            FakeResponse(
                status_code=302,
                url="https://login.example.test/login/token-login",
                cookies={"session_id": "session-secret"},
            ),
            FakeResponse(
                payload={"access_token": "final-product-token"},
                url="https://product.example.test/product/verification",
            ),
        ])

        result = AuthRecipeExecutor(session=session, max_requests=3).execute(
            recipe,
            {"username": "owner", "password": "password-secret"},
            realm_auth_origins=[
                "https://identity.example.test",
                "https://login.example.test",
                "https://product.example.test",
            ],
            adapter_auth_origins=[
                "https://identity.example.test",
                "https://login.example.test",
                "https://product.example.test",
            ],
            realm_secrets={"client_token": "realm-client-secret"},
        )

        self.assertEqual(result.request_count, 3)
        self.assertEqual(
            result.headers,
            {"Authorization": "Bearer final-product-token"},
        )
        self.assertEqual(result.cookies, {"session_id": "session-secret"})
        first_body = session.calls[0][2]["json"]
        self.assertEqual(first_body["account"], "owner")
        self.assertEqual(
            first_body["password"], hashlib.md5(b"password-secret").hexdigest(),
        )
        client_hash = hashlib.md5(b"realm-client-secret").hexdigest()
        expected_request_token = hashlib.md5(
            ("owner" + client_hash + str(first_body["timestamp"])).encode("utf-8")
        ).hexdigest()
        self.assertEqual(first_body["token"], expected_request_token)
        self.assertEqual(
            session.calls[1][2]["params"],
            {"token": "sso-fixture"},
        )
        self.assertEqual(
            session.calls[2][2]["headers"]["Authorization"],
            "Bearer sso-fixture",
        )
        self.assertEqual(
            session.calls[2][2]["json"],
            {"browserid": "browser-fixture", "browsertype": "chrome"},
        )
        self.assertNotIn("sso-fixture", repr(result))
        self.assertNotIn("final-product-token", repr(result))

    def test_legacy_exchange_recipe_is_classified_by_final_output_not_label(self):
        recipe = _recipe()
        recipe["template"] = "legacy_vendor_product_token_v1"
        recipe["output"]["headers"] = {
            "Authorization": "Bearer {{vars.product_access_token}}",
        }
        self.assertEqual(recipe_output_credential_stage(recipe), "product")
        recipe["output"]["headers"] = {
            "Authorization": "Bearer {{vars.sso_access_token}}",
        }
        self.assertEqual(recipe_output_credential_stage(recipe), "session")



if __name__ == "__main__":
    unittest.main()
