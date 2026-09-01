import datetime as dt
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from apiAnalysis.tool.account_context import (
    AccountContext,
    AccountContextExpired,
    AccountContextHostNotAllowed,
    AccountContextInvalid,
    AccountContextRef,
    AccountContextResolver,
    AccountContextUnavailable,
    CallbackAccountContextProvider,
    CodeAccountContextProvider,
    JsonFileAccountContextProvider,
    TokenEndpointProvider,
    validate_trusted_auth_code,
)
from apiAnalysis.tool.snapshot_runner import _headers_with_local_auth, _request_kwargs


class AccountContextTests(unittest.TestCase):
    def _reference(self):
        return AccountContextRef(
            project_id="example-project", env_id="formal", account_id="owner",
            provider_id="test_provider", context_ref="owner-current",
        )

    def _context(self, **overrides):
        values = {
            "project_id": "example-project",
            "env_id": "formal",
            "account_id": "owner",
            "provider_id": "test_provider",
            "context_ref": "owner-current",
            "headers": {"Authorization": "Bearer super-secret"},
            "cookies": {"session": "cookie-secret"},
            "auth_kind": "product_bearer",
            "expires_at": dt.datetime.utcnow() + dt.timedelta(minutes=10),
            "allowed_hosts": ["api.example.test", "*.example.test"],
        }
        values.update(overrides)
        return AccountContext(**values)

    def test_repr_and_descriptor_never_contain_credential_values(self):
        context = self._context()
        rendered = repr(context)
        descriptor = json.dumps(context.descriptor(), sort_keys=True)
        self.assertNotIn("super-secret", rendered + descriptor)
        self.assertNotIn("cookie-secret", rendered + descriptor)
        self.assertEqual(context.descriptor()["header_names"], ["Authorization"])
        self.assertEqual(context.descriptor()["cookie_names"], ["session"])

    def test_context_checks_identity_expiry_and_host_scope(self):
        context = self._context()
        self.assertIs(context.validate(self._reference(), "api.example.test"), context)
        self.assertIs(context.validate(self._reference(), "a.example.test"), context)
        with self.assertRaises(AccountContextHostNotAllowed):
            context.validate(self._reference(), "other.example")
        with self.assertRaises(AccountContextExpired):
            self._context(expires_at=dt.datetime.utcnow()).validate(self._reference())
        with self.assertRaises(AccountContextInvalid):
            self._context(allowed_hosts=["*"])
        with self.assertRaises(AccountContextInvalid):
            self._context(headers={"Host": "evil.example"})

    def test_private_json_provider_resolves_canonical_record(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "accounts.private.json"
            path.write_text(json.dumps({
                "project_id": "example-project",
                "env_id": "formal",
                "allowed_hosts": ["api.example.test"],
                "accounts": [{
                    "account_id": "owner",
                    "context_ref": "owner-current",
                    "status": "ready",
                    "auth_kind": "product_bearer",
                    "authorization": "Bearer file-secret",
                    "expires_at": (dt.datetime.utcnow() + dt.timedelta(minutes=10)).isoformat() + "Z",
                }],
            }), encoding="utf-8")
            provider = JsonFileAccountContextProvider(str(path), provider_id="test_provider")
            context = provider.resolve(self._reference())
            self.assertEqual(context.headers["Authorization"], "Bearer file-secret")
            self.assertEqual(context.descriptor()["allowed_hosts"], ["api.example.test"])
            with self.assertRaises(AccountContextHostNotAllowed):
                context.validate(self._reference(), "other.example")

    def test_malformed_private_file_error_does_not_echo_content(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "broken.private.json"
            path.write_text("not-json bearer-do-not-echo", encoding="utf-8")
            provider = JsonFileAccountContextProvider(
                str(path), provider_id="test_provider",
                default_project_id="example-project", default_env_id="formal",
                allowed_hosts=["api.example.test"],
            )
            with self.assertRaises(AccountContextUnavailable) as raised:
                provider.resolve(self._reference())
            self.assertNotIn("bearer-do-not-echo", str(raised.exception))

    def test_legacy_account_index_can_be_scoped_without_rewriting_private_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "legacy.private.json"
            path.write_text(json.dumps({
                "createdAt": int(dt.datetime.now().timestamp()),
                "accounts": [{
                    "index": 0,
                    "username": "test-user",
                    "status": "ok",
                    "authorization": "Bearer legacy-secret",
                    "expiresHint": (dt.datetime.now() + dt.timedelta(minutes=5)).isoformat(),
                }],
            }), encoding="utf-8")
            reference = AccountContextRef(
                project_id="legacy-project", env_id="formal", account_id="account[0]",
                provider_id="legacy_file",
            )
            provider = JsonFileAccountContextProvider(
                str(path), provider_id="legacy_file",
                default_project_id="legacy-project", default_env_id="formal",
                allowed_hosts=["legacy.example.test"],
            )
            context = provider.resolve(reference)
            self.assertEqual(context.account_id, "account[0]")
            self.assertEqual(context.descriptor()["header_names"], ["Authorization"])

    def test_callback_provider_is_short_cached_and_host_validated(self):
        calls = []

        def callback(reference):
            calls.append(reference.cache_key())
            return self._context()

        resolver = AccountContextResolver([
            CallbackAccountContextProvider("test_provider", callback),
        ], cache_seconds=15)
        resolver.resolve(self._reference(), "api.example.test")
        resolver.resolve(self._reference(), "api.example.test")
        self.assertEqual(len(calls), 1)
        with self.assertRaises(AccountContextHostNotAllowed):
            resolver.resolve(self._reference(), "outside.example")

    def test_account_replay_strips_imported_and_global_auth_then_injects_context(self):
        snapshot = SimpleNamespace(
            project_id="example-project", env_id="formal", account_id="owner",
            auth_provider_id="test_provider", auth_context_ref="owner-current",
            auth_mode="account", domain="api.example.test",
            url="https://api.example.test/users/me",
            headers={
                "Accept": "application/json",
                "Authorization": "Bearer imported-secret",
                "X-Access-Token": "imported-token",
            },
            cookies={"imported": "cookie"}, body=None, content_type="",
        )
        with patch.dict("os.environ", {
            "API_MANAGER_AUTHORIZATION": "Bearer global-secret",
            "API_MANAGER_AUTH_COOKIE": "global=cookie",
        }, clear=False):
            kwargs = _request_kwargs(
                snapshot, auth_mode="account", account_context=self._context(),
            )
        self.assertEqual(kwargs["headers"]["Authorization"], "Bearer super-secret")
        self.assertNotIn("X-Access-Token", kwargs["headers"])
        self.assertEqual(kwargs["cookies"], {"session": "cookie-secret"})
        self.assertNotIn("global-secret", repr(kwargs))

    def test_account_mode_without_context_fails_closed(self):
        with self.assertRaises(AccountContextInvalid):
            _headers_with_local_auth({}, auth_mode="account")

    def test_token_endpoint_uses_versioned_material_and_preserves_alias_identity(self):
        class Response:
            content = b'{"data":{"token":"short-lived"}}'
            text = content.decode()
            cookies = {}

            @staticmethod
            def raise_for_status():
                return None

            @staticmethod
            def json():
                return {"data": {"token": "short-lived"}}

        class Client:
            def __init__(self):
                self.calls = []

            def request(self, method, url, **kwargs):
                self.calls.append((method, url, kwargs))
                return Response()

        reference = AccountContextRef(
            project_id="p1", env_id="test", account_id="admin",
            provider_id="token_endpoint", context_ref="profile-rev-1",
        )
        client = Client()
        provider = TokenEndpointProvider(
            session=client,
            material_loader=lambda _reference: {
                "config": {
                    "token_url": "https://auth.example.test/token",
                    "token_method": "POST",
                    "pass_credentials": "body",
                    "response_path": "data.token",
                    "token_prefix": "Bearer ",
                    "expires_in": 300,
                },
                "credentials": {
                    "username": "real-admin",
                    "password": "private-password",
                },
                "auth_origins": ["https://auth.example.test"],
                "allowed_hosts": ["api.example.test"],
                "tls_verify": True,
            },
        )

        context = provider.resolve(reference)

        self.assertEqual(context.account_id, "admin")
        self.assertEqual(context.headers["Authorization"], "Bearer short-lived")
        self.assertEqual(context.descriptor()["allowed_hosts"], ["api.example.test"])
        self.assertEqual(len(client.calls), 1)
        self.assertTrue(client.calls[0][2]["verify"])
        self.assertFalse(client.calls[0][2]["allow_redirects"])
        self.assertEqual(client.calls[0][2]["json"]["username"], "real-admin")

    def test_token_endpoint_rejects_url_outside_realm_before_request(self):
        class Client:
            @staticmethod
            def request(*_args, **_kwargs):
                raise AssertionError("request must not be sent")

        reference = AccountContextRef(
            project_id="p1", env_id="test", account_id="owner",
            provider_id="token_endpoint", context_ref="profile-rev-1",
        )
        provider = TokenEndpointProvider(
            session=Client(),
            material_loader=lambda _reference: {
                "config": {"token_url": "https://outside.example/token"},
                "auth_origins": ["https://auth.example.test"],
                "allowed_hosts": ["api.example.test"],
            },
        )
        with self.assertRaises(AccountContextInvalid):
            provider.resolve(reference)

    def test_trusted_code_runs_in_subprocess_and_blocks_unsupported_imports(self):
        reference = AccountContextRef(
            project_id="p1", env_id="test", account_id="member",
            provider_id="user_code", context_ref="profile-rev-2",
        )
        source = (
            "def get_auth(username, password):\n"
            "    return {'headers': {'Authorization': 'Bearer ' + username}, "
            "'expires_in': 300}\n"
        )
        provider = CodeAccountContextProvider(
            material_loader=lambda _reference: {
                "source": source,
                "credentials": {"username": "member-1", "password": "secret"},
                "auth_origins": ["https://auth.example.test"],
                "allowed_hosts": ["api.example.test"],
                "tls_verify": True,
                "max_age_seconds": 300,
                "config": {"timeout_seconds": 5, "max_requests": 1},
            },
        )

        context = provider.resolve(reference)

        self.assertEqual(context.headers["Authorization"], "Bearer member-1")
        self.assertEqual(context.account_id, "member")
        with self.assertRaisesRegex(ValueError, "unsupported module"):
            validate_trusted_auth_code(
                "import os\ndef get_auth(username, password):\n    return {}\n"
            )


if __name__ == "__main__":
    unittest.main()
