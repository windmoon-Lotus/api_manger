import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import requests

from apiAnalysis.core.identify.sso import legalize_ws
from apiAnalysis.model.exception import AccountException
from apiAnalysis.tool.account_context import AccountContextRef, AccountContextResolver
from apiAnalysis.tool.project_auth import (
    AUTH_RECIPE_PROVIDER_ID,
    DATABASE_SSO_PROVIDER_ID,
    TOKEN_ENDPOINT_PROVIDER_ID,
    USER_CODE_PROVIDER_ID,
    DatabaseSsoAccountContextProvider,
    RecipeAccountContextProvider,
    auth_repair_defaults,
    environment_host_names,
    normalize_host,
    profile_context_fields,
    register_project_auth_providers,
)


class ProjectAuthTests(unittest.TestCase):
    @patch("apiAnalysis.core.identify.sso._load_local_env")
    @patch("apiAnalysis.core.identify.sso.requests.post")
    def test_sso_401_is_reported_without_a_duplicate_login_post(self, post, _load_env):
        post.return_value = SimpleNamespace(status_code=401)
        account = SimpleNamespace(username="test-owner", password="test-password")

        with patch.dict("os.environ", {
            "API_MANAGER_SSO_AUTH_URL": "https://auth.example.test/authorization",
            "API_MANAGER_SSO_LOGIN_URL": "https://login.example.test/token-login",
            "API_MANAGER_SSO_CLIENT_TOKEN": "test-protocol-token",
        }, clear=False):
            with self.assertRaisesRegex(AccountException, "SSO_AUTH_HTTP_401"):
                legalize_ws(account, SimpleNamespace())

        self.assertEqual(post.call_count, 1)

    def test_environment_hosts_are_normalized_and_deduplicated(self):
        environment = SimpleNamespace(
            default_host="https://API.EXAMPLE.test/base",
            hosts=[
                {"host": "api.example.test"},
                {"base_url": "https://files.example.test/v1"},
            ],
        )
        self.assertEqual(
            environment_host_names(environment),
            ["api.example.test", "files.example.test"],
        )
        self.assertEqual(normalize_host("HTTPS://API.EXAMPLE.TEST/a"), "api.example.test")

    def test_profile_context_uses_account_alias_and_profile_revision(self):
        profile = SimpleNamespace(
            project_id="p1", env_id="test", account_key="owner",
            provider_id=DATABASE_SSO_PROVIDER_ID, context_ref="owner-v2",
            profile_id="profile-1",
        )
        self.assertEqual(profile_context_fields(profile), {
            "project_id": "p1",
            "env_id": "test",
            "account_id": "owner",
            "auth_mode": "account",
            "auth_provider_id": DATABASE_SSO_PROVIDER_ID,
            "auth_context_ref": "owner-v2",
            "auth_profile_revision_id": "",
            "auth_realm_revision_id": "",
            "auth_adapter_version_id": "",
        })

    @patch("apiAnalysis.tool.project_auth.realm_secret_key_names", return_value=[])
    @patch.object(RecipeAccountContextProvider, "_load_revision_chain")
    def test_repair_defaults_remove_the_complete_token_marker(
        self, load_revision_chain, _secret_names,
    ):
        recipe = {
            "schema_version": 1,
            "steps": [{
                "id": "login",
                "type": "http",
                "method": "POST",
                "url": "https://auth.example.test/login",
                "json": {
                    "account": "{{credential.username}}",
                    "password": "{{credential.password}}",
                },
                "extract": {
                    "access_token": {
                        "source": "json",
                        "path": "access_token",
                    },
                },
            }],
            "output": {
                "auth_kind": "bearer",
                "headers": {
                    "Authorization": "Bearer {{vars.access_token}}",
                },
                "expires_in_seconds": 300,
            },
        }
        load_revision_chain.return_value = (
            SimpleNamespace(auth_kind="bearer", max_age_seconds=300),
            SimpleNamespace(
                tls_verify=True,
                auth_origins=["https://auth.example.test"],
            ),
            SimpleNamespace(recipe=recipe),
        )
        defaults = auth_repair_defaults(
            SimpleNamespace(auth_kind="bearer"),
        )
        self.assertEqual(defaults["token_prefix"], "Bearer")

    @patch("apiAnalysis.tool.project_auth.legalize_ws")
    @patch("apiAnalysis.tool.project_auth.WorkspaceSso")
    @patch("apiAnalysis.tool.project_auth.ProjectEnvironment")
    @patch("apiAnalysis.tool.project_auth.ProjectAccountBinding")
    @patch("apiAnalysis.tool.project_auth.ProjectAuthProfile")
    def test_database_provider_acquires_bearer_and_cookie_in_memory(
        self, profile_model, binding_model, environment_model, workspace_model, legalize_ws,
    ):
        profile = SimpleNamespace(
            profile_id="profile-1", project_id="p1", env_id="test",
            account_key="owner", provider_id=DATABASE_SSO_PROVIDER_ID,
            context_ref="owner-current", auth_kind="mixed",
            allowed_hosts=["api.example.test"], metadata={
                "max_age_seconds": 300,
                "workspace_sso_id": "507f1f77bcf86cd799439011",
            },
            last_error_type="", last_refresh_at=None, mtime=None, save=MagicMock(),
        )
        profile_model.objects.return_value = [profile]
        binding_model.objects.return_value.first.return_value = SimpleNamespace(
            account=SimpleNamespace(username="owner"),
        )
        environment_model.objects.return_value.first.return_value = None
        workspace_model.objects.return_value.first.return_value = SimpleNamespace(id="sso-1")
        session = requests.Session()
        session.cookies.set("sid", "cookie-secret")
        legalize_ws.return_value = ("Bearer token-secret", session)

        reference = AccountContextRef(
            project_id="p1", env_id="test", account_id="owner",
            provider_id=DATABASE_SSO_PROVIDER_ID, context_ref="owner-current",
        )
        context = DatabaseSsoAccountContextProvider().resolve(reference)
        self.assertEqual(context.headers, {"Authorization": "Bearer token-secret"})
        self.assertEqual(context.cookies, {"sid": "cookie-secret"})
        self.assertNotIn("token-secret", repr(context))
        self.assertNotIn("cookie-secret", repr(context))
        profile.save.assert_called()

    def test_runtime_registers_all_imported_auth_providers(self):
        resolver = register_project_auth_providers(AccountContextResolver())
        self.assertEqual(
            set(resolver._providers),
            {
                DATABASE_SSO_PROVIDER_ID,
                AUTH_RECIPE_PROVIDER_ID,
                TOKEN_ENDPOINT_PROVIDER_ID,
                USER_CODE_PROVIDER_ID,
            },
        )


if __name__ == "__main__":
    unittest.main()
