import copy
import os
import unittest
import uuid

from apiAnalysis.db.collection import (
    ApiProject,
    AuthAdapter,
    AuthAdapterVersion,
    AuthProfileHealth,
    AuthRealm,
    AuthRealmRevision,
    AuthRealmSecretVersion,
    AuthVerificationAttempt,
    ProjectAuthProfile,
    ProjectAuthProfileRevision,
    ProjectEnvironment,
)
from apiAnalysis.main import _ensure_mongo_connection
from apiAnalysis.tool.account_context import (
    AccountContextRef,
    CodeAccountContextProvider,
    TokenEndpointProvider,
)
from apiAnalysis.tool.project_auth import (
    TOKEN_ENDPOINT_PROVIDER_ID,
    USER_CODE_PROVIDER_ID,
    load_versioned_auth_material,
    profile_context_fields,
    verify_project_auth_profile,
)
from apiAnalysis.tool.universal_auth import (
    import_code_as_profile,
    import_recipe_as_profile,
    import_token_endpoint_as_profile,
)


@unittest.skipUnless(
    os.getenv("API_MANAGER_INTEGRATION_TESTS") == "1",
    "set API_MANAGER_INTEGRATION_TESTS=1 to use local MongoDB",
)
class AuthImportIntegrationTests(unittest.TestCase):
    def setUp(self):
        _ensure_mongo_connection()
        self.project_id = "auth-import-{}".format(uuid.uuid4().hex)
        self.env_id = "test"
        ApiProject(
            project_id=self.project_id,
            name="Auth Import Integration",
        ).save()
        ProjectEnvironment(
            project_id=self.project_id,
            env_id=self.env_id,
            name="Test",
            environment_type="test",
            default_host="https://api.example.test",
            hosts=[{"base_url": "https://api.example.test"}],
            active=True,
        ).save()
        self.recipe = {
            "schema_version": 1,
            "steps": [{
                "id": "login",
                "type": "http",
                "method": "POST",
                "url": "https://auth.example.test/login",
                "json": {
                    "username": "{{credential.username}}",
                    "password": "{{credential.password}}",
                },
                "success_statuses": [200],
                "extract": {
                    "access_token": {
                        "source": "json",
                        "path": "access_token",
                        "required": True,
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

    def tearDown(self):
        profiles = list(ProjectAuthProfile.objects(project_id=self.project_id))
        profile_ids = [item.profile_id for item in profiles]
        revisions = list(ProjectAuthProfileRevision.objects(
            profile_id__in=profile_ids,
        )) if profile_ids else []
        realm_revision_ids = [item.realm_revision_id for item in revisions]
        realms = list(AuthRealmRevision.objects(
            realm_revision_id__in=realm_revision_ids,
        )) if realm_revision_ids else []
        realm_ids = sorted({item.realm_id for item in realms})
        adapter_version_ids = sorted({
            item.adapter_version_id for item in realms
        })
        adapter_versions = list(AuthAdapterVersion.objects(
            adapter_version_id__in=adapter_version_ids,
        )) if adapter_version_ids else []
        adapter_ids = sorted({item.adapter_id for item in adapter_versions})

        if profile_ids:
            AuthProfileHealth.objects(profile_id__in=profile_ids).delete()
            AuthVerificationAttempt.objects(profile_id__in=profile_ids).delete()
            ProjectAuthProfileRevision.objects(profile_id__in=profile_ids).delete()
            ProjectAuthProfile.objects(profile_id__in=profile_ids).delete()
        if realm_ids:
            AuthRealmSecretVersion.objects(realm_id__in=realm_ids).delete()
            AuthRealmRevision.objects(realm_id__in=realm_ids).delete()
            AuthRealm.objects(realm_id__in=realm_ids).delete()
        if adapter_ids:
            AuthAdapterVersion.objects(adapter_id__in=adapter_ids).delete()
            AuthAdapter.objects(adapter_id__in=adapter_ids).delete()
        ProjectEnvironment.objects(project_id=self.project_id).delete()
        ApiProject.objects(project_id=self.project_id).delete()

    def test_multiple_login_points_coexist_and_same_recipe_key_versions_cleanly(self):
        admin = import_recipe_as_profile(
            project_id=self.project_id,
            env_id=self.env_id,
            profile_name="后台管理员登录",
            recipe=self.recipe,
            auth_origins=["https://auth.example.test"],
            account_key="admin-account",
            recipe_key="shared-password-flow",
            realm_key="shared-password-realm",
            realm_secrets={"client_token": "shared-client-secret"},
            login_scene="admin-console",
            role_key="admin",
            login_mode="password",
        )
        member = import_recipe_as_profile(
            project_id=self.project_id,
            env_id=self.env_id,
            profile_name="普通用户登录",
            recipe=self.recipe,
            auth_origins=["https://auth.example.test"],
            account_key="member-account",
            recipe_key="shared-password-flow",
            realm_key="shared-password-realm",
            realm_secrets={"client_token": "shared-client-secret"},
            login_scene="member-web",
            role_key="member",
            login_mode="password",
        )

        self.assertNotEqual(admin["profile_id"], member["profile_id"])
        self.assertEqual(admin["adapter_id"], member["adapter_id"])
        self.assertEqual(admin["adapter_version_id"], member["adapter_version_id"])
        self.assertEqual(admin["realm_id"], member["realm_id"])
        self.assertEqual(admin["realm_revision_id"], member["realm_revision_id"])
        self.assertEqual(admin["secret_version_id"], member["secret_version_id"])
        self.assertEqual(
            ProjectAuthProfile.objects(
                project_id=self.project_id, active=True,
            ).count(),
            2,
        )

        changed_recipe = copy.deepcopy(self.recipe)
        changed_recipe["steps"].insert(0, {
            "id": "timestamp",
            "type": "set",
            "target": "timestamp",
            "operation": "unix_time",
        })
        updated_admin = import_recipe_as_profile(
            project_id=self.project_id,
            env_id=self.env_id,
            profile_name="后台管理员登录",
            recipe=changed_recipe,
            auth_origins=["https://auth.example.test"],
            account_key="admin-account",
            recipe_key="shared-password-flow",
            realm_key="shared-password-realm",
            realm_secrets={"client_token": "shared-client-secret"},
            login_scene="admin-console",
            role_key="admin",
            login_mode="password",
        )

        self.assertEqual(updated_admin["profile_id"], admin["profile_id"])
        self.assertEqual(updated_admin["adapter_id"], admin["adapter_id"])
        self.assertNotEqual(
            updated_admin["adapter_version_id"], admin["adapter_version_id"],
        )
        member_profile = ProjectAuthProfile.objects(
            profile_id=member["profile_id"],
        ).first()
        self.assertEqual(
            member_profile.current_revision_id,
            member["profile_revision_id"],
        )

    def test_token_url_and_trusted_code_resolve_from_version_chain(self):
        token_ids = import_token_endpoint_as_profile(
            project_id=self.project_id,
            env_id=self.env_id,
            profile_name="已有 Token 服务",
            token_url="https://auth.example.test/token",
            response_path="data.token",
            account_key="token-owner",
            login_scene="owner-api",
            role_key="owner",
        )
        code_ids = import_code_as_profile(
            project_id=self.project_id,
            env_id=self.env_id,
            profile_name="SDK 登录",
            code_text=(
                "def get_auth(username, password):\n"
                "    return {'headers': {'Authorization': 'Bearer static'}, "
                "'expires_in': 300}\n"
            ),
            auth_origins=["https://auth.example.test"],
            account_key="partner",
            login_scene="partner-sdk",
            role_key="partner",
        )

        class Response:
            content = b'{"data":{"token":"from-existing-service"}}'
            text = content.decode()
            cookies = {}

            @staticmethod
            def raise_for_status():
                return None

            @staticmethod
            def json():
                return {"data": {"token": "from-existing-service"}}

        class Client:
            @staticmethod
            def request(_method, _url, **_kwargs):
                return Response()

        token_profile = ProjectAuthProfile.objects(
            profile_id=token_ids["profile_id"],
        ).first()
        token_fields = profile_context_fields(token_profile)
        token_reference = AccountContextRef(
            project_id=self.project_id,
            env_id=self.env_id,
            account_id=token_profile.account_key,
            provider_id=TOKEN_ENDPOINT_PROVIDER_ID,
            context_ref=token_fields["auth_context_ref"],
        )
        token_context = TokenEndpointProvider(
            session=Client(),
            material_loader=lambda reference: load_versioned_auth_material(
                reference, TOKEN_ENDPOINT_PROVIDER_ID,
            ),
        ).resolve(token_reference)
        self.assertEqual(
            token_context.headers["Authorization"],
            "Bearer from-existing-service",
        )
        self.assertEqual(
            verify_project_auth_profile(
                token_profile.profile_id, session=Client(),
            ).status,
            "succeeded",
        )

        code_profile = ProjectAuthProfile.objects(
            profile_id=code_ids["profile_id"],
        ).first()
        code_fields = profile_context_fields(code_profile)
        code_reference = AccountContextRef(
            project_id=self.project_id,
            env_id=self.env_id,
            account_id=code_profile.account_key,
            provider_id=USER_CODE_PROVIDER_ID,
            context_ref=code_fields["auth_context_ref"],
        )
        code_context = CodeAccountContextProvider(
            material_loader=lambda reference: load_versioned_auth_material(
                reference, USER_CODE_PROVIDER_ID,
            ),
        ).resolve(code_reference)
        self.assertEqual(code_context.headers["Authorization"], "Bearer static")
        self.assertEqual(
            verify_project_auth_profile(code_profile.profile_id).status,
            "succeeded",
        )


if __name__ == "__main__":
    unittest.main()
