import os
import re
import unittest
import uuid
import datetime as dt
from types import SimpleNamespace
from unittest.mock import patch

from bson import ObjectId
from flask import Flask

from apiAnalysis.db.collection import (
    ApiProject,
    AuthAdapter,
    AuthAdapterVersion,
    AuthProfileHealth,
    AuthRealm,
    AuthRealmRevision,
    AuthRealmSecretVersion,
    AuthRepairCandidate,
    AuthVerificationAttempt,
    CredentialVersion,
    ProjectAccountBinding,
    ProjectAuthProfile,
    ProjectAuthProfileRevision,
    ProjectEnvironment,
    ProjectRequestFixture,
    SsoAccount,
    TestAccount,
    parameter_priority_item,
    parameter_experience,
    parameter_relation,
    parameter_relation_analysis_run,
    parameter_validation_result,
    raw_data,
    request_sample,
    request_snapshot,
    req_data,
    res_data,
    security_execution_checkpoint,
    security_test_result,
    security_test_run,
)
from apiAnalysis.main import _ensure_mongo_connection
from apiAnalysis.model.model import PolicyEnum
from apiAnalysis.web import bp_web
from apiAnalysis.tool.interface_knowledge import DISCOVERY_VERSION, discover_project_relations
from apiAnalysis.tool.auth_recipe import AuthRecipeFailure, RecipeExecutionResult
from apiAnalysis.tool.parameter_analysis import (
    ParameterRelationAnalysisWorker,
    enqueue_relation_analysis,
)
from apiAnalysis.tool.parameter_relation_workbench import preprocess_relation
from apiAnalysis.tool.parameter_validation import (
    record_parameter_validation,
    select_ready_validation_batch,
)
from apiAnalysis.tool.project_auth import (
    create_profile_revision,
    profile_context_fields,
    rebind_zero_progress_auth_run,
)
from apiAnalysis.tool.request_fixture import save_request_fixture


@unittest.skipUnless(
    os.getenv("API_MANAGER_INTEGRATION_TESTS") == "1",
    "set API_MANAGER_INTEGRATION_TESTS=1 to use local MongoDB",
)
class ParameterP0WebIntegrationTests(unittest.TestCase):
    def setUp(self):
        _ensure_mongo_connection()
        suffix = uuid.uuid4().hex
        self.project_id = "parameter-p0-{}".format(suffix)
        self.path_base = 700000000 + int(suffix[:6], 16)
        self.project = ApiProject(project_id=self.project_id, name="Parameter P0 Test")
        self.project.save()
        self.account = SsoAccount(
            username="p0-{}".format(suffix), password="integration-test", describe="P0 test",
        )
        self.account.save()
        self.test_account = TestAccount(
            account_id="test-account-{}".format(suffix),
            username=self.account.username,
            display_name="P0 test",
            current_credential_version_id="credential-{}".format(suffix),
        )
        self.test_account.save()
        CredentialVersion(
            credential_version_id=self.test_account.current_credential_version_id,
            account_id=self.test_account.account_id,
            revision_no=1,
            secret_data={"username": self.account.username, "password": "integration-test"},
        ).save()
        self.auth_adapter_id = "p0-adapter-{}".format(suffix)
        self.auth_adapter_version_id = "p0-adapter-version-{}".format(suffix)
        recipe = {
            "schema_version": 1,
            "steps": [{
                "id": "login", "type": "http", "method": "POST",
                "url": "https://auth.p0.invalid/login",
                "json": {"account": "{{credential.username}}", "password": "{{credential.password}}"},
                "extract": {"access_token": {"source": "json", "path": "access_token"}},
            }],
            "output": {
                "auth_kind": "bearer",
                "headers": {"Authorization": "Bearer {{vars.access_token}}"},
                "expires_in_seconds": 300,
            },
        }
        AuthAdapter(
            adapter_id=self.auth_adapter_id, name="P0 adapter", adapter_type="recipe",
        ).save()
        AuthAdapterVersion(
            adapter_version_id=self.auth_adapter_version_id,
            adapter_id=self.auth_adapter_id,
            semver="1.0.0",
            recipe=recipe,
            allowed_auth_origins=["https://auth.p0.invalid"],
            artifact_sha256=suffix,
            lifecycle="active",
        ).save()
        self.realm_id = "p0-realm-{}".format(suffix)
        self.realm_revision_id = "p0-realm-revision-{}".format(suffix)
        AuthRealm(
            realm_id=self.realm_id, name="P0 realm", lifecycle="active",
            current_revision_id=self.realm_revision_id,
        ).save()
        AuthRealmRevision(
            realm_revision_id=self.realm_revision_id,
            realm_id=self.realm_id,
            revision_no=1,
            adapter_version_id=self.auth_adapter_version_id,
            auth_origins=["https://auth.p0.invalid"],
            config_sha256=suffix,
            lifecycle="active",
        ).save()
        self.environment = ProjectEnvironment(
            project_id=self.project_id,
            env_id="test",
            name="Test",
            environment_type="test",
            allow_mutation=True,
            auto_request_limit=3,
            default_host="p0.invalid",
            hosts=[{"host": "p0.invalid", "base_url": "https://p0.invalid"}],
        )
        self.environment.save()
        self.binding = ProjectAccountBinding(
            project_id=self.project_id,
            env_id="test",
            account_key="owner",
            account_id=self.test_account.account_id,
            account=self.account,
            display_name="Owner",
            is_test_account=True,
        )
        self.binding.save()
        self.profile = ProjectAuthProfile(
            profile_id="p0-profile-{}".format(suffix),
            project_id=self.project_id,
            env_id="test",
            account_key="owner",
            name="Owner mixed",
            provider_id="database_sso",
            context_ref="p0-profile-{}".format(suffix),
            auth_kind="mixed",
            allowed_hosts=["p0.invalid"],
            is_default=True,
        )
        self.profile.save()
        self.source = raw_data(
            _id=ObjectId(),
            project_id=self.project_id,
            source="integration",
            domain="p0.invalid",
            path="/source",
            ptah_id=self.path_base,
            method="GET",
            url="https://p0.invalid/source",
        )
        self.source.save()
        self.consumer = raw_data(
            _id=ObjectId(),
            project_id=self.project_id,
            source="integration",
            domain="p0.invalid",
            path="/consumer/{id}",
            ptah_id=self.path_base + 1,
            method="GET",
            url="https://p0.invalid/consumer/{id}",
        )
        self.consumer.save()
        res_data(
            raw_data=self.source,
            parameter="data.items[].id",
            position="body",
            canonical_name="id",
            schema_path="data.items[].id",
            display_path="data.items[].id",
            locator={
                "version": 1,
                "tokens": [
                    {"kind": "property", "value": "data"},
                    {"kind": "property", "value": "items"},
                    {"kind": "array", "index": 0, "wildcard": True},
                    {"kind": "property", "value": "id"},
                ],
            },
        ).save()
        req_data(
            raw_data=self.consumer,
            parameter="id",
            position="path",
            canonical_name="id",
            schema_path="id",
            display_path="id",
            locator={
                "version": 1,
                "tokens": [{"kind": "property", "value": "id"}],
            },
        ).save()
        self.relation = parameter_relation(
            parameter="id",
            source_parameter="data.items[].id",
            target_parameter="id",
            source_position="body",
            target_position="path",
            source_locator=res_data.objects(raw_data=self.source).first().locator,
            target_locator=req_data.objects(raw_data=self.consumer).first().locator,
            req_pathid=self.consumer.ptah_id,
            res_pathid=self.source.ptah_id,
            relation="source_to_consumer",
            project_id=self.project_id,
            env_id="test",
        )
        self.relation.save()

        app = Flask(
            __name__,
            template_folder=os.path.join(os.path.dirname(__file__), "..", "apiAnalysis", "templates"),
            static_folder=os.path.join(os.path.dirname(__file__), "..", "apiAnalysis", "static"),
        )
        app.secret_key = "test-parameter-p0-secret"
        app.register_blueprint(bp_web)
        app.config.update(TESTING=True)
        self.client = app.test_client()
        with self.client.session_transaction() as state:
            state["username"] = "integration-admin"
            state["role"] = [PolicyEnum.MANAGE.value, PolicyEnum.ACCESS.value]

    def tearDown(self):
        run_ids = list(security_test_run.objects(project_id=self.project_id).scalar("id"))
        if run_ids:
            security_execution_checkpoint.objects(run_id__in=run_ids).delete()
            security_test_result.objects(run_id__in=run_ids).delete()
            parameter_validation_result.objects(run_id__in=run_ids).delete()
        security_test_run.objects(project_id=self.project_id).delete()
        request_snapshot.objects(project_id=self.project_id).delete()
        request_sample.objects(project_id=self.project_id).delete()
        req_data.objects(raw_data__in=[self.source, self.consumer]).delete()
        res_data.objects(raw_data__in=[self.source, self.consumer]).delete()
        parameter_relation.objects(project_id=self.project_id).delete()
        parameter_relation_analysis_run.objects(project_id=self.project_id).delete()
        parameter_priority_item.objects(project_id=self.project_id).delete()
        parameter_experience.objects(project_id=self.project_id).delete()
        ProjectRequestFixture.objects(project_id=self.project_id).delete()
        raw_data.objects(project_id=self.project_id).delete()
        profile_ids = list(ProjectAuthProfile.objects(project_id=self.project_id).scalar("profile_id"))
        AuthRepairCandidate.objects(profile_id__in=profile_ids).delete()
        AuthVerificationAttempt.objects(profile_id__in=profile_ids).delete()
        ProjectAuthProfileRevision.objects(profile_id__in=profile_ids).delete()
        AuthProfileHealth.objects(profile_id__in=profile_ids).delete()
        ProjectAuthProfile.objects(project_id=self.project_id).delete()
        ProjectAccountBinding.objects(project_id=self.project_id).delete()
        ProjectEnvironment.objects(project_id=self.project_id).delete()
        AuthRealmSecretVersion.objects(realm_id=self.realm_id).delete()
        AuthRealmRevision.objects(realm_id=self.realm_id).delete()
        AuthRealm.objects(realm_id=self.realm_id).delete()
        AuthAdapterVersion.objects(adapter_id=self.auth_adapter_id).delete()
        AuthAdapter.objects(adapter_id=self.auth_adapter_id).delete()
        CredentialVersion.objects(account_id=self.test_account.account_id).delete()
        TestAccount.objects(account_id=self.test_account.account_id).delete()
        SsoAccount.objects(id=self.account.id).delete()
        ApiProject.objects(project_id=self.project_id).delete()

    def test_relation_page_explains_discovery_and_queued_validation_progress(self):
        run = security_test_run(
            name="parameter relation validation",
            project_id=self.project_id,
            env_id="test",
            account_id="owner",
            auth_mode="account",
            auth_provider_id="database_sso",
            auth_context_ref=self.profile.profile_id,
            adapter_id="parameter_relation_validation",
            adapter_version="1",
            plan_version="parameter-relation-v1",
            check_type="parameter_relation_validation",
            scope={
                "relation_ids": [str(self.relation.id)],
                "case_count": 1,
                "per_relation_request_budget": 3,
            },
            source="execution_scheduler",
            status=security_test_run.QUEUED,
            scheduler_managed=True,
            queue_name="snapshot",
            total_cases=1,
            pending_cases=1,
            queued_at=dt.datetime.utcnow(),
        ).save()
        security_execution_checkpoint(
            run_id=run.id,
            snapshot_id=ObjectId(),
            project_id=self.project_id,
            env_id="test",
            pathid=self.consumer.ptah_id,
            ordinal=0,
            status=security_execution_checkpoint.PENDING,
        ).save()
        self.relation.preprocess_status = "running"
        self.relation.last_validation_run_id = run.id
        self.relation.save()

        page = self.client.get("/parameter-relations", query_string={
            "project_id": self.project_id,
            "env_id": "test",
            "source_profile_id": self.profile.profile_id,
            "consumer_profile_id": self.profile.profile_id,
            "source_host": "p0.invalid",
            "consumer_host": "p0.invalid",
        })
        body = page.get_data(as_text=True)
        self.assertEqual(page.status_code, 200)
        self.assertIn("发现并分析（不发请求）", body)
        self.assertIn("等待后台执行", body)
        self.assertIn("1 个字段共用 1 个请求案例", body)
        self.assertIn("预算 ≤ 3 请求", body)
        self.assertIn("来源取值", body)
        self.assertIn("注入并消费", body)

        run.status = security_test_run.PAUSED
        run.auth_context_summary = {
            "error_type": "AccountContextUnavailable",
            "error_detail": "project account login failed (SSO_AUTH_HTTP_401)",
        }
        run.save()
        self.relation.preprocess_status = "needs_context"
        self.relation.save()
        paused_page = self.client.get("/parameter-relations", query_string={
            "project_id": self.project_id,
            "env_id": "test",
            "source_profile_id": self.profile.profile_id,
            "consumer_profile_id": self.profile.profile_id,
            "source_host": "p0.invalid",
            "consumer_host": "p0.invalid",
        })
        paused_body = paused_page.get_data(as_text=True)
        self.assertIn("认证服务返回 HTTP 401", paused_body)
        self.assertIn("先验证认证，再恢复这个原批次", paused_body)
        self.assertIn("先修复测试账号认证", paused_body)
        csrf = self._csrf(paused_body)
        response = self.client.post("/parameter-relations", data={
            "csrf_token": csrf,
            "action": "resume_validation_run",
            "run_id": str(run.id),
            "project_id": self.project_id,
            "env_id": "test",
            "source_profile_id": self.profile.profile_id,
            "consumer_profile_id": self.profile.profile_id,
            "source_host": "p0.invalid",
            "consumer_host": "p0.invalid",
        })
        self.assertEqual(response.status_code, 302)
        self.assertIn("/project-auth", response.headers["Location"])
        self.assertIn("resume_run_id={}".format(run.id), response.headers["Location"])

    def test_relation_page_explains_host_scope_failure_and_offers_bounded_retry(self):
        peer_relation = parameter_relation(
            parameter="id_alias",
            source_parameter="data.items[].id",
            target_parameter="id",
            source_position="body",
            target_position="path",
            source_locator=dict(self.relation.source_locator or {}),
            target_locator=dict(self.relation.target_locator or {}),
            req_pathid=self.consumer.ptah_id,
            res_pathid=self.source.ptah_id,
            relation="source_to_consumer",
            project_id=self.project_id,
            env_id="test",
        ).save()
        run = security_test_run(
            name="parameter relation host-scope approval",
            project_id=self.project_id,
            env_id="test",
            account_id="owner",
            auth_mode="account",
            auth_provider_id="database_sso",
            auth_context_ref=self.profile.profile_id,
            adapter_id="parameter_relation_validation",
            adapter_version="1",
            plan_version="parameter-relation-v1",
            check_type="parameter_relation_validation",
            scheduler_managed=True,
            status=security_test_run.DONE,
            scope={
                "relation_ids": [str(self.relation.id), str(peer_relation.id)],
                "case_count": 1,
                "estimated_requests": 3,
                "per_relation_request_budget": 3,
            },
            total_cases=1,
            completed_cases=1,
            queued_at=dt.datetime.utcnow(),
            finished_at=dt.datetime.utcnow(),
        ).save()
        security_execution_checkpoint(
            run_id=run.id,
            snapshot_id=ObjectId(),
            project_id=self.project_id,
            env_id="test",
            pathid=self.consumer.ptah_id,
            ordinal=0,
            status=security_execution_checkpoint.DONE,
            attempt_count=1,
            reason_codes=["parameter_validation_host_scope_approval_required"],
            outcome_summary={
                "status_code": 400,
                "ok": False,
                "request_count": 2,
            },
        ).save()
        for relation in (self.relation, peer_relation):
            parameter_validation_result(
                parameter=relation.parameter,
                relation=relation,
                project_id=self.project_id,
                env_id="test",
                run_id=run.id,
                case_key="{}:{}".format(run.id, relation.id),
                req_pathid=relation.req_pathid,
                res_pathid=relation.res_pathid,
                status="host_scope_approval_required",
                source_profile_id=self.profile.profile_id,
                consumer_profile_id=self.profile.profile_id,
                source_host="p0.invalid",
                consumer_host="p0.invalid",
                source_result={
                    "status_code": 400,
                    "attempts": [
                        {
                            "host": "p0.invalid",
                            "status_code": 400,
                            "ok": False,
                            "error_type": "",
                            "elapsed_ms": 12,
                        },
                        {
                            "host": "p1.invalid",
                            "status_code": 400,
                            "ok": False,
                            "error_type": "",
                            "elapsed_ms": 15,
                        },
                    ],
                    "request_count": 2,
                    "remaining_host_count": 1,
                    "approval_stage": "source",
                },
                consumer_result={
                    "status_code": None,
                    "attempts": [],
                    "request_count": 2,
                    "remaining_host_count": 1,
                    "approval_stage": "source",
                },
            ).save()
            relation.preprocess_status = "approval_required"
            relation.last_validation_run_id = run.id
            relation.save()

        page = self.client.get("/parameter-relations", query_string={
            "project_id": self.project_id,
            "env_id": "test",
            "source_profile_id": self.profile.profile_id,
            "consumer_profile_id": self.profile.profile_id,
            "source_host": "p0.invalid",
            "consumer_host": "p0.invalid",
        })
        body = page.get_data(as_text=True)
        self.assertEqual(page.status_code, 200)
        self.assertIn("等待扩大 Host 范围", body)
        self.assertIn("消费接口尚未发送", body)
        self.assertIn("HTTP 400", body)
        self.assertIn("确认扩大 Host，按 ≤4 请求重试原接口对", body)
        self.assertIn("另有 1 对需单独确认", body)
        self.assertNotIn("最近自动验证 · 验证完成", body)

    def test_relation_page_turns_request_rejection_into_safe_fixture_guidance(self):
        run = security_test_run(
            name="parameter request rejection",
            project_id=self.project_id,
            env_id="test",
            adapter_id="parameter_relation_validation",
            check_type="parameter_relation_validation",
            status=security_test_run.DONE,
            operator="integration-admin",
        ).save()
        plan_snapshot = request_snapshot(
            pathid=self.consumer.ptah_id,
            raw_data=self.consumer,
            source="parameter_relation_plan",
            project_id=self.project_id,
            env_id="test",
            method="GET",
            url="https://p0.invalid/consumer/{id}",
            path="/consumer/{id}",
            domain="p0.invalid",
            metadata={
                "validation_plan": {
                    "relation_id": str(self.relation.id),
                    "source_profile_id": self.profile.profile_id,
                    "consumer_profile_id": self.profile.profile_id,
                    "source_host": "p0.invalid",
                    "consumer_host": "p0.invalid",
                    "request_budget": 3,
                    "consumer_method": "GET",
                },
            },
        ).save()
        saved = record_parameter_validation(
            run,
            plan_snapshot,
            {
                "validation_status": "source_request_rejected",
                "source_status_code": 400,
                "consumer_status_code": None,
                "request_count": 1,
                "source_untried_host_count": 2,
                "source_attempts": [{
                    "host": "p0.invalid",
                    "status_code": 400,
                    "ok": False,
                    "elapsed_ms": 11,
                    "response_top_level_keys": ["code", "message", "errors"],
                    "error_code": "parameter/missing_required",
                    "error_fields": ["vpnid"],
                    "request_method": "GET",
                    "request_origin": "https://p0.invalid",
                    "request_path": "/source",
                    "request_query_names": ["tenant_id"],
                    "request_header_names": ["Authorization"],
                    "request_cookie_names": ["session"],
                    "request_auth_header_names": ["Authorization"],
                    "request_auth_cookie_names": ["session"],
                    "request_body_bytes": 0,
                    "request_timeout_seconds": 5,
                    "request_allow_redirects": False,
                    "request_tls_verify": True,
                    "auth_request_count": 3,
                }],
                "consumer_attempts": [],
                "source_error_summary": {
                    "response_json_type": "dict",
                    "response_top_level_keys": ["code", "message", "errors"],
                    "error_code": "parameter/missing_required",
                    "error_fields": ["vpnid"],
                },
                "raw_message": "account 998877 secret detail",
                "relation_results": [{
                    "relation_id": str(self.relation.id),
                    "canonical_name": "id",
                    "validation_status": "source_request_rejected",
                    "target_position": "path",
                }],
            },
            SimpleNamespace(id=ObjectId()),
            None,
        )
        self.assertNotIn("998877", str(saved.to_mongo().to_dict()))
        self.assertNotIn("secret detail", str(saved.to_mongo().to_dict()))
        self.relation.reload()
        self.assertEqual(self.relation.preprocess_status, "needs_data")
        self.assertEqual(saved.source_result["remaining_host_count"], 0)
        self.assertEqual(saved.source_result["untried_host_count"], 2)
        self.assertEqual(saved.source_result["approval_stage"], "")
        self.assertIn(
            "LATEST_REQUEST_DATA_REJECTED",
            self.relation.preprocess_reason_codes,
        )

        page = self.client.get("/parameter-relations", query_string={
            "project_id": self.project_id,
            "env_id": "test",
            "source_profile_id": self.profile.profile_id,
            "consumer_profile_id": self.profile.profile_id,
            "source_host": "p0.invalid",
            "consumer_host": "p0.invalid",
            "parameter": "id",
        })
        body = page.get_data(as_text=True)

        self.assertEqual(page.status_code, 200)
        self.assertIn("来源请求数据被业务校验拒绝", body)
        self.assertIn("系统已停止跨 Host", body)
        self.assertIn("另有 2 个授权 Host", body)
        self.assertIn("实发 GET https://p0.invalid/source", body)
        self.assertIn("Query 名称：tenant_id", body)
        self.assertIn("Header 名称：Authorization", body)
        self.assertIn("Cookie 名称：session", body)
        self.assertIn("TLS 校验开启", body)
        self.assertIn("跳转禁止", body)
        self.assertIn("认证前置请求 3 次", body)
        self.assertIn("parameter/missing_required", body)
        self.assertIn("vpnid", body)
        self.assertNotIn("998877", body)
        self.assertNotIn("secret detail", body)

    def test_explicit_source_blocker_skips_shared_source_until_fixture_changes(self):
        other_consumer = raw_data(
            _id=ObjectId(),
            project_id=self.project_id,
            source="integration",
            domain="p0.invalid",
            path="/other/{id}",
            ptah_id=self.path_base + 2,
            method="GET",
            url="https://p0.invalid/other/{id}",
        ).save()
        other_relation = parameter_relation(
            parameter="id",
            source_parameter="data.items[].id",
            target_parameter="id",
            source_position="body",
            target_position="path",
            source_locator=dict(self.relation.source_locator or {}),
            target_locator=dict(self.relation.target_locator or {}),
            req_pathid=other_consumer.ptah_id,
            res_pathid=self.source.ptah_id,
            relation="source_to_consumer",
            project_id=self.project_id,
            env_id="test",
            preprocess_status="auto_ready",
            location_status="resolved",
            machine_confidence=0.8,
        ).save()
        self.relation.preprocess_status = "auto_ready"
        self.relation.location_status = "resolved"
        self.relation.machine_confidence = 0.9
        self.relation.save()
        run = security_test_run(
            name="shared source blocker",
            project_id=self.project_id,
            env_id="test",
            adapter_id="parameter_relation_validation",
            check_type="parameter_relation_validation",
            status=security_test_run.DONE,
        ).save()
        parameter_validation_result(
            parameter=self.relation.parameter,
            relation=self.relation,
            project_id=self.project_id,
            env_id="test",
            run_id=run.id,
            case_key="shared-source-blocker:{}".format(self.relation.id),
            req_pathid=self.relation.req_pathid,
            res_pathid=self.relation.res_pathid,
            status="source_request_rejected",
            source_profile_id=self.profile.profile_id,
            consumer_profile_id=self.profile.profile_id,
            source_result={
                "status_code": 400,
                "request_count": 1,
                "error_summary": {
                    "error_code": "parameter/missing_required",
                    "error_fields": ["tenant_id"],
                    "explicit_business_rejection": True,
                },
                "attempts": [{
                    "host": "p0.invalid",
                    "status_code": 400,
                    "ok": False,
                    "explicit_business_rejection": True,
                }],
            },
            consumer_result={"request_count": 1, "attempts": []},
        ).save()

        blocked = select_ready_validation_batch(
            self.project_id,
            self.profile,
            self.profile,
            self.environment,
            total_request_budget=3,
        )
        self.assertEqual(blocked["pair_count"], 0)
        self.assertEqual(blocked["skipped_source_blocked_pair_count"], 2)

        save_request_fixture(
            self.project_id,
            "test",
            self.source.ptah_id,
            profile_id=self.profile.profile_id,
            query={"tenant_id": "qa"},
            operator="integration-admin",
        )
        recovered_view = preprocess_relation(
            self.relation,
            environment=self.environment,
            source_profile=self.profile,
            consumer_profile=self.profile,
            persist=True,
        )
        self.assertEqual(recovered_view["status"], "auto_ready")
        recovered = select_ready_validation_batch(
            self.project_id,
            self.profile,
            self.profile,
            self.environment,
            total_request_budget=3,
        )
        self.assertEqual(recovered["pair_count"], 1)
        self.assertEqual(recovered["skipped_source_blocked_pair_count"], 0)
        self.assertIn(
            recovered["pairs"][0]["pair_key"],
            {
                "{}:{}".format(self.source.ptah_id, self.consumer.ptah_id),
                "{}:{}".format(self.source.ptah_id, other_consumer.ptah_id),
            },
        )
        self.assertIsNotNone(other_relation.id)

    def test_relation_endpoint_detail_renders_traffic_values_with_credentials_redacted(self):
        request_sample(
            pathid=self.source.ptah_id,
            raw_data=self.source,
            sample_signature=uuid.uuid4().hex,
            source="har",
            project_id=self.project_id,
            method="GET",
            url="https://p0.invalid/source?department_id=42&access_token=secret-query",
            path="/source",
            domain="p0.invalid",
            query={"department_id": "42", "access_token": "secret-query"},
            headers={"Authorization": "Bearer secret-header", "X-Tenant": "qa"},
            body={"name": "测试部门", "password": "plain-test-password"},
            response_status_code=200,
            response_sample={"data": {"items": [{"id": 42, "name": "测试部门"}]}},
        ).save()

        page = self.client.get("/parameter-relations", query_string={
            "project_id": self.project_id,
            "env_id": "test",
            "source_profile_id": self.profile.profile_id,
            "consumer_profile_id": self.profile.profile_id,
            "source_host": "p0.invalid",
            "consumer_host": "p0.invalid",
            "parameter": "id",
        })
        body = page.get_data(as_text=True)
        self.assertEqual(page.status_code, 200)
        self.assertIn("HAR 流量", body)
        self.assertIn("department_id", body)
        self.assertIn("测试部门", body)
        self.assertIn("*** 已脱敏 ***", body)
        self.assertNotIn("secret-query", body)
        self.assertNotIn("secret-header", body)
        self.assertNotIn("plain-test-password", body)

    def test_incremental_discovery_preserves_confirmed_mapping_and_marks_schema_drift(self):
        for endpoint, path in ((self.source, "/devices"), (self.consumer, "/devices/{id}")):
            endpoint.source = "apifox"
            endpoint.asset_kind = "abstract"
            endpoint.path = path
            endpoint.source_meta = {
                "apifox_module_id": "devices", "apifox_folder_id": "devices-crud",
            }
            endpoint.save()
        self.relation.verified = True
        self.relation.manual_decision = "trusted"
        self.relation.source_parameter = "manual.payload.id"
        self.relation.source_locator = {"version": 2, "tokens": [{"kind": "property", "value": "manual"}]}
        self.relation.discovery_version = DISCOVERY_VERSION
        self.relation.discovery_source = "manual_override"
        self.relation.schema_fingerprint = "confirmed-before-import"
        self.relation.confirmed_schema_fingerprint = "confirmed-before-import"
        self.relation.save()

        summary = discover_project_relations(
            self.project_id, changed_pathids=[self.consumer.ptah_id],
        )
        self.relation.reload()

        self.assertTrue(summary["incremental"])
        self.assertGreater(summary["candidates"], 0)
        self.assertEqual(self.relation.source_parameter, "manual.payload.id")
        self.assertEqual(self.relation.discovery_source, "manual_override")
        self.assertEqual(self.relation.preprocess_status, "stale")
        self.assertEqual(self.relation.stale_reason, "schema_changed_after_confirmation")

        self.relation.manual_decision = "deleted"
        self.relation.discovery_source = "manual_tombstone"
        self.relation.preprocess_status = "deleted"
        self.relation.save()
        discover_project_relations(self.project_id, changed_pathids=[self.consumer.ptah_id])
        self.relation.reload()
        self.assertEqual(self.relation.manual_decision, "deleted")
        self.assertEqual(self.relation.discovery_source, "manual_tombstone")

    def test_user_can_override_and_delete_relation_without_machine_resurrection(self):
        page = self.client.get("/parameter-relations", query_string={
            "project_id": self.project_id, "env_id": "test",
            "source_profile_id": self.profile.profile_id,
            "consumer_profile_id": self.profile.profile_id,
            "source_host": "p0.invalid", "consumer_host": "p0.invalid",
            "size": 1,
        })
        csrf = self._csrf(page.get_data(as_text=True))
        common = {
            "csrf_token": csrf, "project_id": self.project_id, "env_id": "test",
            "source_profile_id": self.profile.profile_id,
            "consumer_profile_id": self.profile.profile_id,
            "source_host": "p0.invalid", "consumer_host": "p0.invalid",
            "relation_id": str(self.relation.id),
        }
        response = self.client.post("/parameter-relations", data=dict(common, **{
            "action": "save_mapping",
            "source_parameter": "data.items[].resource_id",
            "source_position": "body",
            "target_parameter": "resource_id",
            "target_position": "path",
            "manual_note": "人工确认字段重命名",
        }))
        self.assertEqual(response.status_code, 302)
        self.relation.reload()
        self.assertEqual(self.relation.source_parameter, "data.items[].resource_id")
        self.assertEqual(self.relation.discovery_source, "manual_override")
        self.assertEqual(self.relation.preprocess_status, "stale")

        response = self.client.post("/parameter-relations", data=dict(common, **{
            "action": "delete_relation", "confirm_delete": "yes",
        }))
        self.assertEqual(response.status_code, 302)
        self.relation.reload()
        self.assertEqual(self.relation.manual_decision, "deleted")
        self.assertEqual(self.relation.discovery_source, "manual_tombstone")

    def test_chain_page_projects_live_document_groups_instead_of_history_files(self):
        for endpoint, path in ((self.source, "/devices"), (self.consumer, "/devices/{id}")):
            endpoint.source = "apifox"
            endpoint.asset_kind = "abstract"
            endpoint.path = path
            endpoint.source_meta = {
                "apifox_module_id": "devices", "apifox_folder_id": "devices-crud",
            }
            endpoint.save()
        response = self.client.get("/interface-chains", query_string={
            "project_id": self.project_id,
        })
        body = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("当前项目的实时链路候选", body)
        self.assertIn("字段传递", body)
        self.assertIn("devices", body)
        self.assertNotIn("private-interface-chain", body)

    def test_parameter_asset_is_the_only_experience_merge_and_edit_surface(self):
        for parameter, role, weight in (
            ("id", "resource_identifier", 80),
            ("entity_id", "resource_identifier", 78),
        ):
            parameter_priority_item(
                project_id=self.project_id,
                parameter=parameter,
                canonical_key=parameter.replace("_", ""),
                rule_role=role,
                rule_weight=weight,
            ).save()

        merged = self.client.post("/parameter-priority", data={
            "action": "merge_experience",
            "project_id": self.project_id,
            "selected_params": "id||entity_id",
            "batch_group_key": "resource_id",
            "batch_business_meaning": "资源唯一标识",
        })
        self.assertEqual(merged.status_code, 302)
        experiences = list(parameter_experience.objects(
            project_id=self.project_id, group_key="resource_id",
        ))
        self.assertEqual({item.parameter for item in experiences}, {"id", "entity_id"})
        self.assertTrue(all(item.business_meaning == "资源唯一标识" for item in experiences))

        updated = self.client.post("/parameter-priority", data={
            "action": "quick_feedback",
            "project_id": self.project_id,
            "parameter": "id",
            "parameters": "id",
            "group_key": "resource_id",
            "process_status": "trusted",
            "manual_role": "resource_identifier",
            "scope_type": "path_prefix",
            "scope_value": "/enterprise/",
            "reuse_policy": "reusable",
            "chain_policy": "can_build_chain",
            "validation_policy": "verified",
            "confidence": "0.9",
            "business_meaning": "企业资源唯一标识",
            "manual_note": "人工确认接口文档和流量语义一致",
        })
        self.assertEqual(updated.status_code, 302)
        experience = parameter_experience.objects(
            project_id=self.project_id, parameter="id", group_key="resource_id",
        ).first()
        self.assertEqual(experience.process_status, "trusted")
        self.assertEqual(experience.scope_type, "path_prefix")
        self.assertEqual(experience.scope_value, "/enterprise/")
        self.assertEqual(experience.reuse_policy, "reusable")
        self.assertEqual(experience.chain_policy, "can_build_chain")
        self.assertEqual(experience.validation_policy, "verified")
        self.assertEqual(experience.confidence, 0.9)

    def _make_versioned_auth_profile(self):
        self.profile.provider_id = "auth_recipe"
        self.profile.auth_kind = "bearer"
        self.profile.refresh_strategy = "login"
        self.profile.allowed_hosts = ["p0.invalid"]
        self.profile.metadata = {"max_age_seconds": 300}
        self.profile.save()
        revision = create_profile_revision(
            self.profile,
            project_account_key="owner",
            realm_revision_id=self.realm_revision_id,
            auth_kind="bearer",
            allowed_business_origins=["https://p0.invalid"],
            max_age_seconds=300,
        )
        self.profile.current_revision_id = revision.profile_revision_id
        self.profile.context_ref = revision.profile_revision_id
        self.profile.save()
        AuthProfileHealth(
            profile_id=self.profile.profile_id,
            profile_revision_id=revision.profile_revision_id,
            status="failed",
            stage="login",
            error_code="CREDENTIAL_REJECTED",
        ).save()
        return revision

    @staticmethod
    def _csrf(body):
        match = re.search(r'name="csrf_token" value="([^"]+)"', body)
        if not match:
            raise AssertionError("csrf token missing")
        return match.group(1)

    def test_legacy_parameter_center_is_removed(self):
        page = self.client.get("/parameter-center")
        self.assertEqual(page.status_code, 404)

    def test_project_auth_page_can_add_an_independent_profile_without_login(self):
        page = self.client.get("/project-auth", query_string={
            "project_id": self.project_id, "env_id": "test",
        })
        self.assertEqual(page.status_code, 200)
        csrf = self._csrf(page.get_data(as_text=True))
        profile_id = ""
        response = self.client.post("/project-auth", data={
            "csrf_token": csrf,
            "action": "save_auth_profile",
            "project_id": self.project_id,
            "env_id": "test",
            "profile_id": profile_id,
            "account_key": "owner",
            "name": "Cookie only",
            "auth_kind": "cookie",
            "allowed_hosts": "p0.invalid",
            "realm_revision_id": self.realm_revision_id,
            "max_age_seconds": "900",
            "active": "1",
        })
        self.assertEqual(response.status_code, 302)
        created = ProjectAuthProfile.objects(
            project_id=self.project_id, env_id="test", name="Cookie only",
        ).first()
        self.assertIsNotNone(created)
        self.assertEqual(created.auth_kind, "cookie")
        self.assertEqual(created.allowed_hosts, ["p0.invalid"])
        self.assertEqual(created.provider_id, "auth_recipe")
        self.assertTrue(created.current_revision_id)
        self.assertIsNone(created.last_refresh_at)

    def test_failed_auth_repair_keeps_the_live_revision_unchanged(self):
        current = self._make_versioned_auth_profile()
        project_page = self.client.get("/project-auth", query_string={
            "project_id": self.project_id, "env_id": "test",
        })
        project_body = project_page.get_data(as_text=True)
        self.assertIn("高级认证 / 修复认证域", project_body)
        self.assertNotIn("Realm Client Token", project_body)
        page = self.client.get("/auth-realms/repair", query_string={
            "project_id": self.project_id,
            "env_id": "test",
            "profile_id": self.profile.profile_id,
        })
        self.assertEqual(page.status_code, 200)
        body = page.get_data(as_text=True)
        self.assertIn("认证工作台", body)
        self.assertIn("保存候选（0 请求）", body)
        self.assertIn("工作流编辑", body)
        self.assertIn("原始 Recipe", body)
        self.assertNotIn("蒲公英 SSO + 产品 Token", body)
        self.assertNotIn('name="realm_client_token"', body)
        csrf = self._csrf(body)
        failure = AuthRecipeFailure(
            "CREDENTIAL_REJECTED",
            "login",
            request_count=1,
            diagnostics=[{
                "stage": "login",
                "kind": "http",
                "origin": "https://auth2.p0.invalid",
                "path": "/login",
                "status_code": 401,
            }],
        )
        with patch(
                "apiAnalysis.tool.project_auth.AuthRecipeExecutor.execute",
                side_effect=failure):
            response = self.client.post("/auth-realms/repair", data={
                "csrf_token": csrf,
                "action": "create_validate_auth_repair",
                "project_id": self.project_id,
                "env_id": "test",
                "profile_id": self.profile.profile_id,
                "recipe_mode": "guided",
                "repair_auth_kind": "bearer",
                "login_url": "https://auth2.p0.invalid/login",
                "login_method": "POST",
                "request_format": "form",
                "username_field": "account",
                "password_field": "password",
                "password_transform": "md5",
                "token_source": "json",
                "token_path": "data.token",
                "token_header": "Authorization",
                "token_prefix": "Bearer",
                "success_statuses": "200",
                "extra_fields_json": '{"ismd5": 1}',
                "max_age_seconds": "300",
                "max_requests": "2",
                "tls_verify": "1",
            })
        self.assertEqual(response.status_code, 302)
        self.assertIn("/auth-realms/repair", response.headers["Location"])
        self.profile.reload()
        self.assertEqual(self.profile.current_revision_id, current.profile_revision_id)
        candidate = AuthRepairCandidate.objects(
            profile_id=self.profile.profile_id,
        ).order_by("-ctime").first()
        self.assertIsNotNone(candidate)
        self.assertEqual(candidate.status, AuthRepairCandidate.FAILED)
        self.assertNotEqual(
            candidate.candidate_profile_revision_id,
            current.profile_revision_id,
        )
        attempt = AuthVerificationAttempt.objects(
            repair_candidate_id=candidate.candidate_id,
        ).first()
        self.assertEqual(attempt.error_code, "CREDENTIAL_REJECTED")
        self.assertTrue(attempt.is_candidate)

    def test_auth_repair_candidate_can_be_saved_without_network(self):
        current = self._make_versioned_auth_profile()
        page = self.client.get("/auth-realms/repair", query_string={
            "project_id": self.project_id,
            "env_id": "test",
            "profile_id": self.profile.profile_id,
        })
        self.assertEqual(page.status_code, 200)
        csrf = self._csrf(page.get_data(as_text=True))
        with patch(
                "apiAnalysis.tool.project_auth.AuthRecipeExecutor.execute") as execute:
            response = self.client.post("/auth-realms/repair", data={
                "csrf_token": csrf,
                "action": "create_auth_repair_candidate",
                "project_id": self.project_id,
                "env_id": "test",
                "profile_id": self.profile.profile_id,
                "recipe_mode": "guided",
                "repair_auth_kind": "bearer",
                "login_url": "https://auth2.p0.invalid/login",
                "login_method": "POST",
                "request_format": "json",
                "username_field": "account",
                "password_field": "password",
                "password_transform": "plain",
                "token_source": "json",
                "token_path": "access_token",
                "token_header": "Authorization",
                "token_prefix": "Bearer",
                "success_statuses": "200",
                "extra_fields_json": "{}",
                "max_age_seconds": "300",
                "max_requests": "2",
                "repair_reason": "save only candidate",
                "tls_verify": "1",
            })
        self.assertEqual(response.status_code, 302)
        execute.assert_not_called()
        self.profile.reload()
        self.assertEqual(
            self.profile.current_revision_id,
            current.profile_revision_id,
        )
        candidate = AuthRepairCandidate.objects(
            profile_id=self.profile.profile_id,
        ).order_by("-ctime").first()
        self.assertIsNotNone(candidate)
        self.assertEqual(candidate.status, AuthRepairCandidate.DRAFT)
        self.assertEqual(candidate.reason, "save only candidate")
        self.assertEqual(
            AuthVerificationAttempt.objects(
                repair_candidate_id=candidate.candidate_id,
            ).count(),
            0,
        )


    def test_successful_auth_repair_rebinds_and_resumes_zero_progress_run(self):
        current = self._make_versioned_auth_profile()
        context = profile_context_fields(self.profile)
        plan_snapshot = request_snapshot(
            pathid=self.consumer.ptah_id,
            raw_data=self.consumer,
            source="parameter_relation_plan",
            project_id=self.project_id,
            env_id="test",
            account_id="owner",
            auth_mode="account",
            auth_provider_id=context["auth_provider_id"],
            auth_context_ref=context["auth_context_ref"],
            auth_profile_revision_id=context["auth_profile_revision_id"],
            auth_realm_revision_id=context["auth_realm_revision_id"],
            auth_adapter_version_id=context["auth_adapter_version_id"],
            adapter_id="parameter_relation_validation",
            adapter_version="1",
            method="GET",
            url="https://p0.invalid/consumer/1",
            path="/consumer/{id}",
            domain="p0.invalid",
            query={},
            headers={},
            cookies={},
            path_params={},
            content_type="application/json",
            metadata={"validation_plan": {
                "source_profile_id": self.profile.profile_id,
                "consumer_profile_id": self.profile.profile_id,
                "source_auth": context,
                "consumer_auth": context,
            }},
            template_key="repair-plan-{}".format(uuid.uuid4().hex),
        ).save()
        run = security_test_run(
            name="auth repair resume",
            profile_id=self.profile.profile_id,
            project_id=self.project_id,
            env_id="test",
            account_id="owner",
            auth_mode="account",
            auth_provider_id=context["auth_provider_id"],
            auth_context_ref=current.profile_revision_id,
            auth_profile_revision_id=current.profile_revision_id,
            auth_realm_revision_id=context["auth_realm_revision_id"],
            auth_adapter_version_id=context["auth_adapter_version_id"],
            adapter_id="parameter_relation_validation",
            adapter_version="1",
            check_type="parameter_relation_validation",
            queue_name="test-auth-repair-{}".format(uuid.uuid4().hex),
            scope={
                "source_profile_id": self.profile.profile_id,
                "consumer_profile_id": self.profile.profile_id,
            },
            status=security_test_run.PAUSED,
            scheduler_managed=True,
            snapshot_ids=[plan_snapshot.id],
            total_cases=1,
            pending_cases=1,
            pause_code="auth_unavailable",
            dependency_type="auth_profile",
            dependency_id=current.profile_revision_id,
            dependency_revision_id=current.profile_revision_id,
        ).save()
        security_execution_checkpoint(
            run_id=run.id,
            snapshot_id=plan_snapshot.id,
            project_id=self.project_id,
            env_id="test",
            pathid=self.consumer.ptah_id,
            ordinal=0,
            status=security_execution_checkpoint.PENDING,
        ).save()
        page = self.client.get("/auth-realms/repair", query_string={
            "project_id": self.project_id,
            "env_id": "test",
            "profile_id": self.profile.profile_id,
            "resume_run_id": str(run.id),
        })
        csrf = self._csrf(page.get_data(as_text=True))
        result = RecipeExecutionResult(
            headers={"Authorization": "Bearer in-memory-only"},
            auth_kind="bearer",
            request_count=1,
        )
        with patch(
                "apiAnalysis.tool.project_auth.AuthRecipeExecutor.execute",
                return_value=result):
            response = self.client.post("/auth-realms/repair", data={
                "csrf_token": csrf,
                "action": "create_validate_auth_repair",
                "project_id": self.project_id,
                "env_id": "test",
                "profile_id": self.profile.profile_id,
                "recipe_mode": "guided",
                "repair_auth_kind": "bearer",
                "login_url": "https://auth2.p0.invalid/login",
                "login_method": "POST",
                "request_format": "json",
                "username_field": "account",
                "password_field": "password",
                "password_transform": "plain",
                "token_source": "json",
                "token_path": "access_token",
                "token_header": "Authorization",
                "token_prefix": "Bearer",
                "success_statuses": "200",
                "extra_fields_json": "{}",
                "max_age_seconds": "300",
                "max_requests": "2",
                "tls_verify": "1",
                "resume_run_id": str(run.id),
            })
        self.assertEqual(response.status_code, 302)
        self.profile.reload()
        self.assertNotEqual(
            self.profile.current_revision_id,
            current.profile_revision_id,
        )
        candidate = AuthRepairCandidate.objects(
            profile_id=self.profile.profile_id,
            status=AuthRepairCandidate.ACTIVATED,
        ).order_by("-ctime").first()
        self.assertIsNotNone(candidate)
        run.reload()
        self.assertEqual(run.status, security_test_run.QUEUED)
        self.assertEqual(
            run.auth_profile_revision_id,
            candidate.candidate_profile_revision_id,
        )
        self.assertNotEqual(run.snapshot_ids, [plan_snapshot.id])
        checkpoint = security_execution_checkpoint.objects(run_id=run.id).first()
        self.assertEqual(checkpoint.snapshot_id, run.snapshot_ids[0])
        rebound_snapshot = request_snapshot.objects(id=run.snapshot_ids[0]).first()
        rebound_plan = rebound_snapshot.metadata["validation_plan"]
        self.assertEqual(
            rebound_plan["source_auth"]["auth_profile_revision_id"],
            candidate.candidate_profile_revision_id,
        )
        self.assertEqual(
            rebound_plan["consumer_auth"]["auth_profile_revision_id"],
            candidate.candidate_profile_revision_id,
        )
        self.assertEqual(
            request_snapshot.objects(id=plan_snapshot.id).first().auth_profile_revision_id,
            current.profile_revision_id,
        )
        self.assertEqual(security_test_result.objects(run_id=run.id).count(), 0)

        progressed = security_test_run(
            name="auth repair must not rewrite progress",
            profile_id=self.profile.profile_id,
            project_id=self.project_id,
            env_id="test",
            account_id="owner",
            auth_mode="account",
            auth_provider_id="auth_recipe",
            auth_context_ref=current.profile_revision_id,
            auth_profile_revision_id=current.profile_revision_id,
            auth_realm_revision_id=context["auth_realm_revision_id"],
            auth_adapter_version_id=context["auth_adapter_version_id"],
            adapter_id="parameter_relation_validation",
            adapter_version="1",
            check_type="parameter_relation_validation",
            queue_name="test-auth-repair-{}".format(uuid.uuid4().hex),
            status=security_test_run.PAUSED,
            scheduler_managed=True,
            snapshot_ids=[plan_snapshot.id],
            total_cases=1,
            completed_cases=1,
            pause_code="auth_unavailable",
            dependency_type="auth_profile",
            dependency_id=current.profile_revision_id,
            dependency_revision_id=current.profile_revision_id,
        ).save()
        with self.assertRaisesRegex(ValueError, "execution progress"):
            rebind_zero_progress_auth_run(progressed.id, candidate.candidate_id)

    def test_relation_workbench_renders_readable_mapping_and_schedules_selected_host(self):
        page = self.client.get("/parameter-relations", query_string={
            "project_id": self.project_id,
            "env_id": "test",
            "source_profile_id": self.profile.profile_id,
            "consumer_profile_id": self.profile.profile_id,
            "source_host": "p0.invalid",
            "consumer_host": "p0.invalid",
            "parameter": "id",
        })
        self.assertEqual(page.status_code, 200)
        body = page.get_data(as_text=True)
        self.assertIn("关系验证", body)
        self.assertIn("保持原始类型", body)
        self.assertIn("data.items[].id", body)
        csrf = self._csrf(body)
        fake_run = SimpleNamespace(id="0123456789abcdef01234567")
        with patch("apiAnalysis.web.views_parameter_workbench.schedule_validation_batch", return_value=(fake_run, True)) as schedule:
            response = self.client.post("/parameter-relations", data={
                "csrf_token": csrf,
                "action": "validate_relation",
                "project_id": self.project_id,
                "env_id": "test",
                "source_profile_id": self.profile.profile_id,
                "consumer_profile_id": self.profile.profile_id,
                "source_host": "p0.invalid",
                "consumer_host": "p0.invalid",
                "row_source_host": "p0.invalid",
                "row_consumer_host": "p0.invalid",
                "relation_id": str(self.relation.id),
                "parameter": "id",
                "size": "20",
            })
        self.assertEqual(response.status_code, 302)
        self.assertEqual(schedule.call_count, 1)
        scheduled_relation = schedule.call_args.args[0][0]
        self.assertEqual(scheduled_relation.selected_source_host, "p0.invalid")
        self.assertEqual(scheduled_relation.selected_consumer_host, "p0.invalid")
        self.assertFalse(schedule.call_args.kwargs["approved_large_run"])

    def test_relation_workbench_enqueues_full_local_analysis_instead_of_blocking_request(self):
        page = self.client.get("/parameter-relations", query_string={
            "project_id": self.project_id,
            "env_id": "test",
            "source_profile_id": self.profile.profile_id,
            "consumer_profile_id": self.profile.profile_id,
            "source_host": "p0.invalid",
            "consumer_host": "p0.invalid",
        })
        body = page.get_data(as_text=True)
        self.assertIn("后台全量发现与分析", body)
        csrf = self._csrf(body)
        fake_run = SimpleNamespace(id=ObjectId())
        with patch(
            "apiAnalysis.web.views_parameter_workbench.enqueue_relation_analysis",
            return_value=(fake_run, True),
        ) as enqueue:
            response = self.client.post("/parameter-relations", data={
                "csrf_token": csrf,
                "action": "preprocess_project",
                "project_id": self.project_id,
                "env_id": "test",
                "source_profile_id": self.profile.profile_id,
                "consumer_profile_id": self.profile.profile_id,
                "source_host": "p0.invalid",
                "consumer_host": "p0.invalid",
            })
        self.assertEqual(response.status_code, 302)
        self.assertEqual(enqueue.call_count, 1)
        self.assertIn(
            "不发送业务请求",
            self.client.get(response.headers["Location"]).get_data(as_text=True),
        )

    def test_durable_local_analysis_worker_records_progress_without_http_execution(self):
        run, created = enqueue_relation_analysis(
            self.project_id,
            env_id="test",
            source_profile_id=self.profile.profile_id,
            consumer_profile_id=self.profile.profile_id,
            operator="integration-admin",
        )
        self.assertTrue(created)
        worker = ParameterRelationAnalysisWorker(
            worker_id="integration-analysis",
            poll_seconds=0.2,
            lease_seconds=30,
        )
        analysis = SimpleNamespace(
            env_id="test", profile_revision_id=self.profile.current_revision_id,
            rule_bundle_sha256="a" * 64, input_watermark_sha256="b" * 64,
            summary={
                "projection": {}, "relation_projection": {"status": "complete"},
                "output_counts": {"ParameterRoleCandidate": 1},
                "legacy_diff": {"classification_adapter_parity": 2},
            },
        )
        with patch(
            "apiAnalysis.tool.parameter_analysis.analyze_project",
            return_value=analysis,
        ), patch(
            "apiAnalysis.tool.parameter_analysis.persist_typed_outputs",
            return_value={"relation_created": 0, "relation_protected": 1, "finding_writes": 0},
        ), patch(
            "apiAnalysis.tool.parameter_analysis.create_non_executable_plan_drafts",
            return_value={"draft_created": 1, "execution_runs_created": 0},
        ):
            result = worker.run_once()
        self.assertEqual(result, "done")
        run.reload()
        self.assertEqual(run.status, parameter_relation_analysis_run.STATUS_DONE)
        self.assertEqual(run.processed_relations, 1)
        self.assertEqual(run.status_counts.get("candidate_unverified"), 0)
        self.assertEqual(run.analysis_version, "unified-offline-rules.p1.v1")
        self.assertEqual(run.rule_bundle_sha256, "a" * 64)
        self.assertEqual(run.result_summary.get("business_network_requests"), 0)
        self.assertEqual(run.result_summary.get("finding_writes"), 0)

    def test_relation_workbench_batch_requires_explicit_large_budget_approval(self):
        self.relation.preprocess_status = "auto_ready"
        self.relation.location_status = "resolved"
        self.relation.save()
        page = self.client.get("/parameter-relations", query_string={
            "project_id": self.project_id,
            "env_id": "test",
            "source_profile_id": self.profile.profile_id,
            "consumer_profile_id": self.profile.profile_id,
            "source_host": "p0.invalid",
            "consumer_host": "p0.invalid",
        })
        body = page.get_data(as_text=True)
        self.assertIn("预览将执行的接口对", body)
        csrf = self._csrf(body)
        with patch(
            "apiAnalysis.web.views_parameter_workbench.schedule_validation_batch",
        ) as schedule:
            response = self.client.post("/parameter-relations", data={
                "csrf_token": csrf,
                "action": "validate_ready_batch",
                "project_id": self.project_id,
                "env_id": "test",
                "source_profile_id": self.profile.profile_id,
                "consumer_profile_id": self.profile.profile_id,
                "source_host": "p0.invalid",
                "consumer_host": "p0.invalid",
                "total_request_budget": "30",
                "confirm_preview": "1",
            })
        schedule.assert_not_called()
        failed_body = self.client.get(response.headers["Location"]).get_data(as_text=True)
        self.assertIn("未执行", failed_body)
        self.assertIn("超过自动预算 3", failed_body)

    def test_relation_workbench_schedules_bounded_ready_batch(self):
        self.relation.preprocess_status = "auto_ready"
        self.relation.location_status = "resolved"
        self.relation.save()
        page = self.client.get("/parameter-relations", query_string={
            "project_id": self.project_id,
            "env_id": "test",
            "source_profile_id": self.profile.profile_id,
            "consumer_profile_id": self.profile.profile_id,
            "source_host": "p0.invalid",
            "consumer_host": "p0.invalid",
        })
        csrf = self._csrf(page.get_data(as_text=True))
        selection = {
            "relations": [self.relation],
            "pairs": [{
                "pair_key": "{}:{}".format(
                    self.relation.res_pathid,
                    self.relation.req_pathid,
                ),
            }],
            "pair_count": 1,
            "field_count": 1,
            "read_pair_count": 1,
            "mutation_pair_count": 0,
            "reserved_requests": 3,
            "per_case_request_budget": 3,
        }
        fake_run = SimpleNamespace(id=ObjectId())
        with patch(
            "apiAnalysis.web.views_parameter_workbench.select_ready_validation_batch",
            return_value=selection,
        ) as select, patch(
            "apiAnalysis.web.views_parameter_workbench.schedule_validation_batch",
            return_value=(fake_run, True),
        ) as schedule:
            response = self.client.post("/parameter-relations", data={
                "csrf_token": csrf,
                "action": "validate_ready_batch",
                "project_id": self.project_id,
                "env_id": "test",
                "source_profile_id": self.profile.profile_id,
                "consumer_profile_id": self.profile.profile_id,
                "source_host": "p0.invalid",
                "consumer_host": "p0.invalid",
                "total_request_budget": "3",
                "confirm_preview": "1",
                "preview_pair_keys": "{}:{}".format(
                    self.relation.res_pathid,
                    self.relation.req_pathid,
                ),
            })
        self.assertEqual(response.status_code, 302)
        self.assertEqual(select.call_count, 1)
        self.assertEqual(schedule.call_count, 1)
        self.assertEqual(schedule.call_args.kwargs["per_relation_request_budget"], 3)
        self.assertFalse(schedule.call_args.kwargs["approved_large_run"])

    def test_relation_workbench_previews_exact_pair_without_creating_run(self):
        self.relation.preprocess_status = "auto_ready"
        self.relation.location_status = "resolved"
        self.relation.machine_confidence = 0.91
        self.relation.save()
        run_count = security_test_run.objects(project_id=self.project_id).count()

        response = self.client.get("/parameter-relations", query_string={
            "project_id": self.project_id,
            "env_id": "test",
            "source_profile_id": self.profile.profile_id,
            "consumer_profile_id": self.profile.profile_id,
            "source_host": "p0.invalid",
            "consumer_host": "p0.invalid",
            "preview_batch": "1",
            "total_request_budget": "3",
        })
        body = response.get_data(as_text=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn("执行前预览：1 个接口对", body)
        self.assertRegex(body, r"<strong>GET</strong>\s*/source")
        self.assertRegex(body, r"<strong>GET</strong>\s*/consumer/\{id\}")
        self.assertIn("p0.invalid", body)
        self.assertIn(
            'name="preview_pair_keys" value="{}:{}"'.format(
                self.relation.res_pathid,
                self.relation.req_pathid,
            ),
            body,
        )
        self.assertEqual(
            security_test_run.objects(project_id=self.project_id).count(),
            run_count,
        )

    def test_relation_workbench_rejects_confirmation_when_preview_scope_changed(self):
        self.relation.preprocess_status = "auto_ready"
        self.relation.location_status = "resolved"
        self.relation.save()
        page = self.client.get("/parameter-relations", query_string={
            "project_id": self.project_id,
            "env_id": "test",
            "source_profile_id": self.profile.profile_id,
            "consumer_profile_id": self.profile.profile_id,
            "source_host": "p0.invalid",
            "consumer_host": "p0.invalid",
        })
        csrf = self._csrf(page.get_data(as_text=True))
        selection = {
            "relations": [self.relation],
            "pairs": [{
                "pair_key": "{}:{}".format(
                    self.relation.res_pathid,
                    self.relation.req_pathid,
                ),
            }],
        }
        with patch(
            "apiAnalysis.web.views_parameter_workbench.select_ready_validation_batch",
            return_value=selection,
        ), patch(
            "apiAnalysis.web.views_parameter_workbench.schedule_validation_batch",
        ) as schedule:
            response = self.client.post("/parameter-relations", data={
                "csrf_token": csrf,
                "action": "validate_ready_batch",
                "project_id": self.project_id,
                "env_id": "test",
                "source_profile_id": self.profile.profile_id,
                "consumer_profile_id": self.profile.profile_id,
                "source_host": "p0.invalid",
                "consumer_host": "p0.invalid",
                "total_request_budget": "3",
                "confirm_preview": "1",
                "preview_pair_keys": "outdated:scope",
            })

        schedule.assert_not_called()
        failed_body = self.client.get(
            response.headers["Location"],
        ).get_data(as_text=True)
        self.assertIn("可执行关系范围已发生变化", failed_body)
        self.assertIn("重新预览", failed_body)

    def test_relation_workbench_saves_fixture_and_schedules_all_pair_mappings(self):
        res_data(
            raw_data=self.source,
            parameter="data.items[].tenant_id",
            position="body",
            canonical_name="tenant_id",
            schema_path="data.items[].tenant_id",
            display_path="data.items[].tenant_id",
            locator={
                "version": 1,
                "tokens": [
                    {"kind": "property", "value": "data"},
                    {"kind": "property", "value": "items"},
                    {"kind": "array", "index": 0, "wildcard": True},
                    {"kind": "property", "value": "tenant_id"},
                ],
            },
        ).save()
        tenant_input = req_data(
            raw_data=self.consumer,
            parameter="tenant_id",
            position="query",
            canonical_name="tenant_id",
            schema_path="tenant_id",
            display_path="tenant_id",
            required=True,
            locator={
                "version": 1,
                "tokens": [{"kind": "property", "value": "tenant_id"}],
            },
        )
        tenant_input.save()
        required_name = req_data(
            raw_data=self.consumer,
            parameter="name",
            position="body",
            canonical_name="name",
            schema_path="name",
            display_path="name",
            required=True,
            type="string",
            locator={
                "version": 1,
                "tokens": [{"kind": "property", "value": "name"}],
            },
        )
        required_name.save()
        tenant_relation = parameter_relation(
            parameter="tenant_id",
            source_parameter="data.items[].tenant_id",
            target_parameter="tenant_id",
            source_position="body",
            target_position="query",
            source_locator=res_data.objects(
                raw_data=self.source, canonical_name="tenant_id",
            ).first().locator,
            target_locator=tenant_input.locator,
            req_pathid=self.consumer.ptah_id,
            res_pathid=self.source.ptah_id,
            relation="source_to_consumer",
            project_id=self.project_id,
            env_id="test",
        )
        tenant_relation.save()

        page = self.client.get("/parameter-relations", query_string={
            "project_id": self.project_id,
            "env_id": "test",
            "source_profile_id": self.profile.profile_id,
            "consumer_profile_id": self.profile.profile_id,
            "source_host": "p0.invalid",
            "consumer_host": "p0.invalid",
            "parameter": "id",
        })
        self.assertEqual(page.status_code, 200)
        body = page.get_data(as_text=True)
        self.assertIn("一次验证 2 个字段", body)
        self.assertIn("补充非关联业务数据", body)
        self.assertIn("body · name", body)
        csrf = self._csrf(body)

        with patch("apiAnalysis.web.views_parameter_workbench.schedule_validation_batch") as blocked_schedule:
            blocked = self.client.post("/parameter-relations", data={
                "csrf_token": csrf,
                "action": "validate_relation",
                "project_id": self.project_id,
                "env_id": "test",
                "source_profile_id": self.profile.profile_id,
                "consumer_profile_id": self.profile.profile_id,
                "source_host": "p0.invalid",
                "consumer_host": "p0.invalid",
                "row_source_host": "p0.invalid",
                "row_consumer_host": "p0.invalid",
                "relation_id": str(self.relation.id),
                "parameter": "id",
            })
        self.assertEqual(blocked.status_code, 302)
        blocked_schedule.assert_not_called()

        response = self.client.post("/parameter-relations", data={
            "csrf_token": csrf,
            "action": "save_fixture",
            "fixture_side": "consumer",
            "project_id": self.project_id,
            "env_id": "test",
            "source_profile_id": self.profile.profile_id,
            "consumer_profile_id": self.profile.profile_id,
            "source_host": "p0.invalid",
            "consumer_host": "p0.invalid",
            "relation_id": str(self.relation.id),
            "parameter": "id",
            "fixture_query_json": "{}",
            "fixture_headers_json": "{}",
            "fixture_path_json": "{}",
            "fixture_body_json": '{"name": "可执行测试数据"}',
            "fixture_note": "补齐与关系无关的必填字段",
        })
        self.assertEqual(response.status_code, 302)
        fixture = ProjectRequestFixture.objects(
            project_id=self.project_id,
            env_id="test",
            pathid=self.consumer.ptah_id,
            profile_id=self.profile.profile_id,
        ).first()
        self.assertIsNotNone(fixture)
        self.assertEqual(fixture.body, {"name": "可执行测试数据"})

        ready_page = self.client.get("/parameter-relations", query_string={
            "project_id": self.project_id,
            "env_id": "test",
            "source_profile_id": self.profile.profile_id,
            "consumer_profile_id": self.profile.profile_id,
            "source_host": "p0.invalid",
            "consumer_host": "p0.invalid",
            "parameter": "id",
        })
        ready_body = ready_page.get_data(as_text=True)
        self.assertIn("必填已就绪", ready_body)
        csrf = self._csrf(ready_body)
        fake_run = SimpleNamespace(
            id="0123456789abcdef01234567",
            scope={"per_relation_request_budget": 3, "estimated_requests": 2},
        )
        with patch("apiAnalysis.web.views_parameter_workbench.schedule_validation_batch", return_value=(fake_run, True)) as schedule:
            response = self.client.post("/parameter-relations", data={
                "csrf_token": csrf,
                "action": "validate_relation",
                "project_id": self.project_id,
                "env_id": "test",
                "source_profile_id": self.profile.profile_id,
                "consumer_profile_id": self.profile.profile_id,
                "source_host": "p0.invalid",
                "consumer_host": "p0.invalid",
                "row_source_host": "p0.invalid",
                "row_consumer_host": "p0.invalid",
                "relation_id": str(self.relation.id),
                "parameter": "id",
                "size": "20",
            })
        self.assertEqual(response.status_code, 302)
        self.assertEqual(schedule.call_count, 1)
        scheduled_relations = schedule.call_args.args[0]
        self.assertEqual(
            {item.parameter for item in scheduled_relations},
            {"id", "tenant_id"},
        )

    def test_project_auth_environment_persists_mutation_policy(self):
        page = self.client.get("/project-auth", query_string={
            "project_id": self.project_id, "env_id": "test",
        })
        csrf = self._csrf(page.get_data(as_text=True))
        response = self.client.post("/project-auth", data={
            "csrf_token": csrf,
            "action": "save_environment",
            "project_id": self.project_id,
            "env_id": "test",
            "name": "Test",
            "environment_type": "preprod",
            "allow_mutation": "1",
            "auto_request_limit": "80",
            "default_host": "p0.invalid",
            "hosts": "p0.invalid",
        })
        self.assertEqual(response.status_code, 302)
        self.environment.reload()
        self.assertEqual(self.environment.environment_type, "preprod")
        self.assertTrue(self.environment.allow_mutation)
        self.assertEqual(self.environment.auto_request_limit, 80)

        response = self.client.post("/project-auth", data={
            "csrf_token": csrf,
            "action": "save_environment",
            "project_id": self.project_id,
            "env_id": "test",
            "name": "Formal",
            "environment_type": "production",
            "allow_mutation": "0",
            "auto_request_limit": "99",
            "default_host": "p0.invalid",
            "hosts": "p0.invalid",
        })
        self.assertEqual(response.status_code, 302)
        self.environment.reload()
        self.assertEqual(self.environment.auto_request_limit, 3)

    def test_priority_refresh_normalizes_paths_and_aliases_before_scoring(self):
        res_data(
            raw_data=self.source,
            parameter="credits[].user_id",
            position="body",
            canonical_name="user_id",
            schema_path="credits[].user_id",
            display_path="credits[].user_id",
            locator={"version": 1, "tokens": [{"kind": "property", "value": "user_id"}]},
        ).save()
        req_data(
            raw_data=self.consumer,
            parameter="userid",
            position="query",
            canonical_name="userid",
            schema_path="userid",
            display_path="userid",
            locator={"version": 1, "tokens": [{"kind": "property", "value": "userid"}]},
        ).save()
        req_data(
            raw_data=self.consumer,
            parameter="user_id",
            position="header",
            canonical_name="user_id",
            schema_path="user_id",
            display_path="user_id",
            locator={"version": 1, "tokens": [{"kind": "property", "value": "user_id"}]},
        ).save()
        res_data(
            raw_data=self.source,
            parameter="cts[].count",
            position="body",
            canonical_name="count",
            schema_path="cts[].count",
            display_path="cts[].count",
            locator={"version": 1, "tokens": [{"kind": "property", "value": "count"}]},
        ).save()
        request_sample(
            pathid=self.source.ptah_id,
            raw_data=self.source,
            sample_signature=uuid.uuid4().hex,
            source="har",
            project_id=self.project_id,
            method="GET",
            url="https://p0.invalid/source",
            path="/source",
            domain="p0.invalid",
            hit_count=25,
        ).save()

        response = self.client.post("/parameter-priority", data={
            "action": "refresh",
            "project_id": self.project_id,
        })
        self.assertEqual(response.status_code, 302)
        rows = list(parameter_priority_item.objects(
            project_id=self.project_id, canonical_key="userid",
        ))
        self.assertEqual(len(rows), 1)
        item = rows[0]
        self.assertEqual(item.parameter, "user_id")
        self.assertEqual(item.doc_count, 3)
        self.assertEqual(set(item.aliases), {"userid"})
        self.assertGreaterEqual(item.usage_count, 25)
        self.assertGreater(item.usage_score, 0)
        self.assertGreater(item.composite_score, 0)
        self.assertEqual(
            set(item.raw_paths),
            {"credits[].user_id", "userid", "user_id"},
        )
        self.assertFalse(parameter_priority_item.objects(
            project_id=self.project_id, parameter="credits[].user_id",
        ).first())
        count_item = parameter_priority_item.objects(
            project_id=self.project_id, canonical_key="count",
        ).first()
        self.assertIsNotNone(count_item)
        self.assertEqual(count_item.parameter, "count")
        self.assertEqual(count_item.rule_role, "pagination_filter")
        self.assertLess(count_item.rule_weight, 80)

        page = self.client.get("/parameter-priority", query_string={
            "project_id": self.project_id,
            "q": "credits[].user_id",
        })
        body = page.get_data(as_text=True)
        self.assertEqual(page.status_code, 200)
        self.assertIn("已规范归并 3 个字段路径", body)
        self.assertIn("证据与接口数据（按需加载）", body)
        self.assertIn("真实请求命中", body)
        filtered = self.client.get("/parameter-priority", query_string={
            "project_id": self.project_id,
            "usage": "observed",
            "sort": "usage",
        })
        self.assertEqual(filtered.status_code, 200)
        self.assertIn("使用频率", filtered.get_data(as_text=True))
        evidence = self.client.get("/parameter-evidence", query_string={
            "project_id": self.project_id,
            "parameter": "user_id",
        })
        self.assertEqual(evidence.status_code, 200)
        self.assertIn("规范键 userid", evidence.get_data(as_text=True))


if __name__ == "__main__":
    unittest.main()
