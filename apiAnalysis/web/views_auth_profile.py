"""Project auth profile and realm repair routes."""
import json
import datetime as dt
import logging
from urllib.parse import urlsplit

from bson import ObjectId
from mongoengine.errors import NotUniqueError
from flask import request, make_response, redirect, url_for, session

from . import bp_web
from ._helpers import (
    _bounded_int,
    _canonical_project_id,
    _lifecycle_csrf_token,
    _lifecycle_csrf_valid,
    _available_projects,
)
from ..common.decorators import login_check, templated
from ..common.func import is_manager
from ..conf.conf import *
from ..db.collection import *
from ..tool.project_auth import (
    AUTH_KINDS,
    AUTH_RECIPE_PROVIDER_ID,
    DATABASE_SSO_PROVIDER_ID,
    auth_repair_defaults,
    build_password_login_recipe,
    build_sso_product_token_recipe,
    create_profile_revision,
    create_auth_repair_candidate,
    environment_business_origins,
    environment_host_names,
    normalize_host,
    RecipeAccountContextProvider,
    recipe_secret_names,
    realm_secret_key_names,
    rebind_zero_progress_auth_run,
    register_auth_repair_candidate,
    validate_repair_recipe,
    verify_and_activate_auth_repair_candidate,
    verify_project_auth_profile,
)
from ..tool.account_context import (
    AccountContextInvalid,
    AccountContextUnavailable,
)
from ..tool.auth_recipe import normalize_origin
from ..tool.execution_scheduler import resume_auth_dependency
from ..tool.parameter_relation_workbench import environment_execution_policy

logger = logging.getLogger(__name__)

def _bounded_identifier(value, label, maximum=80):
    text = str(value or "").strip()
    if not text or len(text) > maximum or any(
            not (char.isalnum() or char in "._-") for char in text):
        raise ValueError("{} 只能使用字母、数字、点、下划线或短横线".format(label))
    return text


def _split_form_values(value):
    text = str(value or "").replace("，", ",").replace(";", "\n").replace(",", "\n")
    result = []
    for item in text.splitlines():
        item = item.strip()
        if item and item not in result:
            result.append(item)
    return result


def _form_json_object(value, label, maximum=65536):
    text = str(value or "").strip()
    if not text:
        return {}
    if len(text) > maximum:
        raise ValueError("{}过大".format(label))
    try:
        result = json.loads(text)
    except (TypeError, ValueError):
        raise ValueError("{}必须是有效 JSON".format(label)) from None
    if not isinstance(result, dict):
        raise ValueError("{}必须是 JSON 对象".format(label))
    return result


def _business_identity_form(value):
    supplied = _form_json_object(value, "业务身份", maximum=4096)
    allowed = {
        "userid", "user_id", "uid", "entid", "ent_id",
        "enterprise_id", "tenant_id",
    }
    unexpected = sorted(set(supplied) - allowed)
    if unexpected:
        raise ValueError("业务身份包含不支持的字段：{}".format(", ".join(unexpected)))
    result = {}
    for name, raw_value in supplied.items():
        if isinstance(raw_value, (dict, list, tuple)) or raw_value in (None, ""):
            raise ValueError("业务身份字段必须是非空标量")
        text = str(raw_value).strip()
        if not text or len(text) > 256:
            raise ValueError("业务身份字段无效")
        result[name] = text
    return result


def _auth_success_statuses(value):
    result = []
    for item in _split_form_values(value):
        try:
            status = int(item)
        except (TypeError, ValueError):
            continue
        if 100 <= status <= 599 and status not in result:
            result.append(status)
    return result or [200]


def _environment_host_entries(value):
    result = []
    seen = set()
    for raw_value in _split_form_values(value):
        if "{" in raw_value or "}" in raw_value:
            continue
        host = normalize_host(raw_value)
        if not host or host in seen:
            continue
        base_url = raw_value if "://" in raw_value else "https://" + raw_value
        result.append({"host": host, "base_url": base_url[:500]})
        seen.add(host)
    return result


def _project_auth_target(project_id, env_id=""):
    values = {"project_id": _canonical_project_id(project_id)}
    if env_id:
        values["env_id"] = str(env_id)
    return url_for("web.project_auth", **values)


def _auth_realm_repair_target(project_id, env_id, profile_id, resume_run_id=""):
    values = {
        "project_id": _canonical_project_id(project_id),
        "env_id": str(env_id or ""),
        "profile_id": str(profile_id or ""),
    }
    if resume_run_id:
        values["resume_run_id"] = str(resume_run_id)
    return url_for("web.auth_realm_repair", **values)


def _auth_repair_recipe_for_candidate(candidate):
    adapter = AuthAdapterVersion.objects(
        adapter_version_id=str(candidate.candidate_adapter_version_id or ""),
    ).first()
    if not adapter:
        raise ValueError("认证候选的 Recipe 版本不存在")
    return dict(adapter.recipe or {})


def _auth_recipe_request_floor(recipe):
    request_count = 0
    for item in recipe.get("steps") or []:
        if item.get("type") == "http":
            request_count += 1
        elif (
                item.get("type") == "mfa_receive"
                and str(item.get("mode") or "pull").lower() == "pull"):
            request_count += max(
                1, min(int(item.get("max_attempts") or 1), 6),
            )
    return max(1, min(6, request_count))


def _create_auth_repair_from_form(profile):
    recipe_mode = str(request.form.get("recipe_mode") or "guided").lower()
    max_age_seconds = _bounded_int(
        request.form.get("max_age_seconds"), 1800, 60, 86400,
    )
    auth_origins = _split_form_values(request.form.get("auth_origins"))
    realm_secret_data = None
    replace_realm_secrets = False
    if recipe_mode in {"advanced", "custom", "sso_product"}:
        entered_secrets = _form_json_object(
            request.form.get("realm_secret_json"),
            "Realm 共享秘密",
            maximum=32768,
        )
        realm_secret_data = entered_secrets or None
        replace_realm_secrets = (
            bool(entered_secrets)
            and request.form.get("replace_realm_secrets") == "1"
        )
    elif str(request.form.get("password_transform") or "plain") == "rsa_pkcs1v15":
        rsa_secret_name = _bounded_identifier(
            request.form.get("rsa_public_key_secret_name")
            or "login_rsa_public_key",
            "RSA 公钥配置键",
        )
        entered_public_key = str(request.form.get("rsa_public_key") or "").strip()
        realm_secret_data = (
            {rsa_secret_name: entered_public_key} if entered_public_key else None
        )
    if recipe_mode == "sso_product":
        recipe = build_sso_product_token_recipe(
            request.form.get("sso_authorization_url"),
            request.form.get("token_login_url"),
            request.form.get("product_verification_url"),
            client_token_secret_name=(
                request.form.get("client_token_secret_name") or "client_token"
            ),
            browser_id=request.form.get("browser_id") or "",
            browser_type=request.form.get("browser_type") or "chrome",
            sso_token_path=request.form.get("sso_token_path") or "access_token",
            product_token_path=(
                request.form.get("product_token_path") or "access_token"
            ),
            max_age_seconds=max_age_seconds,
        )
        # All three exact authentication origins are derived from the Recipe.
        auth_origins = []
        output_kind = "mixed"
    elif recipe_mode in {"advanced", "custom"}:
        recipe, auth_origins = validate_repair_recipe(
            _form_json_object(
                request.form.get("recipe_json"),
                "高级 Recipe",
            ),
            auth_origins,
        )
        output_kind = str(
            (recipe.get("output") or {}).get("auth_kind")
            or request.form.get("repair_auth_kind")
            or profile.auth_kind
        )
    else:
        recipe = build_password_login_recipe(
            request.form.get("login_url"),
            method=request.form.get("login_method") or "POST",
            request_format=request.form.get("request_format") or "json",
            username_field=request.form.get("username_field") or "account",
            password_field=request.form.get("password_field") or "password",
            password_transform=request.form.get("password_transform") or "plain",
            token_source=request.form.get("token_source") or "json",
            token_path=request.form.get("token_path") or "",
            token_header=request.form.get("token_header") or "Authorization",
            token_prefix=request.form.get("token_prefix") or "",
            auth_kind=(
                request.form.get("repair_auth_kind")
                or profile.auth_kind
                or "mixed"
            ),
            include_session_cookies=(
                request.form.get("include_session_cookies") == "1"
            ),
            success_statuses=_auth_success_statuses(
                request.form.get("success_statuses")
            ),
            error_json_path=request.form.get("error_json_path") or "",
            extra_fields=_form_json_object(
                request.form.get("extra_fields_json"),
                "附加协议字段",
                maximum=8192,
            ),
            max_age_seconds=max_age_seconds,
            rsa_public_key_secret_name=(
                request.form.get("rsa_public_key_secret_name")
                or "login_rsa_public_key"
            ),
            rsa_append_timestamp=(
                request.form.get("rsa_append_timestamp") == "1"
            ),
            rsa_timestamp_delimiter=(
                request.form.get("rsa_timestamp_delimiter") or ""
            ),
            rsa_timestamp_unit=(
                request.form.get("rsa_timestamp_unit") or "seconds"
            ),
        )
        # The guided form derives the exact Realm origin from its login URL.
        auth_origins = []
        output_kind = str(
            request.form.get("repair_auth_kind")
            or (recipe.get("output") or {}).get("auth_kind")
            or profile.auth_kind
        )
    candidate = create_auth_repair_candidate(
        profile.profile_id,
        recipe=recipe,
        auth_origins=auth_origins,
        tls_verify=request.form.get("tls_verify") == "1",
        auth_kind=output_kind,
        max_age_seconds=max_age_seconds,
        realm_secret_data=realm_secret_data,
        replace_realm_secrets=replace_realm_secrets,
        reason=request.form.get("repair_reason") or "认证失败后的协议修复",
        operator=str(session.get("username") or ""),
    )
    return candidate, recipe


def _run_auth_repair_form_action(profile, action, now):
    requested_max = _bounded_int(
        request.form.get("max_requests"), 3, 1, 6,
    )
    resume_run_id = str(request.form.get("resume_run_id") or "").strip()
    if action in {
            "create_auth_repair_candidate",
            "create_validate_auth_repair"}:
        candidate, recipe = _create_auth_repair_from_form(profile)
    else:
        candidate = AuthRepairCandidate.objects(
            candidate_id=str(request.form.get("repair_candidate_id") or ""),
            profile_id=profile.profile_id,
        ).first()
        if not candidate:
            raise ValueError("认证修复候选不存在")
        recipe = _auth_repair_recipe_for_candidate(candidate)
    if action == "create_auth_repair_candidate":
        return (
            "候选方案已保存，尚未发送任何认证请求。"
            "请检查流程、认证 Origin 和缺失项后，再显式验证该候选。",
            True,
        )
    max_requests = max(requested_max, _auth_recipe_request_floor(recipe))
    candidate, attempt, activated_profile = (
        verify_and_activate_auth_repair_candidate(
            candidate.candidate_id,
            max_requests=max_requests,
            timeout_seconds=10,
        )
    )
    if attempt.status != "succeeded" or not activated_profile:
        notice = (
            "修复候选验证失败：{}（阶段 {}，{} 次认证请求）。"
            "当前生效版本未被覆盖，可修改后生成新候选或重试。"
        ).format(
            attempt.error_code or "ADAPTER_RUNTIME_ERROR",
            attempt.stage or "runtime",
            attempt.request_count,
        )
        return notice, False

    resumed = None
    rebind_note = ""
    if resume_run_id:
        try:
            rebind_zero_progress_auth_run(
                resume_run_id, candidate.candidate_id,
            )
            resumed = resume_auth_dependency(
                resume_run_id,
                candidate.candidate_profile_revision_id,
            )
            if resumed and resumed.status == security_test_run.QUEUED:
                rebind_note = " 原暂停批次已改绑新版本并恢复。"
            else:
                rebind_note = " 新版本已生效，但原批次仍保持暂停。"
        except ValueError as exc:
            candidate.reload()
            candidate.resume_run_id = resume_run_id
            candidate.rebind_status = "blocked"
            candidate.mtime = now
            candidate.save()
            rebind_note = " 新版本已生效；原批次未恢复：{}".format(str(exc))
    notice = (
        "认证修复已验证并切换：{} 次认证请求；旧版本和失败候选均保留。{}"
    ).format(attempt.request_count, rebind_note)
    return notice, True


@bp_web.route("/project-auth", methods=["GET", "POST"])
@login_check
@templated("/project-auth.html")
def project_auth():
    if request.method == "POST":
        project_id = _canonical_project_id(request.form.get("project_id") or "")
        env_id = str(request.form.get("env_id") or "").strip()
        target = _project_auth_target(project_id, env_id)
        if not is_manager():
            return make_response("Forbidden", 403)
        if not _lifecycle_csrf_valid(request.form.get("csrf_token")):
            session["project_auth_notice"] = {
                "level": "error", "text": "操作未执行：页面令牌无效，请刷新后重试。",
            }
            return redirect(target)
        try:
            project = ApiProject.objects(
                project_id=project_id, status=ApiProject.ACTIVE,
            ).first()
            if not project:
                raise ValueError("项目不存在或已停用")
            action = str(request.form.get("action") or "")
            now = dt.datetime.utcnow()
            if action == "save_environment":
                env_id = _bounded_identifier(env_id, "环境标识")
                hosts = _environment_host_entries(request.form.get("hosts"))
                default_value = str(request.form.get("default_host") or "").strip()
                if "{" in default_value or "}" in default_value:
                    raise ValueError("默认 Host 不能包含未解析的模板变量")
                default_host = normalize_host(default_value) or (hosts[0]["host"] if hosts else "")
                if not default_host:
                    raise ValueError("至少配置一个默认 Host")
                if default_host not in {item["host"] for item in hosts}:
                    base_url = default_value if "://" in default_value else "https://" + default_value
                    hosts.insert(0, {"host": default_host, "base_url": base_url[:500]})
                environment = ProjectEnvironment.objects(
                    project_id=project_id, env_id=env_id,
                ).first() or ProjectEnvironment(
                    project_id=project_id, env_id=env_id, ctime=now,
                )
                environment.name = str(request.form.get("name") or env_id).strip()[:120]
                environment_type = str(request.form.get("environment_type") or "unknown").strip().lower()
                if environment_type not in {"unknown", "test", "preprod", "production"}:
                    raise ValueError("环境类型无效")
                allow_mutation = request.form.get("allow_mutation") == "1"
                if allow_mutation and environment_type not in {"test", "preprod"}:
                    raise ValueError("只有测试或预发环境可以开启自动写入/删除验证")
                environment.environment_type = environment_type
                environment.allow_mutation = allow_mutation
                maximum_request_limit = 1000 if environment_type in {"test", "preprod"} else 3
                environment.auto_request_limit = _bounded_int(
                    request.form.get("auto_request_limit"), 3, 1, maximum_request_limit,
                )
                environment.default_host = default_host
                environment.hosts = hosts
                environment.active = True
                environment.mtime = now
                environment.save()
                notice = "环境已保存；测试/预发按自定义预算执行，正式或未确认环境硬限制为最多 3 次请求。"
            elif action == "save_test_account":
                username = str(request.form.get("username") or "").strip()
                password = str(request.form.get("password") or "")
                if not username or not password:
                    raise ValueError("账号和密码不能为空")
                account_id = str(request.form.get("test_account_id") or "").strip()
                account = TestAccount.objects(account_id=account_id).first() if account_id else None
                if not account:
                    account_id = "test-account-{}".format(secrets.token_hex(10))
                    account = TestAccount(account_id=account_id, username=username, ctime=now)
                    revision_no = 1
                else:
                    latest = CredentialVersion.objects(
                        account_id=account.account_id,
                    ).order_by("-revision_no").first()
                    revision_no = int(latest.revision_no if latest else 0) + 1
                credential_id = "credential-{}".format(secrets.token_hex(10))
                CredentialVersion(
                    credential_version_id=credential_id,
                    account_id=account_id,
                    revision_no=revision_no,
                    credential_type="username_password",
                    secret_data={"username": username, "password": password},
                    ctime=now,
                ).save(force_insert=True)
                account.username = username
                account.display_name = str(request.form.get("display_name") or username).strip()[:120]
                business_identity = _business_identity_form(
                    request.form.get("business_identity_json")
                )
                if business_identity:
                    account_metadata = dict(account.metadata or {})
                    account_metadata["business_identity"] = business_identity
                    account.metadata = account_metadata
                account.lifecycle = TestAccount.ACTIVE
                account.current_credential_version_id = credential_id
                account.mtime = now
                account.save()
                notice = "测试账号已保存为新凭据版本；请绑定项目别名后创建认证方案。"
            elif action == "save_account_binding":
                env_id = _bounded_identifier(env_id, "环境标识")
                if not ProjectEnvironment.objects(
                        project_id=project_id, env_id=env_id, active=True).first():
                    raise ValueError("请先保存项目环境")
                account_key = _bounded_identifier(request.form.get("account_key"), "账号别名")
                raw_account_id = str(request.form.get("account_id") or "").strip()
                account = TestAccount.objects(
                    account_id=raw_account_id, lifecycle=TestAccount.ACTIVE,
                ).first()
                legacy_account = None
                if not account:
                    try:
                        legacy_account = SsoAccount.objects(
                            id=ObjectId(raw_account_id), status=SsoAccount.STATUS_VALID,
                        ).first()
                    except Exception:
                        legacy_account = None
                    if legacy_account:
                        account = TestAccount.objects(
                            source_ref="sso_account:{}".format(legacy_account.id),
                            lifecycle=TestAccount.ACTIVE,
                        ).first()
                if not account:
                    raise ValueError("测试账号尚未迁移或已停用")
                binding = ProjectAccountBinding.objects(
                    project_id=project_id, account_key=account_key,
                ).first() or ProjectAccountBinding(
                    project_id=project_id, account_key=account_key, ctime=now,
                )
                binding.env_id = ""
                binding.account_id = account.account_id
                if legacy_account:
                    binding.account = legacy_account
                binding.display_name = str(request.form.get("display_name") or account.display_name or account_key)[:120]
                binding.role = str(request.form.get("role") or "test")[:80]
                binding.is_test_account = str(request.form.get("is_test_account", "1")) == "1"
                binding.active = True
                binding.mtime = now
                binding.save()
                notice = "测试账号已绑定到项目；认证方案可在多个环境复用该账号身份。"
            elif action == "save_auth_profile":
                env_id = _bounded_identifier(env_id, "环境标识")
                environment = ProjectEnvironment.objects(
                    project_id=project_id, env_id=env_id, active=True,
                ).first()
                if not environment:
                    raise ValueError("请先保存项目环境")
                account_key = _bounded_identifier(request.form.get("account_key"), "账号别名")
                binding = ProjectAccountBinding.objects(
                    project_id=project_id, account_key=account_key, active=True,
                ).first()
                if not binding:
                    raise ValueError("请先绑定该测试账号")
                profile_id = str(request.form.get("profile_id") or "").strip()
                if profile_id:
                    profile_id = _bounded_identifier(profile_id, "认证方案标识", maximum=120)
                else:
                    profile_id = "auth-{}".format(secrets.token_hex(8))
                profile = ProjectAuthProfile.objects(profile_id=profile_id).first()
                if profile and (profile.project_id != project_id or profile.env_id != env_id):
                    raise ValueError("认证方案标识已被其他项目使用")
                is_new_profile = profile is None
                if not profile:
                    profile = ProjectAuthProfile(
                        profile_id=profile_id,
                        project_id=project_id,
                        env_id=env_id,
                        account_key=account_key,
                        provider_id=AUTH_RECIPE_PROVIDER_ID,
                        ctime=now,
                    )
                auth_kind = str(request.form.get("auth_kind") or "mixed").lower()
                if auth_kind not in AUTH_KINDS:
                    raise ValueError("认证类型无效")
                allowed_origins = []
                for item in _split_form_values(request.form.get("allowed_hosts")):
                    origin = normalize_origin(item)
                    if origin and origin not in allowed_origins:
                        allowed_origins.append(origin)
                environment_origins = environment_business_origins(environment)
                allowed_origins = allowed_origins or environment_origins
                if not allowed_origins:
                    raise ValueError("认证方案至少需要一个 Host")
                if environment_origins and any(origin not in environment_origins for origin in allowed_origins):
                    raise ValueError("认证方案 Host 必须属于当前环境")
                realm_revision_id = str(request.form.get("realm_revision_id") or "").strip()
                if not realm_revision_id and profile.current_revision_id:
                    current_revision = ProjectAuthProfileRevision.objects(
                        profile_revision_id=profile.current_revision_id,
                    ).first()
                    realm_revision_id = str(current_revision.realm_revision_id or "") if current_revision else ""
                realm_revision = AuthRealmRevision.objects(
                    realm_revision_id=realm_revision_id,
                    lifecycle__in=["validated", "active"],
                ).first()
                if not realm_revision:
                    raise ValueError("请选择已完成结构校验的认证域版本")
                desired_metadata = dict(profile.metadata or {})
                desired_metadata["max_age_seconds"] = _bounded_int(
                    request.form.get("max_age_seconds"), 1800, 60, 86400,
                )
                profile.name = str(request.form.get("name") or profile_id).strip()[:120]
                profile.purpose = str(request.form.get("purpose") or "default").strip()[:80]
                profile.is_default = request.form.get("is_default") == "1"
                profile.active = request.form.get("active", "1") == "1"
                profile.lifecycle = "active" if profile.active else "disabled"
                profile.mtime = now
                if is_new_profile or not profile.current_revision_id:
                    profile.account_key = account_key
                    profile.provider_id = AUTH_RECIPE_PROVIDER_ID
                    profile.auth_kind = auth_kind
                    profile.refresh_strategy = "login"
                    profile.allowed_hosts = [
                        normalize_host(item) for item in allowed_origins
                    ]
                    profile.metadata = desired_metadata
                if profile.is_default:
                    ProjectAuthProfile.objects(
                        project_id=project_id, env_id=env_id, id__ne=profile.id,
                    ).update(set__is_default=False)
                profile.save()
                revision = create_profile_revision(
                    profile,
                    project_account_key=account_key,
                    realm_revision_id=realm_revision.realm_revision_id,
                    auth_kind=auth_kind,
                    allowed_business_origins=allowed_origins,
                    max_age_seconds=desired_metadata["max_age_seconds"],
                )
                if not profile.current_revision_id:
                    profile.current_revision_id = revision.profile_revision_id
                    profile.context_ref = revision.profile_revision_id
                    profile.save()
                    AuthProfileHealth.objects(
                        profile_revision_id=revision.profile_revision_id,
                    ).modify(
                        upsert=True, new=True,
                        set__profile_id=profile.profile_id,
                        set_on_insert__status="unknown",
                        set__updated_at=now,
                    )
                    notice = "认证方案首个版本已保存；请执行一次认证验证。"
                elif revision.profile_revision_id == profile.current_revision_id:
                    profile.account_key = revision.project_account_key
                    profile.provider_id = AUTH_RECIPE_PROVIDER_ID
                    profile.auth_kind = revision.auth_kind
                    profile.refresh_strategy = revision.refresh_strategy
                    profile.allowed_hosts = [
                        normalize_host(item)
                        for item in revision.allowed_business_origins or []
                    ]
                    profile.metadata = desired_metadata
                    profile.save()
                    notice = "认证方案设置已保存，当前执行版本没有变化。"
                else:
                    candidate = register_auth_repair_candidate(
                        profile,
                        revision,
                        reason="认证方案设置变更",
                        operator=str(session.get("username") or ""),
                    )
                    notice = (
                        "已创建认证候选 {}，当前生效版本未被覆盖；"
                        "请进入认证域修复工作台验证，成功后系统才会切换。"
                    ).format(candidate.candidate_id)
            elif action == "validate_auth_profile":
                profile = ProjectAuthProfile.objects(
                    profile_id=str(request.form.get("profile_id") or ""),
                    project_id=project_id,
                    env_id=env_id,
                    active=True,
                ).first()
                if not profile:
                    raise ValueError("认证方案不存在或已停用")
                attempt = verify_project_auth_profile(
                    profile.profile_id,
                    max_requests=_bounded_int(request.form.get("max_requests"), 3, 1, 6),
                    timeout_seconds=10,
                )
                resume_run_id = str(request.form.get("resume_run_id") or "").strip()
                if attempt.status == "succeeded":
                    resumed = None
                    if resume_run_id:
                        resumed = resume_auth_dependency(
                            resume_run_id, attempt.profile_revision_id,
                        )
                    notice = "认证验证成功：{} 次认证请求，Token/Cookie 仅保存在内存。{}".format(
                        attempt.request_count,
                        "原暂停批次已恢复。" if resumed and resumed.status == security_test_run.QUEUED else "",
                    )
                else:
                    notice = "认证验证失败：{}（阶段 {}，{} 次请求）。请按下方诊断修复后重试。".format(
                        attempt.error_code or "ADAPTER_RUNTIME_ERROR",
                        attempt.stage or "runtime",
                        attempt.request_count,
                    )
                    session["project_auth_notice"] = {"level": "error", "text": notice[:300]}
                    return redirect(_project_auth_target(project_id, env_id))
            elif action == "quick_fix_auth":
                profile_id = str(request.form.get("profile_id") or "")
                account_id = str(request.form.get("account_id") or "")
                new_password = str(request.form.get("password") or "")
                if not new_password:
                    raise ValueError("请输入新密码")
                profile = ProjectAuthProfile.objects(
                    profile_id=profile_id, project_id=project_id,
                ).first()
                if not profile:
                    raise ValueError("认证方案不存在")
                env_id = profile.env_id
                account = TestAccount.objects(account_id=account_id).first() if account_id else None
                if not account:
                    binding = ProjectAccountBinding.objects(
                        project_id=project_id, account_key=profile.account_key, active=True,
                    ).first()
                    if binding:
                        account = TestAccount.objects(account_id=str(binding.account_id)).first()
                if not account:
                    raise ValueError("找不到绑定的测试账号，请先在上方绑定账号")
                max_rev = CredentialVersion.objects(account_id=account.account_id).order_by("-revision_no").first()
                next_rev = (max_rev.revision_no + 1) if max_rev else 1
                CredentialVersion(
                    account_id=account.account_id,
                    revision_no=next_rev,
                    secret_data={"password": new_password},
                    lifecycle=CredentialVersion.ACTIVE if hasattr(CredentialVersion, 'ACTIVE') else "active",
                ).save()
                account.current_credential_version_id = None
                account.save()
                attempt = verify_project_auth_profile(
                    profile.profile_id, max_requests=3, timeout_seconds=10,
                )
                resume_run_id = str(request.form.get("resume_run_id") or "").strip()
                if attempt.status == "succeeded":
                    resumed = None
                    if resume_run_id:
                        resumed = resume_auth_dependency(resume_run_id, attempt.profile_revision_id)
                    session["project_auth_notice"] = {
                        "level": "success",
                        "text": "凭据已更新并验证成功！{} 次认证请求。{}".format(
                            attempt.request_count,
                            "暂停批次已恢复。" if resumed else "",
                        ),
                    }
                else:
                    session["project_auth_notice"] = {
                        "level": "error",
                        "text": "凭据已更新但验证仍失败：{}（阶段 {}）。请检查密码是否正确或认证地址是否变更。".format(
                            attempt.error_code or "UNKNOWN", attempt.stage or "login",
                        ),
                    }
                return redirect(_project_auth_target(project_id, env_id))
            elif action in {"toggle_profile", "set_default_profile"}:
                profile = ProjectAuthProfile.objects(
                    profile_id=str(request.form.get("profile_id") or ""),
                    project_id=project_id,
                ).first()
                if not profile:
                    raise ValueError("认证方案不存在")
                env_id = profile.env_id
                if action == "toggle_profile":
                    profile.active = not profile.active
                    profile.lifecycle = "active" if profile.active else "disabled"
                    if not profile.active:
                        profile.is_default = False
                    notice = "认证方案已{}。".format("启用" if profile.active else "停用")
                else:
                    ProjectAuthProfile.objects(
                        project_id=project_id, env_id=profile.env_id,
                    ).update(set__is_default=False)
                    profile.is_default = True
                    profile.active = True
                    profile.lifecycle = "active"
                    notice = "默认认证方案已更新。"
                profile.mtime = now
                profile.save()
            else:
                raise ValueError("不支持的项目认证操作")
            session["project_auth_notice"] = {"level": "success", "text": notice}
        except (ValueError, NotUniqueError) as exc:
            message = str(exc) if isinstance(exc, ValueError) else "名称或标识重复，请修改后重试"
            session["project_auth_notice"] = {"level": "error", "text": message[:300]}
        except Exception:
            logger.exception("project auth configuration failed")
            session["project_auth_notice"] = {
                "level": "error", "text": "配置未保存：数据状态已变化，请刷新后重试。",
            }
        return redirect(_project_auth_target(project_id, env_id))

    projects = _available_projects()
    project_id = _canonical_project_id(request.args.get("project_id") or "")
    if not project_id and projects:
        project_id = projects[0]["id"]
    environments = list(ProjectEnvironment.objects(
        project_id=project_id,
    ).order_by("env_id")) if project_id else []
    env_id = str(request.args.get("env_id") or "")
    if not env_id and environments:
        active_env = next((item for item in environments if item.active), environments[0])
        env_id = active_env.env_id
    selected_environment = next((item for item in environments if item.env_id == env_id), None)
    bindings = list(ProjectAccountBinding.objects(
        project_id=project_id,
    ).order_by("account_key")) if project_id else []
    profiles = list(ProjectAuthProfile.objects(
        project_id=project_id, env_id=env_id,
    ).order_by("-is_default", "name")) if project_id and env_id else []
    edit_profile_id = str(request.args.get("edit_profile_id") or "")
    edit_profile = next(
        (item for item in profiles if item.profile_id == edit_profile_id), None,
    )
    if edit_profile and edit_profile.provider_id != AUTH_RECIPE_PROVIDER_ID:
        edit_profile = None
    edit_profile_revision = ProjectAuthProfileRevision.objects(
        profile_revision_id=str(edit_profile.current_revision_id or ""),
    ).first() if edit_profile else None
    realm_options = []
    for revision in AuthRealmRevision.objects(
            lifecycle__in=["validated", "active"]).order_by("realm_id", "-revision_no"):
        realm = AuthRealm.objects(realm_id=revision.realm_id).first()
        realm_options.append({
            "id": revision.realm_revision_id,
            "label": "{} / r{} / {}".format(
                realm.name if realm else revision.realm_id,
                revision.revision_no,
                ", ".join(revision.auth_origins or []),
            ),
            "tls_verify": bool(revision.tls_verify),
        })
    account_rows = list(TestAccount.objects(
        lifecycle=TestAccount.ACTIVE,
    ).order_by("display_name", "username"))
    binding_accounts = {
        account.account_id: account for account in account_rows
    }
    health_by_revision = {
        row.profile_revision_id: row for row in AuthProfileHealth.objects(
            profile_id__in=[item.profile_id for item in profiles],
        )
    } if profiles else {}
    latest_attempt_by_revision = {}
    for attempt in AuthVerificationAttempt.objects(
            profile_id__in=[item.profile_id for item in profiles]).order_by("-started_at") if profiles else []:
        latest_attempt_by_revision.setdefault(attempt.profile_revision_id, attempt)
    resume_run_id = str(request.args.get("resume_run_id") or "")
    return {
        "projects": projects,
        "project_id": project_id,
        "environments": environments,
        "env_id": env_id,
        "selected_environment": selected_environment,
        "bindings": bindings,
        "profiles": profiles,
        "edit_profile": edit_profile,
        "edit_profile_revision": edit_profile_revision,
        "accounts": account_rows,
        "binding_accounts": binding_accounts,
        "realm_options": realm_options,
        "health_by_revision": health_by_revision,
        "latest_attempt_by_revision": latest_attempt_by_revision,
        "resume_run_id": resume_run_id,
        "host_names": environment_host_names(selected_environment),
        "environment_policy": environment_execution_policy(selected_environment),
        "csrf_token": _lifecycle_csrf_token(),
        "can_manage": is_manager(),
        "notice": session.pop("project_auth_notice", None),
    }


def _auth_recipe_steps_for_view(recipe):
    labels = {
        "sso_authorization": "获取 SSO Token",
        "establish_session": "建立登录 Session / Cookie",
        "product_verification": "换取产品验证 Token",
        "login": "登录并提取认证结果",
    }
    rows = []
    for step in recipe.get("steps") or []:
        step_type = str(step.get("type") or "")
        step_id = str(step.get("id") or "step")
        if step_type == "set":
            operation = str(step.get("operation") or "literal")
            target = str(step.get("target") or step_id)
            rows.append({
                "id": step_id,
                "type": "set",
                "label": str(
                    step.get("label")
                    or labels.get(step_id)
                    or step_id.replace("_", " ")
                ),
                "method": "本地",
                "origin": "",
                "path": "{} → {}".format(operation, target),
                "extract_names": [],
                "is_request": False,
            })
            continue
        if step_type != "http":
            continue
        url = str(step.get("url") or "")
        parsed = urlsplit(url)
        rows.append({
            "id": step_id,
            "type": "http",
            "label": str(
                step.get("label")
                or labels.get(step_id)
                or step_id.replace("_", " ")
            ),
            "method": str(step.get("method") or "POST").upper(),
            "origin": normalize_origin(url),
            "path": str(parsed.path or "/"),
            "extract_names": sorted(
                str(name) for name in (step.get("extract") or {})
            ),
            "is_request": True,
        })
    return rows


def _auth_failure_guidance(health, missing_secret_keys):
    code = str(health.error_code or "") if health else ""
    guidance = {
        "CONFIG_INVALID": (
            "配置不完整",
            "检查流程步骤、认证 Origin、变量引用和输出规则。",
        ),
        "AUTH_HOST_UNREACHABLE": (
            "认证地址不可达",
            "确认环境域名、DNS、TLS 和代理设置，不要通过修改业务 Host 规避。",
        ),
        "CREDENTIAL_REJECTED": (
            "账号或登录协议被拒绝",
            "先确认测试账号可登录，再核对账号字段、密码变换和签名规则。",
        ),
        "MFA_OR_INTERACTION_REQUIRED": (
            "需要人工登录或二次验证",
            "该流程不适合纯 HTTP Recipe，应转入交互式认证适配器。",
        ),
        "LOGIN_PROTOCOL_CHANGED": (
            "登录协议或地址已变化",
            "从最新接口文档、登录流量或已知成功会话重新识别步骤。",
        ),
        "TOKEN_EXTRACTION_FAILED": (
            "登录成功但没有提取到认证结果",
            "核对响应字段、Header/Cookie 名称和输出引用。",
        ),
        "SESSION_ESTABLISH_FAILED": (
            "登录 Session 未建立",
            "检查跳转、Cookie Jar、跨 Origin 和成功状态码。",
        ),
        "IDENTITY_VERIFY_FAILED": (
            "产品或身份验证阶段失败",
            "检查上一步 Token/Cookie 是否正确传递及产品验证请求体。",
        ),
        "BUSINESS_AUDIENCE_MISMATCH": (
            "认证结果不能用于当前业务 Host",
            "核对认证受众、业务 Host 限制和产品 Token 类型。",
        ),
        "RATE_LIMITED": (
            "认证请求受到限流",
            "停止连续重试，等待窗口恢复后再验证同一候选。",
        ),
        "ADAPTER_RUNTIME_ERROR": (
            "认证适配器执行异常",
            "检查候选步骤和最近诊断；原始异常不会作为配置依据。",
        ),
    }
    if missing_secret_keys:
        return {
            "tone": "danger",
            "title": "候选流程缺少 Realm 共享配置",
            "summary": "需要补充：{}。".format("、".join(missing_secret_keys)),
            "action": "共享秘密只填写缺失值；页面不会回显已经保存的值。",
        }
    if code in guidance:
        title, action = guidance[code]
        return {
            "tone": "danger",
            "title": title,
            "summary": str(
                health.error_summary
                or "最近一次认证验证未能建立可用上下文。"
            ),
            "action": action,
        }
    status = str(health.status or "unknown") if health else "unknown"
    if status == "healthy":
        return {
            "tone": "success",
            "title": "当前认证方案可用",
            "summary": "最近一次验证已建立认证上下文。",
            "action": "只有协议、环境或账号发生变化时才需要创建新候选。",
        }
    return {
        "tone": "warning",
        "title": "当前版本尚未完成验证",
        "summary": "系统没有足够证据确认该版本可用。",
        "action": "先保存并检查候选，再显式执行认证验证。",
    }


@bp_web.route("/auth-realms/repair", methods=["GET", "POST"])
@login_check
@templated("/auth-realm-repair.html")
def auth_realm_repair():
    if request.method == "POST":
        project_id = _canonical_project_id(
            request.form.get("project_id") or ""
        )
        env_id = str(request.form.get("env_id") or "").strip()
        profile_id = str(request.form.get("profile_id") or "").strip()
        resume_run_id = str(
            request.form.get("resume_run_id") or ""
        ).strip()
        target = _auth_realm_repair_target(
            project_id, env_id, profile_id, resume_run_id,
        )
        if not is_manager():
            return make_response("Forbidden", 403)
        if not _lifecycle_csrf_valid(request.form.get("csrf_token")):
            session["auth_realm_repair_notice"] = {
                "level": "error",
                "text": "操作未执行：页面令牌无效，请刷新后重试。",
            }
            return redirect(target)
        try:
            profile = ProjectAuthProfile.objects(
                profile_id=profile_id,
                project_id=project_id,
                env_id=env_id,
                provider_id=AUTH_RECIPE_PROVIDER_ID,
                active=True,
            ).first()
            if not profile or not profile.current_revision_id:
                raise ValueError("认证方案不存在、已停用或尚未迁移")
            action = str(request.form.get("action") or "")
            if action not in {
                    "create_auth_repair_candidate",
                    "create_validate_auth_repair",
                    "validate_auth_repair_candidate"}:
                raise ValueError("不支持的认证域修复操作")
            notice, succeeded = _run_auth_repair_form_action(
                profile, action, dt.datetime.utcnow(),
            )
            session["auth_realm_repair_notice"] = {
                "level": "success" if succeeded else "error",
                "text": notice[:300],
                "view": (
                    "history"
                    if action in {
                        "create_auth_repair_candidate",
                        "create_validate_auth_repair",
                        "validate_auth_repair_candidate",
                    }
                    else "overview"
                ),
            }
        except (ValueError, NotUniqueError) as exc:
            message = (
                str(exc)
                if isinstance(exc, ValueError)
                else "认证版本已变化，请刷新后重试"
            )
            session["auth_realm_repair_notice"] = {
                "level": "error", "text": message[:300],
            }
        except Exception:
            logger.exception("authentication Realm repair failed")
            session["auth_realm_repair_notice"] = {
                "level": "error",
                "text": "认证修复未保存：数据状态已变化，请刷新后重试。",
            }
        return redirect(target)

    project_id = _canonical_project_id(request.args.get("project_id") or "")
    env_id = str(request.args.get("env_id") or "").strip()
    profile_id = str(request.args.get("profile_id") or "").strip()
    resume_run_id = str(request.args.get("resume_run_id") or "").strip()
    profile = ProjectAuthProfile.objects(
        profile_id=profile_id,
        project_id=project_id,
        env_id=env_id,
        provider_id=AUTH_RECIPE_PROVIDER_ID,
    ).first()
    if not profile or not profile.current_revision_id:
        return make_response("Authentication profile not found", 404)
    try:
        revision, realm_revision, adapter_version = (
            RecipeAccountContextProvider._load_revision_chain(
                profile, allow_draft=True,
            )
        )
    except (AccountContextInvalid, AccountContextUnavailable):
        return make_response("Authentication revision chain is invalid", 409)
    realm = AuthRealm.objects(
        realm_id=realm_revision.realm_id,
    ).first()
    project = ApiProject.objects(project_id=project_id).first()
    environment = ProjectEnvironment.objects(
        project_id=project_id, env_id=env_id,
    ).first()
    health = AuthProfileHealth.objects(
        profile_revision_id=revision.profile_revision_id,
    ).first()
    attempt = AuthVerificationAttempt.objects(
        profile_revision_id=revision.profile_revision_id,
    ).order_by("-started_at").first()
    defaults = auth_repair_defaults(profile)
    current_recipe = dict(adapter_version.recipe or {})
    current_secret_keys = realm_secret_key_names(realm_revision)
    required_secret_keys = recipe_secret_names(current_recipe)
    missing_secret_keys = [
        key for key in required_secret_keys if key not in current_secret_keys
    ]
    account_binding = ProjectAccountBinding.objects(
        project_id=project_id,
        account_key=revision.project_account_key,
        active=True,
    ).first()
    test_account = TestAccount.objects(
        account_id=str(account_binding.account_id or ""),
        lifecycle=TestAccount.ACTIVE,
    ).first() if account_binding and account_binding.account_id else None
    current_steps = _auth_recipe_steps_for_view(current_recipe)
    request_step_count = len([
        step for step in current_steps if step.get("is_request")
    ])
    transform_step_count = len(current_steps) - request_step_count
    workflow_summary = {
        "step_count": len(current_steps),
        "request_step_count": request_step_count,
        "transform_step_count": transform_step_count,
        "output_kind": str(
            (current_recipe.get("output") or {}).get("auth_kind")
            or revision.auth_kind
            or "mixed"
        ),
        "template": str(current_recipe.get("template") or ""),
        "auth_origins": list(realm_revision.auth_origins or []),
        "business_origins": list(revision.allowed_business_origins or []),
    }
    candidates = []
    for candidate in AuthRepairCandidate.objects(
            profile_id=profile.profile_id).order_by("-ctime")[:12]:
        candidate_realm = AuthRealmRevision.objects(
            realm_revision_id=candidate.candidate_realm_revision_id,
        ).first()
        candidate_adapter = AuthAdapterVersion.objects(
            adapter_version_id=candidate.candidate_adapter_version_id,
        ).first()
        candidate_recipe = dict(candidate_adapter.recipe or {}) if candidate_adapter else {}
        candidate_attempt = AuthVerificationAttempt.objects(
            repair_candidate_id=candidate.candidate_id,
        ).order_by("-started_at").first()
        candidates.append({
            "candidate": candidate,
            "realm": candidate_realm,
            "attempt": candidate_attempt,
            "secret_keys": realm_secret_key_names(candidate_realm),
            "steps": _auth_recipe_steps_for_view(
                candidate_recipe
            ) if candidate_recipe else [],
            "request_floor": _auth_recipe_request_floor(
                candidate_recipe
            ) if candidate_recipe else 1,
        })
    page_notice = session.pop("auth_realm_repair_notice", None)
    initial_view = str(
        (page_notice or {}).get("view") or "overview"
    )
    if initial_view not in {"overview", "configure", "history"}:
        initial_view = "overview"
    return {
        "project": project,
        "project_id": project_id,
        "environment": environment,
        "env_id": env_id,
        "profile": profile,
        "revision": revision,
        "realm": realm,
        "realm_revision": realm_revision,
        "adapter_version": adapter_version,
        "health": health,
        "attempt": attempt,
        "defaults": defaults,
        "current_recipe": current_recipe,
        "current_steps": current_steps,
        "current_secret_keys": current_secret_keys,
        "required_secret_keys": required_secret_keys,
        "missing_secret_keys": missing_secret_keys,
        "workflow_summary": workflow_summary,
        "diagnosis": _auth_failure_guidance(
            health, missing_secret_keys,
        ),
        "account_binding": account_binding,
        "test_account": test_account,
        "candidates": candidates,
        "resume_run_id": resume_run_id,
        "back_url": _project_auth_target(project_id, env_id),
        "csrf_token": _lifecycle_csrf_token(),
        "can_manage": is_manager(),
        "notice": page_notice,
        "initial_view": initial_view,
    }
