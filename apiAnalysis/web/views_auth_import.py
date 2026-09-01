"""Universal auth configuration wizard routes."""
import json
import logging

from flask import abort, request, redirect, url_for, session

from . import bp_web
from ._helpers import _lifecycle_csrf_token, _lifecycle_csrf_valid
from ..common.decorators import login_check, templated
from ..common.func import is_manager
from ..db.collection import ApiProject, ProjectEnvironment
from ..tool.account_context import trusted_auth_code_enabled
from ..tool.universal_auth import (
    import_code_as_profile,
    import_recipe_as_profile,
    import_token_endpoint_as_profile,
    RECIPE_SCHEMA_DOC,
    AI_PROMPT_TEMPLATE,
)
from ..tool.project_auth import build_sso_product_token_recipe

logger = logging.getLogger(__name__)


def _lines(value):
    return [item.strip() for item in str(value or "").splitlines() if item.strip()]


@bp_web.route("/auth-import", methods=["GET", "POST"])
@login_check
@templated("/auth-import.html")
def auth_import_wizard():
    projects = list(ApiProject.objects(status="active").order_by("name"))
    project_id = request.args.get("project_id") or request.form.get("project_id") or ""
    env_id = request.args.get("env_id") or request.form.get("env_id") or ""
    environments = list(ProjectEnvironment.objects(project_id=project_id, active=True)) if project_id else []
    if not env_id and environments:
        env_id = str(environments[0].env_id or "")

    if request.method == "POST":
        if not is_manager():
            abort(403)
        if not _lifecycle_csrf_valid(request.form.get("csrf_token")):
            abort(400)
        action = request.form.get("action", "")
        project_id = request.form.get("project_id", "")
        env_id = request.form.get("env_id", "")
        profile_name = request.form.get("profile_name", "").strip() or "导入的认证方案"
        account_key = request.form.get("account_key", "").strip() or "owner"
        login_scene = request.form.get("login_scene", "").strip() or profile_name
        role_key = request.form.get("role_key", "").strip() or "default"
        login_mode = request.form.get("login_mode", "").strip()
        tls_verify = (
            request.form.get("tls_verify") == "1"
            if request.form.get("tls_verify_present") == "1"
            else True
        )

        try:
            if action == "import_sso_product":
                client_token = request.form.get("realm_client_token", "")
                if not client_token:
                    raise ValueError("请填写 Realm Client Token")
                recipe = build_sso_product_token_recipe(
                    request.form.get("sso_authorization_url", ""),
                    request.form.get("token_login_url", ""),
                    request.form.get("product_verification_url", ""),
                    client_token_secret_name="client_token",
                    browser_id=request.form.get("browser_id", ""),
                    browser_type=request.form.get("browser_type", "chrome"),
                    sso_token_path=(
                        request.form.get("sso_token_path", "") or "access_token"
                    ),
                    product_token_path=(
                        request.form.get("product_token_path", "") or "access_token"
                    ),
                    max_age_seconds=int(
                        request.form.get("max_age_seconds") or 1800
                    ),
                )
                ids = import_recipe_as_profile(
                    project_id=project_id,
                    env_id=env_id,
                    profile_name=profile_name,
                    recipe=recipe,
                    realm_secrets={"client_token": client_token},
                    auth_origins=[],
                    business_origins=(
                        _lines(request.form.get("business_origins")) or None
                    ),
                    account_key=account_key,
                    recipe_key=request.form.get("recipe_key", "").strip(),
                    login_scene=login_scene,
                    role_key=role_key,
                    login_mode=login_mode or "sso_product_token",
                    max_age_seconds=int(
                        request.form.get("max_age_seconds") or 1800
                    ),
                    tls_verify=tls_verify,
                )
                session["project_auth_notice"] = {
                    "level": "success",
                    "text": (
                        f"三阶段认证 Profile 已导入：{ids['profile_id']}。"
                        "请在认证工作台显式验证后再绑定业务测试。"
                    ),
                }
                return redirect(url_for(
                    "web.project_auth", project_id=project_id, env_id=env_id,
                ))

            elif action == "import_recipe":
                recipe_text = request.form.get("recipe_json", "").strip()
                if not recipe_text:
                    raise ValueError("请粘贴 Recipe JSON")
                recipe = json.loads(recipe_text)
                secrets_text = request.form.get("realm_secrets", "").strip()
                realm_secrets = json.loads(secrets_text) if secrets_text else {}
                auth_origins = _lines(request.form.get("auth_origins"))
                biz_origins = _lines(request.form.get("business_origins")) or None

                ids = import_recipe_as_profile(
                    project_id=project_id, env_id=env_id,
                    profile_name=profile_name, recipe=recipe,
                    realm_secrets=realm_secrets, auth_origins=auth_origins,
                    business_origins=biz_origins, account_key=account_key,
                    recipe_key=request.form.get("recipe_key", "").strip(),
                    login_scene=login_scene,
                    role_key=role_key,
                    login_mode=login_mode or "recipe",
                    tls_verify=tls_verify,
                )
                session["project_auth_notice"] = {
                    "level": "success",
                    "text": (
                        f"Recipe 已一键导入并激活：{ids['profile_id']}。"
                        "其他登录功能点和历史执行版本未被覆盖。"
                    ),
                }
                return redirect(url_for("web.project_auth", project_id=project_id, env_id=env_id))

            elif action == "import_token_url":
                token_url = request.form.get("token_url", "").strip()
                if not token_url:
                    raise ValueError("请填写 Token URL")
                ids = import_token_endpoint_as_profile(
                    project_id=project_id,
                    env_id=env_id,
                    profile_name=profile_name,
                    token_url=token_url,
                    token_method=request.form.get("token_method", "GET"),
                    pass_credentials=request.form.get("pass_credentials", "none"),
                    response_path=request.form.get("response_path", "access_token"),
                    token_prefix=request.form.get("token_prefix", "Bearer "),
                    expires_in=int(request.form.get("expires_in") or 1800),
                    account_key=account_key,
                    login_scene=login_scene,
                    role_key=role_key,
                    login_mode=login_mode or "token_url",
                    tls_verify=tls_verify,
                )
                session["project_auth_notice"] = {
                    "level": "success",
                    "text": (
                        f"Token URL 复用方案已保存并激活：{ids['profile_id']}。"
                        "系统需要认证时会调用已有 Token 服务。"
                    ),
                }
                return redirect(url_for("web.project_auth", project_id=project_id, env_id=env_id))

            elif action == "import_code":
                code_text = request.form.get("user_code", "").strip()
                if not code_text:
                    raise ValueError("请粘贴登录代码")
                ids = import_code_as_profile(
                    project_id=project_id,
                    env_id=env_id,
                    profile_name=profile_name,
                    code_text=code_text,
                    auth_origins=_lines(request.form.get("auth_origins")),
                    account_key=account_key,
                    login_scene=login_scene,
                    role_key=role_key,
                    login_mode=login_mode or "trusted_code",
                    max_age_seconds=int(request.form.get("expires_in") or 1800),
                    tls_verify=tls_verify,
                )
                session["project_auth_notice"] = {
                    "level": "success",
                    "text": (
                        f"管理员可信代码方案已保存并激活：{ids['profile_id']}。"
                        "运行时通过受限请求客户端在独立子进程中调用 get_auth()。"
                    ),
                }
                return redirect(url_for("web.project_auth", project_id=project_id, env_id=env_id))
            else:
                raise ValueError("不支持的认证导入操作")

        except json.JSONDecodeError as exc:
            session["auth_import_notice"] = {"level": "error", "text": f"JSON 解析失败: {exc}"}
        except ValueError as exc:
            session["auth_import_notice"] = {"level": "error", "text": str(exc)}
        except Exception as exc:
            logger.exception("auth import failed")
            session["auth_import_notice"] = {"level": "error", "text": f"导入失败: {str(exc)[:200]}"}
        return redirect(url_for("web.auth_import_wizard", project_id=project_id, env_id=env_id))

    notice = session.pop("auth_import_notice", None)
    return {
        "projects": projects,
        "project_id": project_id,
        "env_id": env_id,
        "environments": environments,
        "notice": notice,
        "can_manage": is_manager(),
        "csrf_token": _lifecycle_csrf_token(),
        "trusted_code_enabled": trusted_auth_code_enabled(),
        "recipe_schema_doc": RECIPE_SCHEMA_DOC,
        "ai_prompt_template": AI_PROMPT_TEMPLATE,
    }
