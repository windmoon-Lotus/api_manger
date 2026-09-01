"""Application factory and shared infrastructure handles.

The Web process is intentionally passive: creating a Flask application only
connects model metadata and registers HTTP routes.  Network execution,
relation analysis, and periodic recovery are owned by separate CLI processes.
"""
import os

import redis

from apiAnalysis.common.func import (
    format_json,
    is_manager,
    str_show,
    time_now,
    time_show,
)
from apiAnalysis.common.i18n import get_lang, t
from apiAnalysis.conf.conf import logger
from apiAnalysis.conf.secret import (
    mongo_database,
    mongo_host,
    mongo_password,
    mongo_port,
    mongo_user,
    redis_db,
    redis_host,
    redis_password,
    redis_port,
    secret_key,
    secret_key_is_ephemeral,
)
from apiAnalysis.model.model import PolicyEnum
from apiAnalysis.runtime_check import format_checks, run_checks
from apiAnalysis.version import __version__


app_path = os.path.dirname(os.path.realpath(__file__))
redis_pool = redis.ConnectionPool(
    host=redis_host,
    port=redis_port,
    db=redis_db,
    password=redis_password,
)


def _build_local_users():
    users = {}
    admin_password = os.getenv("API_MANAGER_ADMIN_PASSWORD")
    normal_password = os.getenv("API_MANAGER_NORMAL_PASSWORD")
    if admin_password:
        users[os.getenv("API_MANAGER_ADMIN_USERNAME", "admin")] = {
            "password": admin_password,
            "role": [PolicyEnum.MANAGE.value, PolicyEnum.ACCESS.value],
        }
    if normal_password:
        users[os.getenv("API_MANAGER_NORMAL_USERNAME", "normal")] = {
            "password": normal_password,
            "role": [PolicyEnum.ACCESS.value],
        }
    if os.getenv("API_MANAGER_ALLOW_INSECURE_DEFAULT_USERS", "0") == "1":
        logger.warning("insecure built-in Web users are enabled for local migration only")
        users.setdefault("admin", {
            "password": "admin123",
            "role": [PolicyEnum.MANAGE.value, PolicyEnum.ACCESS.value],
        })
        users.setdefault("normal", {
            "password": "normal123",
            "role": [PolicyEnum.ACCESS.value],
        })
    return users


users = _build_local_users()


def init():
    """Register the default Mongo connection without starting background work."""
    from mongoengine import connect

    return connect(
        mongo_database,
        username=mongo_user,
        password=mongo_password,
        host=mongo_host,
        port=mongo_port,
        connect=False,
    )


def create_app():
    """Create the passive Flask Web application."""
    from flask import Flask
    from flask_cors import CORS

    from .conf.conf import cors_origin
    from .web import bp_api, bp_web

    checks = run_checks(include_tools=False)
    logger.info("startup checks:\n%s", format_checks(checks))
    if not users:
        logger.warning("no local Web user is configured; set API_MANAGER_ADMIN_PASSWORD before login")
    if secret_key_is_ephemeral:
        logger.warning("API_MANAGER_SECRET_KEY is not set; Web sessions will reset on restart")

    init()

    app = Flask(__name__)
    app.secret_key = secret_key

    CORS(bp_api, supports_credentials=True, origins=cors_origin)
    app.register_blueprint(bp_api)
    app.register_blueprint(bp_web)

    app.add_template_global(is_manager, "is_manager")
    app.add_template_global(time_now, "time_now")
    app.add_template_global(t, "t")
    app.add_template_global(get_lang, "get_lang")
    app.add_template_global(__version__, "app_version")

    app.add_template_filter(time_show, "time_show")
    app.add_template_filter(format_json, "json_show")
    app.add_template_filter(str_show, "str_show")

    return app
