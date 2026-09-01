import platform

from . import bp_web
from ..common.decorators import login_check
from ..version import version_info


@bp_web.route("/system/version", methods=["GET"])
@login_check
def system_version_web():
    payload = version_info()
    payload["python"] = platform.python_version()
    return payload
