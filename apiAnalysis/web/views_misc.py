import os
import redis
from flask import request, make_response, redirect, url_for, session, send_file
from . import bp_web
from .. import redis_pool
from ..common.decorators import *
from ..db.collection import *
from ..conf.conf import *
from ..common.util import get_page, resp_length
from ..tool.result_review import get_review_queue


@bp_web.route("/favicon.ico")
def favicon():
    """
    favicon
    :return:
    """
    from .. import app_path
    icon_path = os.path.abspath(os.path.join(app_path, "..", "favicon.ico"))
    if not os.path.isfile(icon_path):
        # A missing optional icon must not generate a server exception or a
        # misleading HTTP 200 response with an error page.
        return make_response("", 204)
    return send_file(icon_path, mimetype="image/x-icon", conditional=True)


@bp_web.route("/welcome")
@login_check
@templated("welcome.html")
def welcome():
    from ..db.collection import (
        ApiProject,
        security_test_run,
        security_test_result,
        vulnerability_finding,
        RequestObservation,
        ObservationRoutingDecision,
    )
    project_count = ApiProject.objects(status="active").count()
    review_queue = list(get_review_queue(limit=None))
    pending_review = len(review_queue)
    open_findings = vulnerability_finding.objects(
        status__nin=vulnerability_finding.CLOSED_REASONS,
    ).count()
    unassigned_obs = ObservationRoutingDecision.objects(
        decision__in=["unassigned", "ambiguous"],
    ).count()
    recent_runs = list(
        security_test_run.objects().order_by("-started_at").limit(8)
    )
    review_items = review_queue[:8]
    return {
        "project_count": project_count,
        "pending_review": pending_review,
        "open_findings": open_findings,
        "unassigned_obs": unassigned_obs,
        "recent_runs": recent_runs,
        "review_items": review_items,
    }


@bp_web.route("/")
@login_check
@templated("/home.html")
def home():
    pass

@bp_web.route("/report/<_filename>", methods=['GET'])
@login_check
def report(_filename):
    path = os.listdir("app/templates/report")
    if _filename in path:
        file = open("app/templates/report/"+_filename, encoding="utf-8")
        content = file.read()
        return content
    else:
        ret = {"filename"+str(i): path[i] for i in range(0, len(path))}
        return ret


@bp_web.route("/lang/<lang>")
def set_lang(lang):
    if lang in ["zh", "en"]:
        session["lang"] = lang
    nxt = request.args.get("next") or request.referrer or url_for("web.home")
    return redirect(nxt)
