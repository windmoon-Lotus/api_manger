"""
V2 project-centric routes.

Provides the project list, project overview, and project-scoped
wrapper routes that delegate to existing domain views with a
pre-selected project context.
"""
import logging

from flask import request, redirect, url_for

from . import bp_web
from ..common.decorators import login_check, templated
from ..common.func import is_manager
from ..db.collection import (
    ApiProject,
    ProjectEnvironment,
    ProjectAssetLink,
    ProjectAuthProfile,
    security_test_run,
    security_test_result,
    vulnerability_finding,
    result_review_event,
    RequestObservation,
    ObservationRoutingDecision,
)
from ..tool.result_review import get_review_queue

logger = logging.getLogger(__name__)


@bp_web.route("/projects")
@login_check
@templated("/projects.html")
def project_list():
    projects = list(ApiProject.objects(status="active").order_by("name"))
    project_cards = []
    for p in projects:
        env_count = ProjectEnvironment.objects(project_id=p.project_id, active=True).count()
        asset_count = ProjectAssetLink.objects(project_id=p.project_id).count()
        run_count = security_test_run.objects(project_id=p.project_id).count()
        finding_count = vulnerability_finding.objects(
            project_id=p.project_id,
            status__nin=vulnerability_finding.CLOSED_REASONS,
        ).count()
        project_cards.append({
            "project": p,
            "env_count": env_count,
            "asset_count": asset_count,
            "run_count": run_count,
            "finding_count": finding_count,
        })
    return {
        "project_cards": project_cards,
        "can_manage": is_manager(),
    }


@bp_web.route("/projects/<project_id>")
@login_check
@templated("/project-overview.html")
def project_overview(project_id):
    project = ApiProject.objects(project_id=project_id).first()
    if not project:
        return {"error": "项目不存在"}, 404

    environments = list(ProjectEnvironment.objects(project_id=project_id, active=True).order_by("env_id"))
    asset_count = ProjectAssetLink.objects(project_id=project_id).count()
    profiles = list(ProjectAuthProfile.objects(project_id=project_id, active=True).order_by("name"))

    recent_runs = list(
        security_test_run.objects(project_id=project_id)
        .order_by("-started_at")
        .limit(10)
    )

    open_findings = vulnerability_finding.objects(
        project_id=project_id,
        status__nin=vulnerability_finding.CLOSED_REASONS,
    ).count()

    pending_review = len(get_review_queue(project_id=project_id, limit=None))

    return {
        "project": project,
        "project_id": project_id,
        "environments": environments,
        "asset_count": asset_count,
        "profiles": profiles,
        "recent_runs": recent_runs,
        "open_findings": open_findings,
        "pending_review": pending_review,
        "can_manage": is_manager(),
    }


# ── Project-scoped wrapper routes ──

@bp_web.route("/projects/<project_id>/assets")
@login_check
def project_assets(project_id):
    return redirect(url_for("web.rawdata", project_id=project_id))


@bp_web.route("/projects/<project_id>/knowledge/parameters")
@login_check
def project_knowledge_parameters(project_id):
    return redirect(url_for("web.parameter_priority", project_id=project_id))


@bp_web.route("/projects/<project_id>/knowledge/relations")
@login_check
def project_knowledge_relations(project_id):
    return redirect(url_for("web.parameter_relations", project_id=project_id))


@bp_web.route("/projects/<project_id>/knowledge/chains")
@login_check
def project_knowledge_chains(project_id):
    return redirect(url_for("web.interface_chains", project_id=project_id))


@bp_web.route("/projects/<project_id>/tests")
@login_check
def project_tests(project_id):
    return redirect(url_for("web.test_plans", project_id=project_id))


@bp_web.route("/projects/<project_id>/runs")
@login_check
def project_runs(project_id):
    return redirect(url_for("web.project_execution_center", project_id=project_id))


@bp_web.route("/projects/<project_id>/findings")
@login_check
def project_findings(project_id):
    return redirect(url_for("web.findings_list", project_id=project_id))


@bp_web.route("/projects/<project_id>/auth")
@login_check
def project_auth_page(project_id):
    return redirect(url_for("web.project_auth", project_id=project_id))


@bp_web.route("/projects/<project_id>/environments/<env_id>/auth")
@login_check
def project_env_auth(project_id, env_id):
    return redirect(url_for("web.project_auth", project_id=project_id, env_id=env_id))
