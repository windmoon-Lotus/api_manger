"""Run one explicit bounded auth verification and print only safe diagnostics."""
import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from apiAnalysis.db.collection import ProjectAuthProfile
from apiAnalysis.main import _ensure_mongo_connection
from apiAnalysis.tool.execution_scheduler import resume_auth_dependency
from apiAnalysis.tool.project_auth import verify_project_auth_profile


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile-id", default="")
    parser.add_argument("--project-id", default="")
    parser.add_argument("--env-id", default="")
    parser.add_argument("--max-requests", type=int, default=6)
    parser.add_argument("--resume-run-id", default="")
    args = parser.parse_args()
    _ensure_mongo_connection()
    query = {"active": True, "provider_id": "auth_recipe"}
    if args.profile_id:
        query["profile_id"] = args.profile_id
    if args.project_id:
        query["project_id"] = args.project_id
    if args.env_id:
        query["env_id"] = args.env_id
    profile = ProjectAuthProfile.objects(**query).order_by("-is_default", "name").first()
    if not profile:
        raise SystemExit("no matching active recipe auth profile")
    attempt = verify_project_auth_profile(
        profile.profile_id,
        max_requests=args.max_requests,
        timeout_seconds=10,
    )
    resumed_status = ""
    if attempt.status == "succeeded" and args.resume_run_id:
        run = resume_auth_dependency(args.resume_run_id, attempt.profile_revision_id)
        resumed_status = str(run.status or "") if run else "not_found"
    print(json.dumps({
        "attempt_id": attempt.attempt_id,
        "profile_id": attempt.profile_id,
        "profile_revision_id": attempt.profile_revision_id,
        "realm_revision_id": attempt.realm_revision_id,
        "adapter_version_id": attempt.adapter_version_id,
        "status": attempt.status,
        "stage": attempt.stage,
        "request_count": attempt.request_count,
        "max_requests": attempt.max_requests,
        "error_code": attempt.error_code or "",
        "error_summary": attempt.error_summary or "",
        "diagnostics": list(attempt.diagnostics or []),
        "resumed_run_status": resumed_status,
    }, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()
