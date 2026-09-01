import unittest
from pathlib import Path
from types import SimpleNamespace

from bson import ObjectId
from flask import Flask, render_template

from apiAnalysis.web import bp_web


class TestPlanTemplateTests(unittest.TestCase):
    def test_active_plan_has_csrf_protected_one_click_execution(self):
        root = Path(__file__).resolve().parents[1] / "apiAnalysis"
        app = Flask(
            __name__,
            template_folder=str(root / "templates"),
            static_folder=str(root / "static"),
        )
        app.secret_key = "test-plan-template"
        app.register_blueprint(bp_web)
        plan = SimpleNamespace(
            id=ObjectId(),
            name="Owner baseline",
            version=2,
            status="active",
            env_id="test",
            scope={"pathids": [42]},
            request_budget=1,
            check_type="snapshot_baseline",
            auth_mode="account",
            auth_profile_id="profile-1",
            ctime=None,
        )
        with app.test_request_context("/test-plans?project_id=project-1"):
            html = render_template(
                "test-plans.html",
                projects=[SimpleNamespace(
                    project_id="project-1", name="Project 1",
                )],
                project_id="project-1",
                plans=[plan],
                environments=[SimpleNamespace(env_id="test", name="Test")],
                auth_profiles=[SimpleNamespace(
                    profile_id="profile-1",
                    name="Owner",
                    env_id="test",
                    account_key="owner",
                )],
                status_filter="",
                check_type_filter="",
                notice=None,
                can_manage=True,
                csrf_token="csrf-plan-token",
                plan_statuses=["draft", "active", "archived"],
            )

        self.assertIn('name="action" value="execute"', html)
        self.assertIn("一键执行", html)
        self.assertIn('name="pathids"', html)
        self.assertIn('name="auth_profile_id"', html)
        self.assertGreaterEqual(
            html.count('name="csrf_token" value="csrf-plan-token"'),
            4,
        )


if __name__ == "__main__":
    unittest.main()
