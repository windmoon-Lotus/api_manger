import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from flask import Flask, render_template
from apiAnalysis.web import bp_web


class ReadinessWebTests(unittest.TestCase):
    def setUp(self):
        self.app = Flask(__name__, template_folder=str(
            Path(__file__).resolve().parents[1] / "apiAnalysis" / "templates",
        ))
        self.app.secret_key = "synthetic-test"
        self.app.register_blueprint(bp_web)

    def test_blocked_execution_never_calls_scheduler(self):
        prefix = "apiAnalysis.web.views_test_plan."
        with self.app.test_client() as client:
            with client.session_transaction() as session:
                session["username"] = "synthetic-owner"
            with patch(prefix + "ApiProject") as projects, \
                    patch(prefix + "is_manager", return_value=True), \
                    patch(prefix + "_lifecycle_csrf_valid", return_value=True), \
                    patch(prefix + "get_plan", return_value=SimpleNamespace(project_id="p")), \
                    patch(prefix + "_readiness_for_plan", return_value={"status": "blocked"}), \
                    patch(prefix + "schedule_plan_execution") as schedule:
                projects.objects.return_value.order_by.return_value = []
                response = client.post("/test-plans", data={
                    "action": "execute", "project_id": "p", "plan_id": "synthetic",
                })
                self.assertEqual(response.status_code, 302)
                self.assertIn("readiness_plan_id=synthetic", response.location)
                schedule.assert_not_called()

    def test_readiness_renders_actions_and_escapes_content(self):
        with self.app.test_request_context("/test-plans"):
            html = render_template("test-plans.html", projects=[], plans=[],
                project_id="p", can_manage=False, notice=None,
                readiness_plan_name="<script>invalid</script>", readiness={
                    "status": "blocked", "blockers": [{
                        "message": "缺少认证方案", "action": "在项目环境与认证中补齐",
                    }], "warnings": [],
                })
        self.assertIn("在项目环境与认证中补齐", html)
        self.assertIn("不发送请求", html)
        self.assertNotIn("<script>invalid</script>", html)
