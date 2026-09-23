import unittest
from types import SimpleNamespace as NS
from apiAnalysis.tool.plan_readiness import assess_plan_readiness


class PlanReadinessTests(unittest.TestCase):
    def setUp(self):
        self.plan = NS(project_id="p", env_id="test", status="active", scope={"pathids": [1]},
            snapshot_filter={}, request_budget=1, auth_mode="account", auth_profile_id="a",
            adapter_id="authenticated_snapshot_batch", adapter_version="1", check_type="baseline")
        self.env = NS(project_id="p", env_id="test", active=True)
        self.profile = NS(project_id="p", env_id="test", active=True, lifecycle="active")
        self.asset = NS(ptah_id=1, project_id="p", env_id="test", method="GET")

    def check(self):
        return assess_plan_readiness(self.plan, [self.asset], self.env, self.profile)

    def test_static_pass_never_claims_live_success(self):
        result = self.check()
        self.assertEqual(result["status"], "preflight_only")
        self.assertEqual({r["code"] for r in result["warnings"]}, {"judge_required", "live_baseline_unverified"})

    def test_draft_flag_blocks_even_active_plan(self):
        self.plan.scope["execution_allowed"] = False
        self.assertEqual(self.check()["status"], "blocked")

    def test_each_invalid_context_blocks(self):
        for obj, field, value in [
            (self.env, "active", False), (self.profile, "env_id", "other"),
            (self.asset, "project_id", "other"), (self.asset, "method", "POST"),
            (self.plan, "adapter_version", "2"), (self.plan, "auth_mode", "anonymous"),
        ]:
            with self.subTest(field=field):
                old = getattr(obj, field)
                setattr(obj, field, value)
                self.assertEqual(self.check()["status"], "blocked")
                setattr(obj, field, old)

    def test_missing_assets_and_invalid_scope(self):
        self.assertEqual(assess_plan_readiness(self.plan, [], self.env, self.profile)["status"], "blocked")
        self.plan.scope = {"pathids": ["secret-invalid"]}
        result = self.check()
        self.assertEqual(result["status"], "blocked")
        self.assertNotIn("secret-invalid", str(result))
