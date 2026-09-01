import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from apiAnalysis.tool.parameter_validation import (
    LargeValidationApprovalRequired,
    select_ready_validation_batch,
)
from apiAnalysis.tool.parameter_relation_workbench import (
    _validation_view,
    environment_execution_policy,
    host_candidates,
    infer_environment_type,
    reason_view,
    relation_request_estimate,
)


class ParameterRelationWorkbenchTests(unittest.TestCase):
    def test_legacy_explicit_400_uses_untried_hosts_without_approval_semantics(self):
        result = SimpleNamespace(
            status="source_request_rejected",
            source_result={
                "status_code": 400,
                "remaining_host_count": 7,
                "approval_stage": "source",
                "error_summary": {
                    "error_code": "parameter/error",
                    "explicit_business_rejection": True,
                },
                "attempts": [],
            },
            consumer_result={},
            run_id="run-1",
            source_host="api.test",
            consumer_host="",
            ctime=None,
        )

        view = _validation_view(result)

        self.assertEqual(view["status"], "source_request_rejected")
        self.assertEqual(view["remaining_host_count"], 0)
        self.assertEqual(view["untried_host_count"], 7)
        self.assertEqual(view["approval_stage"], "")

    def test_request_estimate_separates_read_and_mutation(self):
        self.assertEqual(relation_request_estimate("GET"), 2)
        self.assertEqual(relation_request_estimate("DELETE"), 3)
        self.assertEqual(relation_request_estimate("PATCH"), 3)

    def test_mutation_requires_explicit_test_or_preprod_policy(self):
        test_env = SimpleNamespace(
            environment_type="test", allow_mutation=True, auto_request_limit=9,
            env_id="test", name="Test", default_host="api.test",
            hosts=[{"host": "api.test", "base_url": "https://api.test"}], metadata={},
        )
        policy = environment_execution_policy(test_env)
        self.assertTrue(policy["allow_mutation"])
        self.assertEqual(policy["auto_request_limit"], 9)
        self.assertEqual(policy["approved_request_limit"], 1000)
        self.assertFalse(policy["hard_limited"])

        production = SimpleNamespace(
            environment_type="production", allow_mutation=True, auto_request_limit=99,
            env_id="formal", name="Formal", default_host="api.example.com",
            hosts=[], metadata={},
        )
        production_policy = environment_execution_policy(production)
        self.assertFalse(production_policy["allow_mutation"])
        self.assertEqual(production_policy["auto_request_limit"], 3)
        self.assertEqual(production_policy["approved_request_limit"], 3)
        self.assertTrue(production_policy["hard_limited"])

    def test_environment_type_can_be_inferred_from_preproduction_host(self):
        environment = SimpleNamespace(
            environment_type="unknown", env_id="default", name="Default",
            default_host="api.preprod.example.test", hosts=[], metadata={},
        )
        self.assertEqual(infer_environment_type(environment), "preprod")

    def test_exact_endpoint_host_is_ranked_before_environment_default(self):
        endpoint = SimpleNamespace(domain="api-write.test", url="https://api-write.test/items")
        environment = SimpleNamespace(
            default_host="api-default.test",
            hosts=[
                {"host": "api-default.test", "base_url": "https://api-default.test"},
                {"host": "api-write.test", "base_url": "https://api-write.test"},
            ],
        )
        profile = SimpleNamespace(allowed_hosts=["api-default.test", "api-write.test"])
        rows = host_candidates(endpoint, environment, profile)
        self.assertEqual(rows[0]["host"], "api-write.test")
        self.assertTrue(rows[0]["exact"])

    def test_legacy_404_is_explained_as_host_evidence_not_relation_rejection(self):
        view = reason_view("UPSTREAM_HTTP_404")
        self.assertIn("Host", view["detail"])
        self.assertIn("不代表参数关系错误", view["detail"])

    @patch("apiAnalysis.tool.parameter_validation.ProjectRequestFixture.objects")
    @patch("apiAnalysis.tool.parameter_validation.parameter_validation_result.objects")
    @patch("apiAnalysis.tool.parameter_validation.mutation_execution_allowed", return_value=True)
    @patch("apiAnalysis.tool.parameter_validation.raw_data.objects")
    @patch("apiAnalysis.tool.parameter_validation.parameter_relation.objects")
    def test_batch_selection_reserves_hard_total_budget_and_skips_mutations_by_default(
        self, relation_objects, endpoint_objects, _mutation_allowed,
        validation_result_objects, fixture_objects,
    ):
        def relation(index, method):
            return SimpleNamespace(
                id="r{}".format(index),
                project_id="p1",
                res_pathid=100 + index,
                req_pathid=200 + index,
                source_locator={"tokens": [{"kind": "property", "value": "id"}]},
                target_locator={"tokens": [{"kind": "property", "value": "id"}]},
                location_status="resolved",
                machine_confidence=1.0 - index / 100.0,
                method=method,
            )

        rows = [relation(1, "GET"), relation(2, "GET"), relation(3, "DELETE")]
        relation_query = MagicMock()
        relation_query.order_by.return_value = rows
        relation_objects.return_value = relation_query
        endpoint_query = MagicMock()
        endpoints = []
        for row in rows:
            endpoints.extend([
                SimpleNamespace(
                    ptah_id=row.res_pathid,
                    method="GET",
                    path="/source/{}".format(row.res_pathid),
                    domain="source.invalid",
                    url="",
                ),
                SimpleNamespace(
                    ptah_id=row.req_pathid,
                    method=row.method,
                    path="/consumer/{}".format(row.req_pathid),
                    domain="consumer.invalid",
                    url="",
                ),
            ])
        endpoint_query.only.return_value = endpoints
        endpoint_objects.return_value = endpoint_query
        validation_query = MagicMock()
        validation_query.only.return_value.order_by.return_value = []
        validation_result_objects.return_value = validation_query
        fixture_query = MagicMock()
        fixture_query.only.return_value = []
        fixture_objects.return_value = fixture_query
        environment = SimpleNamespace(
            env_id="test",
            environment_type="test",
            allow_mutation=True,
            auto_request_limit=9,
            metadata={},
        )
        source_profile = SimpleNamespace(
            project_id="p1", env_id="test", profile_id="source-profile",
        )
        consumer_profile = SimpleNamespace(
            project_id="p1", env_id="test", profile_id="consumer-profile",
        )

        selection = select_ready_validation_batch(
            "p1",
            source_profile,
            consumer_profile,
            environment,
            total_request_budget=6,
            include_mutations=False,
        )

        self.assertEqual(selection["pair_count"], 2)
        self.assertEqual(selection["reserved_requests"], 6)
        self.assertEqual(selection["read_pair_count"], 2)
        self.assertEqual(selection["mutation_pair_count"], 0)
        self.assertEqual(selection["skipped_mutation_pair_count"], 1)
        self.assertEqual(
            [item["pair_key"] for item in selection["pairs"]],
            ["101:201", "102:202"],
        )
        self.assertEqual(selection["pairs"][0]["source_path"], "/source/101")
        self.assertEqual(selection["pairs"][0]["consumer_path"], "/consumer/201")
        self.assertEqual(
            relation_objects.call_args.kwargs.get("preprocess_status"),
            "auto_ready",
        )
        self.assertNotIn(
            "preprocess_status__in",
            relation_objects.call_args.kwargs,
        )

    @patch("apiAnalysis.tool.parameter_validation.parameter_relation.objects")
    def test_batch_selection_requires_explicit_approval_above_automatic_limit(
        self, _relation_objects,
    ):
        environment = SimpleNamespace(
            env_id="test",
            environment_type="test",
            allow_mutation=False,
            auto_request_limit=3,
            metadata={},
        )
        profile = SimpleNamespace(project_id="p1", env_id="test")
        with self.assertRaises(LargeValidationApprovalRequired):
            select_ready_validation_batch(
                "p1",
                profile,
                profile,
                environment,
                total_request_budget=30,
                approved_large_run=False,
            )


if __name__ == "__main__":
    unittest.main()
