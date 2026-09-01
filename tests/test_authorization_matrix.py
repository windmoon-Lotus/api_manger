import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock

from apiAnalysis.tool.authorization_matrix import (
    build_authorization_matrix_adapter,
    judge_authorization_matrix,
    observe_authorization_decision,
)
from apiAnalysis.tool.authorization_policy import (
    AuthorizationMatrixBudgetExceeded,
    authorization_relation_descriptor,
    expand_authorization_matrix,
    resolve_authorization_expectation,
    selector_matches,
)
from apiAnalysis.tool.execution_adapter import adapter_registry
from apiAnalysis.tool.execution_scheduler import ExecutionWorker


def principal(principal_id, role, rank, scope, *, labels=(), attributes=None):
    return {
        "principal_id": principal_id,
        "profile_id": "profile-" + principal_id,
        "account_key": "account-" + principal_id,
        "role_key": role,
        "privilege_rank": rank,
        "scope_key": scope,
        "labels": list(labels),
        "attributes": dict(attributes or {}),
        "active": True,
    }


def rule(rule_id, priority, expected, *, subject=None, owner=None, scope="any"):
    return SimpleNamespace(
        rule_id=rule_id,
        priority=priority,
        expected_decision=expected,
        subject_selector=subject or {},
        owner_selector=owner or {},
        scope_relation=scope,
        resource_family="orders",
        action="read",
        reason_codes=[rule_id],
        active=True,
    )


class AuthorizationPolicyTests(unittest.TestCase):
    def setUp(self):
        self.principals = [
            principal("admin", "administrator", 100, "global", labels=["staff"]),
            principal("manager-a", "manager", 60, "department-a", labels=["staff"]),
            principal(
                "member-a", "member", 20, "department-a",
                labels=["staff"], attributes={"employment": "internal"},
            ),
            principal("guest-b", "guest", 0, "department-b", labels=["external"]),
        ]
        self.policy = SimpleNamespace(
            policy_key="orders-access",
            policy_version_id="orders-access-v3",
            version=3,
            principal_ids=[item["principal_id"] for item in self.principals],
            include_self=False,
            case_budget=12,
            request_budget_per_case=3,
            default_decision="deny",
            same_principal_decision="allow",
            action="read",
        )
        self.rules = [
            rule(
                "administrators-read-all", 300, "allow",
                subject={"min_privilege_rank": 90, "labels_all": ["staff"]},
            ),
            rule(
                "managers-read-same-scope", 200, "allow",
                subject={"role_keys": ["manager"]}, scope="same",
            ),
        ]

    def test_selector_combines_role_rank_scope_labels_and_attributes(self):
        self.assertTrue(selector_matches({
            "role_keys": ["member"],
            "min_privilege_rank": 10,
            "max_privilege_rank": 30,
            "scope_keys": ["department-a"],
            "labels_all": ["staff"],
            "attributes": {"employment": "internal"},
        }, self.principals[2]))
        self.assertFalse(selector_matches({"labels_any": ["external"]}, self.principals[2]))
        with self.assertRaisesRegex(ValueError, "sensitive field"):
            selector_matches({"attributes": {"access_token": "not-persistable"}}, self.principals[2])

    def test_expectations_are_rule_driven_not_rank_only(self):
        admin_cross_scope = resolve_authorization_expectation(
            self.policy, self.rules, self.principals[3], self.principals[0],
            resource_family="orders", action="read",
        )
        manager_same_scope = resolve_authorization_expectation(
            self.policy, self.rules, self.principals[2], self.principals[1],
            resource_family="orders", action="read",
        )
        manager_cross_scope = resolve_authorization_expectation(
            self.policy, self.rules, self.principals[3], self.principals[1],
            resource_family="orders", action="read",
        )
        self.assertEqual(admin_cross_scope["expected_decision"], "allow")
        self.assertEqual(manager_same_scope["matched_rule_id"], "managers-read-same-scope")
        self.assertEqual(manager_cross_scope["expected_decision"], "deny")

    def test_four_principals_expand_to_complete_ordered_matrix(self):
        cases = expand_authorization_matrix(
            self.policy,
            self.principals,
            self.rules,
            [{
                "resource_key": "10:20",
                "relation_ids": ["r1", "r2"],
                "resource_family": "orders",
                "action": "read",
            }],
        )
        self.assertEqual(len(cases), 12)
        self.assertEqual(len({case.case_key for case in cases}), 12)
        self.assertIn(
            ("guest-b", "admin"),
            {
                (case.owner["principal_id"], case.subject["principal_id"])
                for case in cases
            },
        )

    def test_matrix_accepts_arbitrary_project_defined_levels(self):
        principals = [
            principal(
                "level-{}".format(level),
                "project-role-{}".format(level),
                level * 10,
                "scope-{}".format(level % 3),
                attributes={"business_level": level},
            )
            for level in range(1, 8)
        ]
        policy = SimpleNamespace(
            policy_key="custom-levels",
            policy_version_id="custom-levels-v1",
            version=1,
            principal_ids=[item["principal_id"] for item in principals],
            include_self=False,
            case_budget=42,
            request_budget_per_case=3,
            default_decision="review",
            same_principal_decision="allow",
            action="read",
        )

        cases = expand_authorization_matrix(
            policy, principals, [], [{
                "resource_key": "custom-resource",
                "relation_ids": ["r1"],
                "resource_family": "custom",
                "action": "read",
            }],
        )

        self.assertEqual(len(cases), 7 * 6)
        self.assertEqual(
            {case.owner["privilege_rank"] for case in cases},
            {10, 20, 30, 40, 50, 60, 70},
        )

    def test_matrix_budget_fails_closed_without_truncation(self):
        self.policy.case_budget = 11
        with self.assertRaises(AuthorizationMatrixBudgetExceeded) as raised:
            expand_authorization_matrix(
                self.policy,
                self.principals,
                self.rules,
                [{
                    "resource_key": "10:20", "relation_ids": ["r1"],
                    "resource_family": "orders", "action": "read",
                }],
            )
        self.assertEqual(raised.exception.required_cases, 12)

    def test_relation_descriptor_detects_locator_drift(self):
        relation = SimpleNamespace(
            id="r1", project_id="p1", env_id="test", res_pathid=10, req_pathid=20,
            parameter="id", source_parameter="items[].id", target_parameter="id",
            source_locator={"json_pointer": "/items/*/id"},
            target_locator={"json_pointer": "/id"}, target_position="body",
            schema_fingerprint="schema-v1",
        )
        original = authorization_relation_descriptor(relation)
        relation.target_locator = {"json_pointer": "/resource/id"}
        changed = authorization_relation_descriptor(relation)
        self.assertNotEqual(original["relation_sha256"], changed["relation_sha256"])


class AuthorizationJudgeTests(unittest.TestCase):
    @staticmethod
    def evidence(expected, consumer_status, matches=0, fields=1):
        return {
            "source_status_code": 200,
            "consumer_status_code": consumer_status,
            "authorization_expected_decision": expected,
            "authorization_resource_match_count": matches,
            "authorization_resource_field_count": fields,
        }

    def test_denied_cell_disclosing_owner_resource_is_candidate(self):
        evidence = self.evidence("deny", 200, matches=1)
        self.assertEqual(observe_authorization_decision(evidence), "allow")
        verdict, reasons, confidence = judge_authorization_matrix(
            evidence, "authorization_matrix", "matrix",
        )
        self.assertEqual(verdict, "potential_vuln")
        self.assertIn("authorization_policy_denied_but_resource_disclosed", reasons)
        self.assertGreater(confidence, 0.9)

    def test_denied_cell_blocked_by_server_is_not_vulnerable(self):
        verdict, _, _ = judge_authorization_matrix(
            self.evidence("deny", 403), "authorization_matrix", "matrix",
        )
        self.assertEqual(verdict, "no_vuln")

    def test_expected_access_block_is_a_regression_for_review(self):
        verdict, reasons, _ = judge_authorization_matrix(
            self.evidence("allow", 404), "authorization_matrix", "matrix",
        )
        self.assertEqual(verdict, "need_review")
        self.assertIn("authorization_expected_access_blocked", reasons)

    def test_malformed_transport_status_is_inconclusive_not_an_exception(self):
        evidence = self.evidence("deny", "not-a-status")
        self.assertEqual(observe_authorization_decision(evidence), "unknown")
        verdict, reasons, _ = judge_authorization_matrix(
            evidence, "authorization_matrix", "matrix",
        )
        self.assertEqual(verdict, "need_review")
        self.assertIn("authorization_denial_response_inconclusive", reasons)

    def test_matrix_adapter_is_registered_without_one_run_account(self):
        adapter = build_authorization_matrix_adapter(MagicMock())
        registry = adapter_registry([adapter])
        run = SimpleNamespace(
            adapter_id="authorization_matrix", adapter_version="1", auth_mode="matrix",
        )
        registry["authorization_matrix"].validate(run)
        self.assertFalse(adapter.requires_account_context)

    def test_execution_worker_registers_matrix_and_relation_adapters(self):
        worker = ExecutionWorker(account_context_resolver=MagicMock())
        self.assertIn("authorization_matrix", worker.adapters)
        self.assertIn("parameter_relation_validation", worker.adapters)
        self.assertEqual(
            worker.adapters["authorization_matrix"].auth_modes,
            frozenset({"matrix"}),
        )


if __name__ == "__main__":
    unittest.main()
