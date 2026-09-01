import dataclasses
import json
import socket
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from apiAnalysis.rule.builtin_rules import parameter_occurrence_from_values
from apiAnalysis.rule.framework import EndpointFact
from apiAnalysis.rule.framework import EndpointClassificationCandidate, RuleMatch
from apiAnalysis.rule.p1_rules import (
    CrudPairCandidate,
    ParameterRoleCandidate,
    PrincipalScopeCandidate,
    ResourceChainCandidate,
    build_endpoint_pair_facts,
    build_principal_pair_facts,
    build_resource_chain_facts,
    load_p1_rule_specs,
    run_p1_rules,
)
from apiAnalysis.tool.test_plan import schedule_plan_execution
from apiAnalysis.tool.unified_rule_analysis import (
    UnifiedAnalysisResult, effective_endpoint_facts, endpoint_watermark_rows,
    persist_typed_outputs,
)


def locator(direction, name, position="body"):
    return {
        "version": 2, "direction": direction, "position": position,
        "kind": "schema", "schema_path": name, "canonical_name": name,
        "tokens": [{"kind": "property", "value": name, "dynamic": False}],
    }


def parameter(name, values, pathid=1, direction="request", position="body"):
    return parameter_occurrence_from_values(
        fact_id="{}:{}:{}".format(direction, pathid, name),
        project_id="project-a", env_id="test", endpoint_ref="endpoint:{}".format(pathid),
        pathid=pathid, direction=direction, canonical_name=name,
        parameter_type="string", required=True,
        locator=locator(direction, name, position), values=values,
    )


class P1RuleAnalysisTests(unittest.TestCase):
    def test_machine_classification_does_not_change_input_watermark_rows(self):
        before = EndpointFact(
            "endpoint:1", "project-a", "test", 1, "GET", "/items",
            action="Q_Path", classification_source="machine",
        )
        after = dataclasses.replace(before, action="endpoint.query")
        manual = dataclasses.replace(before, action="manual.special", classification_source="manual")
        self.assertEqual(endpoint_watermark_rows((before,)), endpoint_watermark_rows((after,)))
        self.assertNotEqual(endpoint_watermark_rows((before,)), endpoint_watermark_rows((manual,)))

    def test_downstream_rules_use_same_run_classification_output(self):
        endpoint = EndpointFact(
            "endpoint:1", "project-a", "test", 1, "POST", "/items",
            action="legacy-stale", classification_source="machine",
        )
        output = EndpointClassificationCandidate(
            endpoint_ref="endpoint:1", proposed_action="endpoint.create",
            legacy_action="C_Path", confidence=0.9, reason_codes=(),
            score_contributions=(), existing_action="legacy-stale", apply_allowed=True,
        )
        report = SimpleNamespace(matches=(SimpleNamespace(output=output),))
        effective = effective_endpoint_facts((endpoint,), (report,))
        self.assertEqual(effective[0].action, "endpoint.create")

    @patch("apiAnalysis.tool.unified_rule_analysis.endpoint_fact_from_document")
    @patch("apiAnalysis.tool.unified_rule_analysis.raw_data")
    def test_classification_persistence_uses_custom_primary_key(self, raw_model, project_fact):
        endpoint = SimpleNamespace(pk="custom-primary-key")
        project_fact.return_value = EndpointFact(
            "endpoint:7", "project-a", "test", 7, "GET", "/items",
            action="endpoint.query", classification_source="machine",
        )
        output = EndpointClassificationCandidate(
            endpoint_ref="endpoint:7", proposed_action="endpoint.query",
            legacy_action="Q_Path", confidence=0.9,
            reason_codes=("CLASSIFIED",), score_contributions=(),
            existing_action="endpoint.query", apply_allowed=True,
        )
        match = RuleMatch(
            rule_id="endpoint.classification", rule_version=1,
            rule_sha256="a" * 64, fact_refs=(("endpoint", "endpoint:7"),),
            score=0.9, reason_codes=("CLASSIFIED",), score_contributions=(),
            output=output,
        )
        result = UnifiedAnalysisResult(
            project_id="project-a", env_id="test", profile_id="",
            profile_revision_id="", input_watermark_sha256="b" * 64,
            rule_bundle_sha256="c" * 64,
            endpoint_documents={7: endpoint}, parameter_documents={},
            relation_facts={}, reports=(), matches=(match,), summary={},
        )
        persisted = persist_typed_outputs(result)
        raw_model.objects.assert_called_once_with(pk="custom-primary-key")
        self.assertEqual(persisted["classification_upserted"], 1)

    @patch("apiAnalysis.tool.test_plan.get_plan")
    def test_rule_generated_draft_cannot_execute_even_if_activated(self, get_plan):
        get_plan.return_value = SimpleNamespace(
            status="draft", adapter_id="rule_plan_draft_only",
            scope={"execution_allowed": False},
        )
        with self.assertRaisesRegex(ValueError, "not executable"):
            schedule_plan_execution("synthetic-plan")

    def test_p1_specs_are_versioned_offline_and_deterministic(self):
        first = load_p1_rule_specs()
        second = load_p1_rule_specs()
        self.assertEqual(len(first), 4)
        self.assertEqual(
            [(item.rule_id, item.canonical_sha256()) for item in first],
            [(item.rule_id, item.canonical_sha256()) for item in second],
        )
        self.assertTrue(all(item.safety.network == "forbidden" for item in first))
        self.assertTrue(all(item.safety.mutation == "forbidden" for item in first))

    @patch.object(socket, "create_connection", side_effect=AssertionError("network attempted"))
    def test_p1_rule_engine_performs_no_network_access(self, connect):
        run_p1_rules(parameters=(parameter("resource_id", ["resource-1"]),))
        connect.assert_not_called()

    def test_parameter_roles_filter_context_values_and_keep_resources(self):
        parameters = (
            parameter("nonce", ["one"]),
            parameter("page", [1]),
            parameter("status", [0, 1]),
            parameter("device_id", ["device-1"]),
        )
        reports = run_p1_rules(parameters=parameters)
        outputs = {
            match.output.canonical_name: match.output
            for report in reports for match in report.matches
            if isinstance(match.output, ParameterRoleCandidate)
        }
        self.assertEqual(outputs["nonce"].role, "dynamic")
        self.assertEqual(outputs["page"].role, "pagination_filter")
        self.assertEqual(outputs["status"].role, "generic_enum")
        self.assertEqual(outputs["device_id"].role, "resource")
        self.assertFalse(outputs["nonce"].relation_eligible)
        self.assertTrue(outputs["device_id"].relation_eligible)
        serialized = json.dumps(dataclasses.asdict(outputs["device_id"]), sort_keys=True)
        self.assertNotIn("device-1", serialized)

    def test_crud_and_parent_child_candidates_are_typed_not_verified(self):
        endpoints = (
            EndpointFact("endpoint:list", "project-a", "test", 1, "GET", "/orgs/{org_id}/devices"),
            EndpointFact("endpoint:create", "project-a", "test", 2, "POST", "/orgs/{org_id}/devices"),
            EndpointFact("endpoint:detail", "project-a", "test", 3, "GET", "/orgs/{org_id}/devices/{device_id}"),
            EndpointFact("endpoint:org", "project-a", "test", 4, "GET", "/orgs/{org_id}"),
        )
        pairs = build_endpoint_pair_facts(endpoints)
        chains = build_resource_chain_facts(endpoints)
        reports = run_p1_rules(endpoint_pairs=pairs, resource_chains=chains)
        crud = [
            match.output for report in reports for match in report.matches
            if isinstance(match.output, CrudPairCandidate)
        ]
        resources = [
            match.output for report in reports for match in report.matches
            if isinstance(match.output, ResourceChainCandidate)
        ]
        self.assertTrue(any({item.left_pathid, item.right_pathid} == {1, 2} for item in crud))
        self.assertTrue(any(item.parent_pathid == 4 and item.child_pathid in {1, 2, 3} for item in resources))
        self.assertTrue(all(not item.verified and item.dry_run for item in crud + resources))

    def test_principal_pairs_emit_profile_scope_and_rank_relations(self):
        principals = (
            {"principal_id": "owner", "project_id": "project-a", "env_id": "test",
             "profile_revision_id": "profile-owner", "scope_key": "tenant-a", "privilege_rank": 100},
            {"principal_id": "member", "project_id": "project-a", "env_id": "test",
             "profile_revision_id": "profile-member", "scope_key": "tenant-a", "privilege_rank": 10},
            {"principal_id": "external", "project_id": "project-a", "env_id": "test",
             "profile_revision_id": "profile-external", "scope_key": "tenant-b", "privilege_rank": 10},
        )
        facts = build_principal_pair_facts(principals)
        reports = run_p1_rules(principal_pairs=facts)
        outputs = [
            match.output for report in reports for match in report.matches
            if isinstance(match.output, PrincipalScopeCandidate)
        ]
        owner_member = {
            item.relation_kind for item in outputs
            if item.source_principal_id == "owner" and item.target_principal_id == "member"
        }
        member_external = {
            item.relation_kind for item in outputs
            if item.source_principal_id == "member" and item.target_principal_id == "external"
        }
        self.assertEqual(owner_member, {"same_scope", "higher_privilege"})
        self.assertEqual(member_external, {"different_scope", "peer"})
        self.assertTrue(all(not item.verified for item in outputs))


if __name__ == "__main__":
    unittest.main()
