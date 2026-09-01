import dataclasses
import json
import socket
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from apiAnalysis.rule.analysis import analysis
from apiAnalysis.rule.builtin_rules import (
    builtin_engine,
    endpoint_fact_from_document,
    legacy_relation_outcome,
    load_builtin_rule_specs,
    parameter_occurrence_from_document,
    parameter_occurrence_from_values,
    run_builtin_p0,
)
from apiAnalysis.rule.framework import (
    EndpointFact,
    OfflineRuleEngine,
    OutputAdapterRegistry,
    PredicateRegistry,
    RuleBudgetExceeded,
    RuleProtocolError,
    RuleSpec,
    UnknownPredicate,
)
from apiAnalysis.rule.legacy_scoring import (
    classify_endpoint_with_score,
    score_weak_relation,
)
from apiAnalysis.rule.shadow_evaluation import (
    ShadowEvaluationError,
    ShadowLimits,
    ShadowProjection,
    build_shadow_report,
    load_shadow_projection,
)


CORPUS_PATH = Path(__file__).with_name("fixtures") / "abstract_rule_p0_corpus.json"


def load_corpus():
    raw = json.loads(CORPUS_PATH.read_text(encoding="utf-8"))
    endpoints = tuple(
        EndpointFact(
            fact_id=item["fact_id"],
            project_id=item["project_id"],
            env_id=item["env_id"],
            pathid=item["pathid"],
            method=item["method"],
            path_template=item["path_template"],
            action=item.get("action", ""),
            classification_source=item.get("classification_source", "none"),
            has_request_body=item.get("has_request_body", False),
            response_status_codes=tuple(item.get("response_status_codes", ())),
        )
        for item in raw["endpoints"]
    )
    parameters = []
    for item in raw["parameters"]:
        locator = {
            "version": 2,
            "direction": item["direction"],
            "position": item["position"],
            "kind": "parameter" if item["position"] != "body" else "instance",
            "schema_path": item["canonical_name"],
            "canonical_name": item["canonical_name"],
            "tokens": [{"kind": "property", "value": item["canonical_name"], "dynamic": False}],
        }
        parameters.append(parameter_occurrence_from_values(
            fact_id=item["fact_id"],
            project_id=item["project_id"],
            env_id=item["env_id"],
            endpoint_ref=item["endpoint_ref"],
            pathid=item["pathid"],
            direction=item["direction"],
            canonical_name=item["canonical_name"],
            parameter_type=item["parameter_type"],
            required=False,
            locator=locator,
            values=item["values"],
            principal_id=item["principal_id"],
            profile_revision_id=item["profile_revision_id"],
            scope_key=item["scope_key"],
        ))
    return raw, endpoints, tuple(parameters)


def outputs_by_relation(reports):
    result = {}
    for report in reports:
        for match in report.matches:
            output = match.output
            relation = getattr(output, "relation", "")
            if relation:
                result.setdefault(relation, []).append(output)
    return result


class FakeQuerySet:
    def __init__(self, rows):
        self.rows = list(rows)

    def count(self):
        return len(self.rows)

    def order_by(self, *_):
        return self

    def __iter__(self):
        return iter(self.rows)


class AbstractRuleFrameworkTests(unittest.TestCase):
    def setUp(self):
        self.raw, self.endpoints, self.parameters = load_corpus()

    def test_builtin_rules_are_json_versioned_and_deterministic(self):
        first = load_builtin_rule_specs()
        second = load_builtin_rule_specs()
        self.assertEqual(
            [(item.rule_id, item.version, item.canonical_sha256()) for item in first],
            [(item.rule_id, item.version, item.canonical_sha256()) for item in second],
        )
        self.assertEqual(len(first), 4)
        self.assertTrue(all(item.safety.network == "forbidden" for item in first))
        self.assertTrue(all(item.safety.mutation == "forbidden" for item in first))

    def test_endpoint_adapter_preserves_legacy_classification_semantics(self):
        reports = run_builtin_p0(self.endpoints, ())
        outputs = {
            match.output.endpoint_ref: match.output
            for report in reports for match in report.matches
            if hasattr(match.output, "proposed_action")
        }
        for endpoint in self.endpoints:
            legacy_action, legacy_confidence, _ = classify_endpoint_with_score(endpoint)
            self.assertEqual(outputs[endpoint.fact_id].legacy_action, legacy_action)
            self.assertEqual(outputs[endpoint.fact_id].confidence, legacy_confidence / 100.0)
        self.assertEqual(outputs["endpoint-list-users"].proposed_action, "endpoint.query")
        self.assertEqual(outputs["endpoint-create-user"].proposed_action, "endpoint.create")
        self.assertTrue(outputs["endpoint-list-users"].score_contributions)

    def test_existing_analysis_methods_delegate_without_score_drift(self):
        legacy_object = SimpleNamespace(
            method="POST", path="/v1/users/create", raw_req=[{"name": "synthetic"}],
            response_status_code=[201],
        )
        self.assertEqual(
            analysis().classify_with_score(legacy_object),
            classify_endpoint_with_score(legacy_object),
        )
        self.assertEqual(
            analysis()._score_weak_relation("user_id", 1, 1, 2),
            score_weak_relation("user_id", 1, 1, 2),
        )

    def test_loaded_domain_documents_project_to_value_free_facts(self):
        endpoint_document = SimpleNamespace(
            ptah_id=900, project_id="project-a", env_id="test", method="GET",
            path="/v1/resources/{resource_id}", action="Q_Path", rule="path_score_v1",
            raw_req=[], response_status_code=[200],
        )
        endpoint = endpoint_fact_from_document(endpoint_document)
        self.assertEqual(endpoint.classification_source, "machine")
        parameter_document = SimpleNamespace(
            id="synthetic-occurrence", raw_data=endpoint_document, direction="response",
            canonical_name="resource_id", parameter="items[].resource_id", type="string",
            required=False, value=["private-value-not-retained"], locator={
                "version": 2, "direction": "response", "position": "body", "kind": "schema",
                "schema_path": "items[].resource_id", "canonical_name": "resource_id",
                "tokens": [
                    {"kind": "property", "value": "items", "dynamic": False},
                    {"kind": "array", "index": 0, "wildcard": True},
                    {"kind": "property", "value": "resource_id", "dynamic": False},
                ],
            },
        )
        fact = parameter_occurrence_from_document(
            parameter_document, profile_revision_id="profile-revision-a",
        )
        self.assertEqual(fact.category, "resource")
        self.assertNotIn("private-value-not-retained", repr(fact))
        self.assertEqual(len(fact.observation.value_digests[0]), 64)

    def test_manual_endpoint_classification_is_never_overwritten(self):
        reports = run_builtin_p0(self.endpoints, ())
        manual = next(
            match.output for report in reports for match in report.matches
            if getattr(match.output, "endpoint_ref", "") == "endpoint-manual-action"
        )
        self.assertFalse(manual.apply_allowed)
        self.assertTrue(manual.dry_run)
        self.assertIn("EXISTING_CLASSIFICATION_PRESERVED", manual.reason_codes)

    def test_same_name_with_overlap_only_emits_weak_candidate(self):
        relations = outputs_by_relation(run_builtin_p0((), self.parameters))
        expected = next(
            item for item in relations["weak_candidate"]
            if item.producer_ref == "response-user-id" and item.consumer_ref == "request-user-id-overlap"
        )
        self.assertFalse(expected.verified)
        self.assertEqual(expected.write_disposition, "create_only")
        self.assertGreater(expected.confidence, 0.0)

    def test_empty_intersection_is_insufficient_evidence_not_not_equal(self):
        relations = outputs_by_relation(run_builtin_p0((), self.parameters))
        empty = next(
            item for item in relations["insufficient_evidence"]
            if item.producer_ref == "response-object-id-same-endpoint"
            and item.consumer_ref == "request-object-id-same-endpoint"
        )
        facts = {item.fact_id: item for item in self.parameters}
        legacy = legacy_relation_outcome(
            facts["response-object-id-same-endpoint"], facts["request-object-id-same-endpoint"],
        )
        self.assertEqual(legacy["relation"], "not_equal")
        self.assertEqual(empty.relation, "insufficient_evidence")
        self.assertEqual(empty.confidence, 0.0)
        self.assertFalse(empty.verified)

    @patch("apiAnalysis.rule.analysis.parameter_relation")
    @patch("apiAnalysis.rule.analysis.parameter_data")
    def test_legacy_import_inference_counts_empty_intersection_without_writing_not_equal(
        self, parameter_model, relation_model,
    ):
        parameter_model.objects.return_value = [SimpleNamespace(
            parameter="object_id",
            req_pathid=[107],
            res_pathid=[107],
            req_value=["synthetic-object-a"],
            res_value=["synthetic-object-b"],
        )]

        summary = analysis().infer_weak_relations(pathids=[107])

        self.assertEqual(summary["insufficient_evidence_pairs"], 1)
        self.assertEqual(summary["accepted_candidates"], 0)
        relation_model.objects.assert_not_called()
        relation_model.assert_not_called()

    def test_different_name_same_value_is_alias_candidate(self):
        relations = outputs_by_relation(run_builtin_p0((), self.parameters))
        alias = next(
            item for item in relations["alias_candidate"]
            if item.producer_ref == "response-user-id" and item.consumer_ref == "request-account-id-alias"
        )
        self.assertFalse(alias.verified)
        self.assertIn("PARAMETER_ALIAS_CANDIDATE", alias.reason_codes)

    def test_dynamic_parameter_is_classified_but_not_a_resource_relation(self):
        facts = {item.fact_id: item for item in self.parameters}
        self.assertEqual(facts["response-nonce"].category, "dynamic")
        reports = run_builtin_p0((), self.parameters)
        relation_pairs = {
            (match.output.producer_ref, match.output.consumer_ref)
            for report in reports for match in report.matches
            if hasattr(match.output, "producer_ref")
        }
        self.assertNotIn(("response-nonce", "request-nonce"), relation_pairs)
        rejected = dict(next(
            report.rejection_counts for report in reports
            if report.rule_id == "parameter.shared_value.weak_relation"
        ))
        self.assertGreater(rejected.get("PARAMETER_CONTEXT_ONLY", 0), 0)

    def test_cross_project_and_profile_contexts_are_isolated(self):
        reports = run_builtin_p0((), self.parameters)
        relation_pairs = {
            (match.output.producer_ref, match.output.consumer_ref)
            for report in reports for match in report.matches
            if hasattr(match.output, "producer_ref")
        }
        self.assertNotIn(("response-user-id", "request-user-id-cross-project"), relation_pairs)
        weak_report = next(
            report for report in reports if report.rule_id == "parameter.shared_value.weak_relation"
        )
        self.assertGreater(dict(weak_report.rejection_counts).get("SCOPE_PROJECT_MISMATCH", 0), 0)

    def test_rule_outputs_do_not_contain_observed_values(self):
        reports = run_builtin_p0(self.endpoints, self.parameters)
        serialized = json.dumps(dataclasses.asdict(reports[0]), ensure_ascii=False, sort_keys=True)
        for raw_value in (
            "synthetic-resource-42", "synthetic-resource-43", "synthetic-resource-99",
            "synthetic-nonce-123456", "synthetic-object-a", "synthetic-object-b",
        ):
            self.assertNotIn(raw_value, serialized)
        self.assertTrue(all(
            len(digest) == 64
            for item in self.parameters for digest in item.observation.value_digests
        ))

    def test_offline_run_attempts_no_network_or_database_access(self):
        with patch.object(socket, "create_connection", side_effect=AssertionError("network attempted")) as connect:
            run_builtin_p0(self.endpoints, self.parameters)
        connect.assert_not_called()
        source = (
            (Path(__file__).parents[1] / "apiAnalysis" / "rule" / "framework.py").read_text(encoding="utf-8")
            + (Path(__file__).parents[1] / "apiAnalysis" / "rule" / "builtin_rules.py").read_text(encoding="utf-8")
        )
        self.assertNotIn("apiAnalysis.db", source)
        self.assertNotIn("requests.", source)

    def test_unknown_fields_predicates_and_online_safety_fail_closed(self):
        base = load_builtin_rule_specs()[0].to_mapping()
        with_unknown = dict(base)
        with_unknown["mongo_query"] = {}
        with self.assertRaises(RuleProtocolError):
            RuleSpec.from_mapping(with_unknown)
        online = json.loads(json.dumps(base))
        online["safety"]["network"] = "allowed"
        with self.assertRaises(RuleProtocolError):
            RuleSpec.from_mapping(online)
        unknown_predicate = json.loads(json.dumps(base))
        unknown_predicate["predicates"] = [{"name": "unknown.predicate.v1"}]
        rule = RuleSpec.from_mapping(unknown_predicate)
        with self.assertRaises(UnknownPredicate):
            builtin_engine().evaluate(rule, {"endpoint": self.endpoints})

    def test_match_budget_fails_without_truncation(self):
        raw = load_builtin_rule_specs()[0].to_mapping()
        raw["safety"]["max_matches"] = 1
        rule = RuleSpec.from_mapping(raw)
        with self.assertRaises(RuleBudgetExceeded):
            builtin_engine().evaluate(rule, {"endpoint": self.endpoints})

    def test_empty_registries_do_not_execute_unregistered_code(self):
        rule = load_builtin_rule_specs()[0]
        engine = OfflineRuleEngine(PredicateRegistry(), OutputAdapterRegistry())
        with self.assertRaises(RuleProtocolError):
            engine.evaluate(rule, {"endpoint": self.endpoints})

    def test_shadow_report_compares_legacy_and_p0_without_values_or_writes(self):
        projection = ShadowProjection(
            endpoints=self.endpoints,
            parameters=self.parameters,
            context={
                "project_id": "project-a",
                "env_id": "test",
                "profile_revision_id": "profile-revision-a",
                "account_ref_sha256": "a" * 64,
                "profile_config_sha256": "b" * 64,
            },
            stats={"projected_request_facts": 6, "projected_response_facts": 3},
            historical_not_equal=({
                "pair_ref_sha256": "c" * 64,
                "rule": "no_intersection_same_path",
                "verified": False,
                "manual_decision_present": False,
            },),
        )

        with patch.object(socket, "create_connection", side_effect=AssertionError("business network attempted")) as connect:
            report = build_shadow_report(projection)

        connect.assert_not_called()
        self.assertEqual(report["business_network_requests"], 0)
        self.assertEqual(report["database_writes"], 0)
        self.assertEqual(report["relations"]["status"], "complete")
        self.assertGreater(
            report["relations"]["legacy_to_p0_counts"].get(
                "not_equal->insufficient_evidence", 0,
            ),
            0,
        )
        self.assertEqual(report["historical_not_equal_audit"]["count"], 1)
        serialized = json.dumps(report, ensure_ascii=False, sort_keys=True)
        self.assertNotIn("synthetic-resource-42", serialized)
        self.assertNotIn("synthetic-object-a", serialized)

    def test_shadow_report_blocks_relations_without_profile_scoped_facts(self):
        projection = ShadowProjection(
            endpoints=self.endpoints,
            parameters=(),
            context={
                "project_id": "project-a", "env_id": "test",
                "profile_revision_id": "profile-revision-a",
            },
            stats={},
            historical_not_equal=(),
        )
        report = build_shadow_report(projection)
        self.assertEqual(report["status"], "partial")
        self.assertEqual(report["relations"]["status"], "blocked")
        self.assertEqual(
            report["relations"]["blockers"],
            ["PROFILE_SCOPED_RELATION_FACTS_UNAVAILABLE"],
        )

    def test_shadow_report_pair_budget_fails_closed(self):
        projection = ShadowProjection(
            endpoints=(),
            parameters=self.parameters,
            context={"project_id": "project-a", "env_id": "test", "profile_revision_id": "pr-a"},
            stats={},
            historical_not_equal=(),
        )
        with self.assertRaises(ShadowEvaluationError):
            build_shadow_report(projection, ShadowLimits(max_pair_combinations=1))

    @patch("apiAnalysis.rule.shadow_evaluation.parameter_relation")
    @patch("apiAnalysis.rule.shadow_evaluation.res_data")
    @patch("apiAnalysis.rule.shadow_evaluation.req_data")
    @patch("apiAnalysis.rule.shadow_evaluation.parameter_archive")
    @patch("apiAnalysis.rule.shadow_evaluation.raw_data")
    @patch("apiAnalysis.rule.shadow_evaluation.ProjectAccountBinding")
    @patch("apiAnalysis.rule.shadow_evaluation.ProjectEnvironment")
    @patch("apiAnalysis.rule.shadow_evaluation.ProjectAuthProfile")
    @patch("apiAnalysis.rule.shadow_evaluation.ProjectAuthProfileRevision")
    def test_mongo_shadow_projection_uses_fixed_project_profile_read_queries(
        self, revision_model, profile_model, environment_model, binding_model, raw_model,
        archive_model, request_model, response_model, relation_model,
    ):
        revision_model.objects.return_value.first.return_value = SimpleNamespace(
            profile_id="profile-a",
            project_account_key="owner",
            config_sha256="d" * 64,
        )
        profile_model.objects.return_value.first.return_value = SimpleNamespace(profile_id="profile-a")
        environment_model.objects.return_value.only.return_value = FakeQuerySet([
            SimpleNamespace(env_id="test"),
        ])
        binding_model.objects.return_value.first.return_value = SimpleNamespace(account_id="account-stable-a")
        endpoint = SimpleNamespace(
            id="endpoint-object-id", ptah_id=701, project_id="project-a", env_id="test",
            method="GET", path="/v1/resources/{resource_id}", action="", rule="path",
            raw_req=[], response_status_code=[200],
        )
        raw_model.objects.return_value.order_by.return_value = FakeQuerySet([endpoint])
        archive_model.objects.return_value = FakeQuerySet([
            SimpleNamespace(
                parameter="resource_id", req_pathid=[701], res_pathid=[701],
                req_value=["scoped-request-value"], res_value=["scoped-response-value"],
                env_id="test", profile_revision_id="profile-revision-a",
                source_kind="profile_scoped_request_sample_v1",
            ),
            SimpleNamespace(
                parameter="resource_id", req_pathid=[701], res_pathid=[701],
                req_value=["legacy-untrusted-value"], res_value=["legacy-untrusted-value"],
                env_id="test", profile_revision_id="", source_kind="",
            ),
        ])
        request_locator = {
            "version": 2, "direction": "request", "position": "path", "kind": "parameter",
            "schema_path": "resource_id", "canonical_name": "resource_id",
            "tokens": [{"kind": "property", "value": "resource_id", "dynamic": False}],
        }
        response_locator = dict(request_locator, direction="response", position="body", kind="instance")
        request_model.objects.return_value = FakeQuerySet([SimpleNamespace(
            raw_data=endpoint, parameter="resource_id", canonical_name="resource_id",
            locator=request_locator, type="string", required=True,
        )])
        response_model.objects.return_value = FakeQuerySet([SimpleNamespace(
            raw_data=endpoint, parameter="resource_id", canonical_name="resource_id",
            locator=response_locator, type="string", required=False,
        )])
        relation_model.objects.return_value = FakeQuerySet([SimpleNamespace(
            parameter="resource_id", req_pathid=701, res_pathid=701,
            rule="no_intersection_same_path", verified=False, manual_decision="",
        )])

        projection = load_shadow_projection(
            "project-a", "test", "profile-revision-a",
        )

        revision_model.objects.assert_called_once_with(profile_revision_id="profile-revision-a")
        profile_model.objects.assert_called_once_with(
            profile_id="profile-a", project_id="project-a", env_id="test",
        )
        raw_model.objects.assert_called_once_with(project_id="project-a")
        archive_model.objects.assert_called_once_with(
            project_id="project-a", account_id__in=["account-stable-a", "owner"],
        )
        relation_model.objects.assert_called_once_with(
            project_id="project-a", relation="not_equal",
        )
        self.assertEqual(len(projection.parameters), 2)
        self.assertEqual(projection.stats["profile_archive_candidate_rows"], 2)
        self.assertEqual(projection.stats["profile_archive_untrusted_rows"], 1)
        self.assertNotIn("scoped-request-value", repr(projection))
        self.assertNotIn("scoped-response-value", repr(projection))
        self.assertNotIn("legacy-untrusted-value", repr(projection))

    def test_shadow_projection_source_has_no_database_or_business_request_writes(self):
        source = (
            Path(__file__).parents[1] / "apiAnalysis" / "rule" / "shadow_evaluation.py"
        ).read_text(encoding="utf-8")
        for forbidden in (
            ".save(", ".update(", ".update_one(", ".delete(", ".delete_one(",
            "requests.", "httpx.", "urllib.request", "replay_snapshot(",
        ):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
