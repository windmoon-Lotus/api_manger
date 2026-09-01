import json
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from apiAnalysis.rule.profile_parameter_archive import (
    ArchiveOperation,
    PROFILE_ARCHIVE_SOURCE_KIND,
    ProfileArchiveError,
    ProfileArchiveLimits,
    ProfileArchivePlan,
    apply_profile_archive_plan,
    build_profile_archive_plan,
    profile_archive_report,
)


class FakeQuerySet:
    def __init__(self, rows):
        self.rows = list(rows)

    def count(self):
        return len(self.rows)

    def order_by(self, *_):
        return self

    def only(self, *_):
        return self

    def __iter__(self):
        return iter(self.rows)


def locator(direction, position, *tokens):
    return {
        "version": 2,
        "direction": direction,
        "position": position,
        "kind": "parameter" if position != "body" else "schema",
        "canonical_name": tokens[-1].get("value", "") if tokens else "",
        "tokens": list(tokens),
    }


class ProfileParameterArchiveTests(unittest.TestCase):
    @patch("apiAnalysis.rule.profile_parameter_archive.parameter_archive")
    @patch("apiAnalysis.rule.profile_parameter_archive.parameter_data")
    @patch("apiAnalysis.rule.profile_parameter_archive.res_data")
    @patch("apiAnalysis.rule.profile_parameter_archive.req_data")
    @patch("apiAnalysis.rule.profile_parameter_archive.request_sample")
    @patch("apiAnalysis.rule.profile_parameter_archive.ProjectEnvironment")
    @patch("apiAnalysis.rule.profile_parameter_archive.ProjectAccountBinding")
    @patch("apiAnalysis.rule.profile_parameter_archive.ProjectAuthProfile")
    @patch("apiAnalysis.rule.profile_parameter_archive.ProjectAuthProfileRevision")
    def test_plan_extracts_only_profile_scoped_typed_sample_values(
        self, revision_model, profile_model, binding_model, environment_model,
        sample_model, request_model, response_model, parameter_model, archive_model,
    ):
        revision_model.objects.return_value.first.return_value = SimpleNamespace(
            profile_id="profile-a",
            project_account_key="owner-alias",
            config_sha256="a" * 64,
        )
        profile_model.objects.return_value.first.return_value = SimpleNamespace(profile_id="profile-a")
        binding_model.objects.return_value.first.return_value = SimpleNamespace(account_id="account-stable-a")
        environment_model.objects.return_value.only.return_value = FakeQuerySet([
            SimpleNamespace(env_id="test"),
        ])
        endpoint = SimpleNamespace(
            id="endpoint-object-a",
            project_id="project-a",
            env_id="",
            ptah_id=701,
            path="/v1/resources/{resource_id}",
        )
        sample = SimpleNamespace(
            id="sample-object-a",
            raw_data=endpoint,
            project_id="project-a",
            env_id="",
            account_id="account-stable-a",
            pathid=701,
            sample_signature="sample-signature-a",
            response_hash="response-hash-a",
            url="https://example.test/v1/resources/resource-42?page=2",
            path="/v1/resources/{resource_id}",
            query={"page": 2},
            headers={"Authorization": "secret-bearer"},
            body={"resource_id": "resource-42"},
            response_sample=json.dumps({"items": [{"resource_id": "resource-42"}]}),
        )
        sample_model.objects.return_value.order_by.return_value = FakeQuerySet([sample])
        request_model.objects.return_value.order_by.return_value = FakeQuerySet([
            SimpleNamespace(
                id="req-path", raw_data=endpoint, parameter="resource_id",
                canonical_name="resource_id", position="path", type="string",
                locator=locator("request", "path", {
                    "kind": "property", "value": "resource_id", "dynamic": False,
                }),
            ),
            SimpleNamespace(
                id="req-page", raw_data=endpoint, parameter="page",
                canonical_name="page", position="query", type="integer",
                locator=locator("request", "query", {
                    "kind": "property", "value": "page", "dynamic": False,
                }),
            ),
            SimpleNamespace(
                id="req-auth", raw_data=endpoint, parameter="authorization",
                canonical_name="authorization", position="header", type="string",
                locator=locator("request", "header", {
                    "kind": "property", "value": "Authorization", "dynamic": False,
                }),
            ),
        ])
        response_model.objects.return_value.order_by.return_value = FakeQuerySet([
            SimpleNamespace(
                id="res-resource", raw_data=endpoint, parameter="items[].resource_id",
                canonical_name="resource_id", position="body", type="string",
                locator=locator(
                    "response", "body",
                    {"kind": "property", "value": "items", "dynamic": False},
                    {"kind": "array", "index": 0, "wildcard": True},
                    {"kind": "property", "value": "resource_id", "dynamic": False},
                ),
            ),
        ])
        parameter_model.objects.return_value = FakeQuerySet([
            SimpleNamespace(
                parameter="resource_id", parameterid=11,
                req_pathid=[701], res_pathid=[],
            ),
            SimpleNamespace(
                parameter="items[].resource_id", parameterid=12,
                req_pathid=[], res_pathid=[701],
            ),
            SimpleNamespace(
                parameter="page", parameterid=13,
                req_pathid=[701], res_pathid=[],
            ),
        ])
        archive_model.objects.return_value = FakeQuerySet([])

        plan = build_profile_archive_plan("project-a", "test", "profile-revision-a")

        self.assertEqual(plan.status, "complete")
        self.assertEqual(len(plan.operations), 2)
        operations = {item.identity: item for item in plan.operations}
        self.assertEqual(operations["resource_id"].req_values, ("resource-42",))
        self.assertEqual(operations["resource_id"].res_values, ("resource-42",))
        self.assertEqual(operations["resource_id"].parameterids, (11, 12))
        self.assertEqual(operations["page"].req_values, (2,))
        self.assertEqual(plan.stats["category_auth_session_excluded"], 1)
        self.assertEqual(plan.stats["category_pagination_filter_observations"], 1)
        report = profile_archive_report(plan, mode="dry_run")
        serialized = json.dumps(report, ensure_ascii=False, sort_keys=True)
        self.assertNotIn("resource-42", serialized)
        self.assertNotIn("secret-bearer", serialized)
        self.assertNotIn("owner-alias", serialized)
        self.assertNotIn("/v1/resources", serialized)
        self.assertEqual(report["database_writes"], 0)
        self.assertEqual(report["business_network_requests"], 0)

    def test_apply_requires_exact_plan_hash_before_any_write(self):
        plan = MagicMock()
        plan.blockers = ()
        plan.plan_sha256 = "a" * 64
        with self.assertRaisesRegex(ProfileArchiveError, "expected plan hash"):
            apply_profile_archive_plan(plan, "b" * 64)

    @patch("apiAnalysis.rule.profile_parameter_archive.parameter_archive")
    def test_apply_creates_only_after_exact_hash(self, archive_model):
        operation = ArchiveOperation(
            identity="resource_id",
            parameter="resource_id",
            parameterids=(11,),
            req_pathids=(701,),
            res_pathids=(702,),
            req_values=("resource-42",),
            res_values=("resource-42",),
            properties=(PROFILE_ARCHIVE_SOURCE_KIND,),
            existing_id="",
            before_sha256="0" * 64,
            action="create",
        )
        plan = ProfileArchivePlan(
            project_id="project-a",
            env_id="test",
            profile_revision_id="profile-revision-a",
            account_key="owner-alias",
            input_watermark_sha256="b" * 64,
            plan_sha256="a" * 64,
            operations=(operation,),
            stats={},
            blockers=(),
            limits=ProfileArchiveLimits(),
        )
        archive_model.objects.return_value = FakeQuerySet([])
        record = archive_model.return_value

        writes = apply_profile_archive_plan(plan, "a" * 64)

        self.assertEqual(writes, 1)
        self.assertEqual(record.profile_revision_id, "profile-revision-a")
        self.assertEqual(record.source_kind, PROFILE_ARCHIVE_SOURCE_KIND)
        self.assertEqual(record.req_value, ["resource-42"])
        record.save.assert_called_once_with()

    def test_source_contains_no_business_request_dispatch(self):
        source = (
            Path(__file__).parents[1]
            / "apiAnalysis" / "rule" / "profile_parameter_archive.py"
        ).read_text(encoding="utf-8")
        for forbidden in (
            "requests.", "httpx.", "urllib.request", "replay_snapshot(",
        ):
            self.assertNotIn(forbidden, source)
        self.assertIn("expected_plan_sha256", source)
        self.assertIn(PROFILE_ARCHIVE_SOURCE_KIND, source)


if __name__ == "__main__":
    unittest.main()
