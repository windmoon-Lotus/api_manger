import unittest
from types import SimpleNamespace

from apiAnalysis.tool.interface_knowledge import (
    relation_candidate_score,
    resource_family,
)


def endpoint(pathid, path, *, method="GET", folder="folder-a", source="apifox"):
    return SimpleNamespace(
        ptah_id=pathid,
        path=path,
        method=method,
        source=source,
        asset_kind="abstract" if source == "apifox" else "concrete",
        source_meta={"apifox_module_id": "module-a", "apifox_folder_id": folder},
    )


def field(name="device_id", *, position="body", required=True, values=None):
    return SimpleNamespace(
        parameter=name,
        canonical_name=name,
        position=position,
        required=required,
        type="integer",
        value=list(values or []),
    )


class InterfaceKnowledgeTests(unittest.TestCase):
    def test_resource_family_removes_versions_actions_and_path_parameters(self):
        self.assertEqual(
            resource_family("/v2/devices/{device_id}/detail"),
            "devices",
        )
        self.assertEqual(resource_family("https://api.test/enterprise/users"), "enterprise/users")

    def test_same_document_folder_and_resource_create_relation_candidate(self):
        result = relation_candidate_score(
            field(), field(position="path"),
            endpoint(1, "/devices"), endpoint(2, "/devices/{device_id}"),
        )
        self.assertIsNotNone(result)
        self.assertIn("DOCUMENT_SAME_FOLDER", result["reason_codes"])
        self.assertIn("SAME_RESOURCE_FAMILY", result["reason_codes"])
        self.assertEqual(result["evidence_sources"], ["document"])

    def test_generic_id_is_not_linked_across_unrelated_document_groups(self):
        result = relation_candidate_score(
            field("id"), field("id", position="query"),
            endpoint(1, "/users", folder="users"),
            endpoint(2, "/orders", folder="orders", method="POST"),
        )
        self.assertIsNone(result)

    def test_document_examples_do_not_masquerade_as_real_traffic(self):
        result = relation_candidate_score(
            field(values=[123]), field(position="path", values=[123]),
            endpoint(1, "/devices"), endpoint(2, "/devices/{device_id}"),
        )
        self.assertIn("DOCUMENT_EXAMPLE_OVERLAP", result["reason_codes"])
        self.assertNotIn("traffic", result["evidence_sources"])

        traffic_result = relation_candidate_score(
            field(values=[123]), field(position="path", values=[123]),
            endpoint(1, "/devices"), endpoint(2, "/devices/{device_id}"),
            traffic_pathids={1},
        )
        self.assertIn("TRAFFIC_VALUE_OVERLAP", traffic_result["reason_codes"])
        self.assertIn("traffic", traffic_result["evidence_sources"])


if __name__ == "__main__":
    unittest.main()
