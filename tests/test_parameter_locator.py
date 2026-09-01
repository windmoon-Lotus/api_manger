import unittest

from apiAnalysis.tool.parameter_locator import (
    extract_values_at_locator,
    iter_json_leaf_occurrences,
    locator_from_path,
    materialize_flat_json,
    set_value_at_locator,
)
from apiAnalysis.tool.tool import unflatten_json


class ParameterLocatorTests(unittest.TestCase):
    def test_schema_array_materializes_one_representative_item(self):
        body = unflatten_json(
            {
                "remote_users[].remote_id": 7,
                "remote_users[].name": "peer",
            },
            value_selector=lambda value: value,
        )
        self.assertEqual(body, {"remote_users": [{"remote_id": 7, "name": "peer"}]})

    def test_numeric_schema_root_is_an_object_key_not_a_huge_list(self):
        body = materialize_flat_json({"13705615.remote_users[].remote_id": 7})
        self.assertIsInstance(body, dict)
        self.assertEqual(body["13705615"]["remote_users"][0]["remote_id"], 7)

    def test_large_nested_numeric_map_key_is_not_materialized_as_a_huge_list(self):
        body = materialize_flat_json({"groups.13705615.remote_id": 7})
        self.assertEqual(body, {"groups": {"13705615": {"remote_id": 7}}})

    def test_concrete_occurrences_preserve_array_indexes_and_numeric_map_keys(self):
        original = {
            "13705615": {
                "remote_users": [{"remote_id": 7}, {"remote_id": 8}],
            }
        }
        rebuilt = None
        locators = []
        for locator, value in iter_json_leaf_occurrences(original, direction="response"):
            locators.append(locator)
            rebuilt = set_value_at_locator(rebuilt, locator, value)
        self.assertEqual(rebuilt, original)
        self.assertEqual(locators[0]["schema_path"], "13705615.remote_users[].remote_id")
        self.assertEqual(locators[0]["canonical_name"], "remote_id")
        self.assertEqual(locators[0]["display_path"], "{key}.remote_users[].remote_id")

    def test_dynamic_schema_key_extracts_across_runtime_key_changes(self):
        locator = locator_from_path(
            "13705615.remote_users[].remote_id",
            direction="response",
            position="body",
            schema=True,
        )
        response = {
            "99990001": {"remote_users": [{"remote_id": 11}, {"remote_id": 12}]},
        }
        self.assertEqual(extract_values_at_locator(response, locator), [11, 12])


if __name__ == "__main__":
    unittest.main()
