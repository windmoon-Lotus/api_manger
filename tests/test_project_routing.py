import unittest

from apiAnalysis.tool.api_signature import abstract_signature
from apiAnalysis.tool.project_routing import route_observation


class ProjectRoutingTests(unittest.TestCase):
    def setUp(self):
        self.observation = {
            "method": "GET",
            "url": "https://api.example.com/users/123",
            "path": "/users/123",
        }

    def test_explicit_project_always_wins(self):
        result = route_observation(self.observation, [], explicit_project_id="project-a")
        self.assertEqual(result["decision"], "assigned")
        self.assertEqual(result["selected_project_id"], "project-a")
        self.assertEqual(result["confidence"], 1.0)

    def test_abstract_signature_and_host_assign_one_project(self):
        assets = [{
            "project_id": "project-a", "method": "GET", "domain": "api.example.com",
            "path": "/users/{id}", "abstract_signature": abstract_signature("GET", "/users/{id}"),
        }]
        result = route_observation(self.observation, assets)
        self.assertEqual(result["decision"], "assigned")
        self.assertEqual(result["selected_project_id"], "project-a")
        self.assertGreaterEqual(result["confidence"], 0.9)

    def test_equal_matches_remain_ambiguous(self):
        signature = abstract_signature("GET", "/users/{id}")
        assets = [
            {"project_id": "project-a", "method": "GET", "domain": "api.example.com", "path": "/users/{id}", "abstract_signature": signature},
            {"project_id": "project-b", "method": "GET", "domain": "api.example.com", "path": "/users/{id}", "abstract_signature": signature},
        ]
        result = route_observation(self.observation, assets)
        self.assertEqual(result["decision"], "ambiguous")
        self.assertEqual(result["selected_project_id"], "")

    def test_host_only_binding_does_not_auto_assign(self):
        bindings = [{"project_id": "project-a", "routing_rules": {"hosts": ["api.example.com"]}}]
        result = route_observation(self.observation, [], bindings=bindings)
        self.assertEqual(result["decision"], "unassigned")
        self.assertEqual(result["candidate_projects"][0]["score"], 0.65)

    def test_confirmed_source_signature_routes_future_observations(self):
        signature = abstract_signature("GET", "/users/{id}")
        bindings = [{
            "project_id": "project-a",
            "routing_rules": {"signatures": ["GET {}".format(signature)]},
        }]
        result = route_observation(self.observation, [], bindings=bindings)
        self.assertEqual(result["decision"], "assigned")
        self.assertEqual(result["selected_project_id"], "project-a")
        self.assertEqual(result["confidence"], 0.99)
        self.assertIn("binding_signature", result["reason_codes"])


if __name__ == "__main__":
    unittest.main()
