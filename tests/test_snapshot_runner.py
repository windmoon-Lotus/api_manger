import datetime as dt
import json
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import requests
from bson import ObjectId

from apiAnalysis.tool.account_context import AccountContext
from apiAnalysis.tool.snapshot_runner import (
    _headers_with_local_auth,
    _normalize_body,
    _request_kwargs,
    replay_snapshot,
    _validated_request_options,
)


class SnapshotRunnerTest(unittest.TestCase):
    def test_normalize_byte_list_body(self):
        self.assertEqual(_normalize_body([123, 34, 97, 34, 58, 49, 125]), b'{"a":1}')

    def test_headers_auth_overlay(self):
        headers = _headers_with_local_auth({"Accept": "*/*"})
        self.assertEqual(headers["Accept"], "*/*")

    def test_anonymous_mode_strips_all_auth_and_ignores_environment(self):
        with patch.dict("os.environ", {
            "API_MANAGER_AUTHORIZATION": "Bearer local-secret",
            "API_MANAGER_AUTH_COOKIE": "session=local-secret",
        }, clear=False):
            headers = _headers_with_local_auth({
                "Accept": "*/*",
                "Authorization": "Bearer imported-secret",
                "Cookie": "session=imported-secret",
                "X-API-Key": "imported-key",
            }, auth_mode="anonymous")
        self.assertEqual(headers, {"Accept": "*/*"})

    def test_unknown_auth_mode_is_rejected(self):
        with self.assertRaises(ValueError):
            _headers_with_local_auth({}, auth_mode="guess")

    def test_scheduler_request_options_are_bounded(self):
        snapshot = type("Snapshot", (), {
            "headers": {}, "body": None, "content_type": "", "auth_mode": "anonymous",
        })()
        kwargs = _request_kwargs(
            snapshot,
            auth_mode="anonymous",
            request_options={"timeout": 12, "allow_redirects": False},
        )
        self.assertEqual(kwargs["timeout"], 12.0)
        self.assertFalse(kwargs["allow_redirects"])
        self.assertTrue(kwargs["verify"])
        with self.assertRaises(ValueError):
            _validated_request_options({"timeout": 0})
        with self.assertRaises(ValueError):
            _validated_request_options({"verify": False})
        with self.assertRaises(ValueError):
            _validated_request_options({"allow_redirects": "false"})

    def test_account_tls_switch_and_packet_shape_are_persisted_without_values(self):
        snapshot = SimpleNamespace(
            id=ObjectId(),
            pathid=7,
            project_id="project-1",
            env_id="test",
            account_id="owner",
            auth_provider_id="auth_recipe",
            auth_context_ref="revision-1",
            auth_mode="account",
            method="GET",
            url="https://api.example.test/items?limit=10",
            path="/items",
            domain="api.example.test",
            headers={"Accept": "application/json"},
            cookies={},
            body=None,
            content_type="",
            expected_status_codes=[200],
        )
        context = AccountContext(
            project_id="project-1",
            env_id="test",
            account_id="owner",
            provider_id="auth_recipe",
            context_ref="revision-1",
            headers={"Authorization": "Bearer header-secret"},
            cookies={"session": "cookie-secret"},
            expires_at=dt.datetime.utcnow() + dt.timedelta(minutes=10),
            allowed_hosts=("api.example.test",),
            metadata={"tls_verify": False, "auth_request_count": 3},
        )
        prepared = requests.Request(
            "GET",
            snapshot.url,
            headers={
                "Accept": "application/json",
                "Authorization": "Bearer header-secret",
                "Cookie": "session=cookie-secret",
            },
        ).prepare()
        response = requests.Response()
        response.status_code = 200
        response.headers["Content-Type"] = "application/json; charset=utf-8"
        response._content = b'[{"id":1,"name":"first"}]'
        response.request = prepared

        with patch(
            "apiAnalysis.tool.snapshot_runner.requests_request",
            return_value=response,
        ) as request_mock:
            evidence = replay_snapshot(
                snapshot,
                auth_mode="account",
                request_options={"timeout": 15, "allow_redirects": False},
                account_context=context,
            )

        self.assertFalse(request_mock.call_args.kwargs["verify"])
        self.assertEqual(evidence["request_method"], "GET")
        self.assertEqual(evidence["request_query_names"], ["limit"])
        self.assertEqual(evidence["request_cookie_names"], ["session"])
        self.assertEqual(evidence["request_auth_header_names"], ["Authorization"])
        self.assertFalse(evidence["request_tls_verify"])
        self.assertEqual(evidence["auth_request_count"], 3)
        self.assertEqual(evidence["response_record_count"], 1)
        self.assertEqual(evidence["response_field_names"], ["id", "name"])
        rendered = json.dumps(evidence, sort_keys=True)
        self.assertNotIn("header-secret", rendered)
        self.assertNotIn("cookie-secret", rendered)


if __name__ == "__main__":
    unittest.main()
