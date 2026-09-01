import os
import threading
import time
import unittest
from unittest.mock import patch

from flask import Flask

from apiAnalysis.tool.mfa_receiver import (
    MfaPushBroker,
    MfaReceiverError,
    _decrypt_code,
    _encrypt_code,
    default_mfa_push_broker,
)
from apiAnalysis.web import bp_api


class MfaReceiverTests(unittest.TestCase):
    def setUp(self):
        default_mfa_push_broker().clear()

    def tearDown(self):
        default_mfa_push_broker().clear()

    def test_broker_consumes_each_code_once(self):
        broker = MfaPushBroker()
        outcome = {}

        def wait_for_code():
            outcome["code"] = broker.wait(
                "test-otp", correlation="account-1", timeout_seconds=2,
            )

        worker = threading.Thread(target=wait_for_code, daemon=True)
        worker.start()
        pending = []
        deadline = time.time() + 1
        while time.time() < deadline and not pending:
            pending = broker.pending("test-otp")
            if not pending:
                time.sleep(0.01)

        self.assertEqual(len(pending), 1)
        transaction_id = pending[0]["transaction_id"]
        self.assertTrue(broker.deliver(transaction_id, "246810"))
        self.assertFalse(broker.deliver(transaction_id, "246810"))
        worker.join(timeout=1)
        self.assertEqual(outcome["code"], "246810")
        self.assertEqual(broker.pending(), [])

    def test_push_api_requires_token_and_never_echoes_code(self):
        app = Flask(__name__)
        app.secret_key = "mfa-receiver-test"
        app.register_blueprint(bp_api)
        broker = default_mfa_push_broker()
        outcome = {}

        def wait_for_code():
            outcome["code"] = broker.wait(
                "company-otp", correlation="owner", timeout_seconds=2,
            )

        worker = threading.Thread(target=wait_for_code, daemon=True)
        worker.start()
        deadline = time.time() + 1
        while time.time() < deadline and not broker.pending("company-otp"):
            time.sleep(0.01)

        with patch.dict(os.environ, {
            "API_MANAGER_MFA_RECEIVER_TOKEN": "receiver-api-token",
        }, clear=False):
            client = app.test_client()
            unauthorized = client.get("/api/auth/mfa-receiver/pending")
            self.assertEqual(unauthorized.status_code, 401)

            headers = {"Authorization": "Bearer receiver-api-token"}
            missing_receiver = client.get(
                "/api/auth/mfa-receiver/pending", headers=headers,
            )
            self.assertEqual(missing_receiver.status_code, 400)
            pending_response = client.get(
                "/api/auth/mfa-receiver/pending?receiver_id=company-otp",
                headers=headers,
            )
            self.assertEqual(pending_response.status_code, 200)
            pending = pending_response.get_json()["pending"]
            self.assertEqual(len(pending), 1)

            push_response = client.post(
                "/api/auth/mfa-receiver/push",
                headers=headers,
                json={
                    "transaction_id": pending[0]["transaction_id"],
                    "code": "135790",
                },
            )
            self.assertEqual(push_response.status_code, 202)
            self.assertEqual(push_response.get_json(), {"accepted": True})
            self.assertNotIn("135790", push_response.get_data(as_text=True))

        worker.join(timeout=1)
        self.assertEqual(outcome["code"], "135790")

    def test_shared_broker_payload_is_encrypted_and_authenticated(self):
        with patch.dict(os.environ, {
            "API_MANAGER_MFA_RECEIVER_TOKEN": "receiver-encryption-key",
        }, clear=False):
            payload = _encrypt_code("mfa-transaction", "908172")
            self.assertNotIn("908172", payload)
            self.assertEqual(
                _decrypt_code("mfa-transaction", payload),
                "908172",
            )
            with self.assertRaises(MfaReceiverError):
                _decrypt_code("mfa-other-transaction", payload)

    def test_push_api_hides_shared_broker_failures(self):
        class BrokenBroker:
            def pending(self, receiver_id=""):
                raise MfaReceiverError("internal connection details")

        app = Flask(__name__)
        app.secret_key = "mfa-receiver-test"
        app.register_blueprint(bp_api)
        with patch.dict(os.environ, {
            "API_MANAGER_MFA_RECEIVER_TOKEN": "receiver-api-token",
        }, clear=False), patch(
            "apiAnalysis.web.views_mfa_receiver.default_mfa_push_broker",
            return_value=BrokenBroker(),
        ):
            response = app.test_client().get(
                "/api/auth/mfa-receiver/pending?receiver_id=company-otp",
                headers={"Authorization": "Bearer receiver-api-token"},
            )
        self.assertEqual(response.status_code, 503)
        self.assertEqual(
            response.get_json(), {"error": "mfa_receiver_unavailable"},
        )
        self.assertNotIn("connection", response.get_data(as_text=True))


if __name__ == "__main__":
    unittest.main()
