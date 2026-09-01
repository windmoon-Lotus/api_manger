import unittest

from tools.record_locked_snapshot_batch import verdict_for_sample


class LockedSnapshotBatchRecordingTests(unittest.TestCase):
    def test_auth_block_is_no_vuln_for_unauth_check(self):
        verdict, reasons, confidence = verdict_for_sample({"status": 401, "cluster": "auth_401"})
        self.assertEqual(verdict, "no_vuln")
        self.assertIn("anonymous_authentication_required", reasons)
        self.assertGreater(confidence, 0.9)

    def test_anonymous_2xx_requires_review(self):
        verdict, reasons, _confidence = verdict_for_sample({"status": 200})
        self.assertEqual(verdict, "need_review")
        self.assertIn("anonymous_success_requires_public_data_review", reasons)

    def test_transport_error_is_not_security_conclusion(self):
        verdict, _reasons, _confidence = verdict_for_sample({"status": None})
        self.assertEqual(verdict, "error")


if __name__ == "__main__":
    unittest.main()
