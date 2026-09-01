import unittest

from apiAnalysis.rule import security_reasons as reasons


class SecurityReasonTests(unittest.TestCase):
    def test_dynamic_attacker_block_reasons_are_evaluable_and_verified(self):
        self.assertTrue(reasons.is_evaluable_reason(reasons.attacker_blocked_http(401)))
        self.assertTrue(reasons.is_evaluable_reason(reasons.attacker_blocked_http(403)))
        self.assertTrue(reasons.is_verified_reason(reasons.attacker_blocked_http(401)))
        self.assertTrue(reasons.is_verified_reason(reasons.attacker_blocked_http(403)))

    def test_rejected_4xx_is_evaluable_but_not_verified(self):
        reason = reasons.attacker_rejected_http(409)
        self.assertTrue(reasons.is_evaluable_reason(reason))
        self.assertFalse(reasons.is_verified_reason(reason))

    def test_owner_and_payload_failures_are_not_evaluable(self):
        self.assertTrue(reasons.is_not_evaluable_reason(reasons.owner_create_status(500)))
        self.assertTrue(reasons.is_not_evaluable_reason(reasons.PAYLOAD_NOT_BUILT))
        self.assertTrue(reasons.is_not_evaluable_reason("create_no_id_payload_not_built"))

    def test_verified_delete_readback_reasons(self):
        self.assertTrue(reasons.is_verified_reason(reasons.ATTACKER_DELETE_REMOVED_VERIFIED))
        self.assertTrue(reasons.is_verified_reason(reasons.ATTACKER_DELETE_STILL_EXISTS))
        self.assertTrue(reasons.is_evaluable_reason(reasons.ATTACKER_DELETE_STILL_EXISTS))


if __name__ == "__main__":
    unittest.main()
