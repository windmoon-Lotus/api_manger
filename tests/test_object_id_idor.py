import unittest

from apiAnalysis.rule.object_id import (
    is_object_id_param,
    collect_object_ids,
    build_idor_payload,
)


class ObjectIdDetectionTest(unittest.TestCase):
    def test_detects_common_object_id_names(self):
        for name in [
            "id", "uid", "uuid",
            "user_id", "userId", "userid",
            "account_id", "accountId",
            "device_id", "deviceId",
            "order_id", "orgId", "tenant_id",
            "target_user_id", "owner_uid",
            "data.user_id",
        ]:
            self.assertTrue(is_object_id_param(name), "should detect: {}".format(name))

    def test_ignores_noise_and_non_ids(self):
        for name in [
            "page", "page_size", "pageSize", "offset", "limit",
            "timestamp", "_t", "ts", "nonce", "sign", "token", "callback",
            "version", "keyword", "sort", "order", "status", "type", "code",
            "page_no", "error_code",
            # words that merely end in "id" but are not identifiers
            "valid", "is_valid", "android", "paid", "void", "grid",
            # session / auth ids are credential context, not swappable
            "sid", "sessionid",
        ]:
            self.assertFalse(is_object_id_param(name), "should ignore: {}".format(name))

    def test_detects_domain_resource_ids_by_suffix(self):
        # real-world domain parameter names a name-allowlist would miss
        for name in [
            "remoteid", "remoteids", "tagid", "tagids", "packageid",
            "policyid", "seatid", "moduleid", "macid", "iccid",
            "entid", "hardwareid", "server_instanceid", "account", "cc_account",
        ]:
            self.assertTrue(is_object_id_param(name), "should detect: {}".format(name))


class CollectObjectIdsTest(unittest.TestCase):
    def test_collects_from_query_path_and_nested_body(self):
        payload = {
            "query": {"user_id": "100", "page": "1"},
            "path_params": {"deviceId": "d-1"},
            "body": {"data": {"order_id": "o-9", "name": "x"}, "page_size": 20},
        }
        found = {(item["location"], item["param"]) for item in collect_object_ids(payload)}
        self.assertIn(("query", "user_id"), found)
        self.assertIn(("path", "deviceId"), found)
        self.assertIn(("body", "data.order_id"), found)
        self.assertNotIn(("query", "page"), found)
        self.assertNotIn(("body", "page_size"), found)


class BuildIdorPayloadTest(unittest.TestCase):
    def test_swaps_object_ids_to_victim_values(self):
        attacker = {
            "query": {"account_id": "A-1", "page": "1"},
            "path_params": {"deviceId": "att-dev"},
            "body": {"data": {"order_id": "att-order", "note": "keep"}},
            "url": "https://t.test/api",
        }
        victim = {
            "query": {"account_id": "V-9", "page": "5"},
            "path_params": {"deviceId": "vic-dev"},
            "body": {"data": {"order_id": "vic-order", "note": "other"}},
        }
        new_payload, swaps = build_idor_payload(attacker, victim)

        # attacker now carries the victim's object identifiers
        self.assertEqual(new_payload["query"]["account_id"], "V-9")
        self.assertEqual(new_payload["path_params"]["deviceId"], "vic-dev")
        self.assertEqual(new_payload["body"]["data"]["order_id"], "vic-order")
        # non-id fields and noise are untouched
        self.assertEqual(new_payload["query"]["page"], "1")
        self.assertEqual(new_payload["body"]["data"]["note"], "keep")
        # original attacker payload is not mutated
        self.assertEqual(attacker["query"]["account_id"], "A-1")
        # three swaps recorded
        self.assertEqual(len(swaps), 3)

    def test_no_swap_when_victim_value_missing_or_equal(self):
        attacker = {"query": {"user_id": "same"}}
        victim = {"query": {"user_id": "same"}}
        _new, swaps = build_idor_payload(attacker, victim)
        self.assertEqual(swaps, [])

        attacker2 = {"query": {"user_id": "A"}}
        victim2 = {"query": {"user_id": ""}}
        _new2, swaps2 = build_idor_payload(attacker2, victim2)
        self.assertEqual(swaps2, [])

    def test_no_object_id_means_no_swap(self):
        attacker = {"query": {"page": "1"}, "body": {"keyword": "x"}}
        victim = {"query": {"page": "2"}, "body": {"keyword": "y"}}
        _new, swaps = build_idor_payload(attacker, victim)
        self.assertEqual(swaps, [])


if __name__ == "__main__":
    unittest.main()
