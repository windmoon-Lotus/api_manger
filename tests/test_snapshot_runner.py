import unittest

from apiAnalysis.tool.snapshot_runner import _headers_with_local_auth, _normalize_body


class SnapshotRunnerTest(unittest.TestCase):
    def test_normalize_byte_list_body(self):
        self.assertEqual(_normalize_body([123, 34, 97, 34, 58, 49, 125]), b'{"a":1}')

    def test_headers_auth_overlay(self):
        headers = _headers_with_local_auth({"Accept": "*/*"})
        self.assertEqual(headers["Accept"], "*/*")


if __name__ == "__main__":
    unittest.main()
