import importlib.util
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).resolve().parents[1] / "tools" / "public_repo_guard.py"
SPEC = importlib.util.spec_from_file_location("public_repo_guard", str(MODULE_PATH))
guard = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(guard)


TEST_CONFIG = {
    "schema_version": 1,
    "max_text_file_bytes": 1024,
    "forbidden_path_components": [".secrets", "output", ".playwright-cli"],
    "forbidden_path_globs": ["*.har", "*.private.*", "*.docx"],
    "allowed_binary_globs": ["apiAnalysis/static/**"],
    "allowed_hosts": ["github.com", "localhost", "127.0.0.1"],
    "content_rule_exemptions": {},
}


class PublicRepoGuardTests(unittest.TestCase):
    def rules(self, findings):
        return {item.rule for item in findings}

    def test_forbidden_private_path_is_blocked(self):
        findings = guard.scan_blob(
            b"{}", ".secrets/auth.private.json", TEST_CONFIG,
        )
        self.assertIn("forbidden-path", self.rules(findings))
        self.assertIn("forbidden-file-type", self.rules(findings))

    def test_private_network_and_unknown_host_are_blocked(self):
        text = 'BASE_URL = "https://api.internal.invalid-domain.com/v1"\nHOST = "10.2.3.4"\n'
        findings = guard.scan_text(text, "config.py", TEST_CONFIG)
        self.assertIn("unknown-literal-host", self.rules(findings))
        self.assertIn("private-network", self.rules(findings))

    def test_reserved_examples_and_reviewed_public_hosts_pass(self):
        text = (
            '{% extends "base.html" %}\n'
            'module = "runtime_check.py"\n'
            'BASE_URL = "https://api.example.test/v1"\n'
            'DOCS = "https://github.com/example/project"\n'
            'PASSWORD = "example-password"\n'
            'HOST = "192.0.2.10"\n'
        )
        self.assertEqual(guard.scan_text(text, "example.py", TEST_CONFIG), [])

    def test_concrete_credential_is_blocked_without_value_in_message(self):
        secret_value = "prod-credential-7f83a924b650"
        findings = guard.scan_text(
            'access_token = "{}"'.format(secret_value), "settings.py", TEST_CONFIG,
        )
        self.assertIn("credential-literal", self.rules(findings))
        self.assertTrue(all(secret_value not in item.message for item in findings))

    def test_unreviewed_binary_is_blocked_but_static_asset_is_allowed(self):
        binary = b"\x89PNG\x00private"
        blocked = guard.scan_blob(binary, "docs/screenshot.png", TEST_CONFIG)
        allowed = guard.scan_blob(binary, "apiAnalysis/static/images/logo.png", TEST_CONFIG)
        self.assertIn("unreviewed-binary", self.rules(blocked))
        self.assertEqual(allowed, [])

    def test_local_policy_blocks_terms_without_echoing_them(self):
        term = "engagement-codename"
        policy = {"deny_terms": [term], "deny_host_suffixes": []}
        findings = guard.scan_text(
            "case = {!r}".format(term), "tests/test_case.py", TEST_CONFIG,
            local_policy=policy,
        )
        self.assertIn("local-deny-term", self.rules(findings))
        self.assertTrue(all(term not in item.message for item in findings))


if __name__ == "__main__":
    unittest.main()
