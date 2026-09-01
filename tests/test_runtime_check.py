import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from apiAnalysis import runtime_check


class RuntimeSecurityCheckTests(unittest.TestCase):
    def test_locked_core_dependency_versions_are_checked(self):
        with patch.object(
            runtime_check.metadata,
            "version",
            side_effect=lambda name: runtime_check.CORE_DISTRIBUTIONS[name],
        ):
            item = runtime_check._check_core_dependencies()

        self.assertTrue(item["ok"])

    def test_dependency_version_drift_fails_closed(self):
        with patch.object(runtime_check.metadata, "version", return_value="0.0"):
            item = runtime_check._check_core_dependencies()

        self.assertFalse(item["ok"])
        self.assertIn("version drift", item["detail"])

    def test_missing_web_credentials_are_reported_as_warnings(self):
        with tempfile.TemporaryDirectory() as directory:
            missing = str(Path(directory) / "missing.env")
            with patch.dict(
                os.environ, {"API_MANAGER_WEB_CREDENTIALS_FILE": missing}, clear=True
            ), patch.object(runtime_check, "secret_key_is_ephemeral", True):
                checks = runtime_check._check_web_security()

        self.assertEqual([item["name"] for item in checks], ["web:secret_key", "web:local_user"])
        self.assertTrue(all(item.get("warning") for item in checks))
        self.assertTrue(all(item.get("ok") for item in checks))

    def test_configured_web_security_is_ok(self):
        with tempfile.TemporaryDirectory() as directory:
            missing = str(Path(directory) / "missing.env")
            with patch.dict(os.environ, {
                "API_MANAGER_ADMIN_PASSWORD": "test-only",
                "API_MANAGER_WEB_CREDENTIALS_FILE": missing,
            }, clear=True), patch.object(runtime_check, "secret_key_is_ephemeral", False):
                checks = runtime_check._check_web_security()

        self.assertTrue(all(item.get("ok") for item in checks))
        self.assertTrue(all(not item.get("warning") for item in checks))


if __name__ == "__main__":
    unittest.main()
