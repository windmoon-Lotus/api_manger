import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from local_web_credentials import (
    ADMIN_PASSWORD_ENV,
    ADMIN_USERNAME_ENV,
    SECRET_KEY_ENV,
    bootstrap_local_web_credentials,
    inspect_local_web_credentials,
)


class LocalWebCredentialTests(unittest.TestCase):
    def test_first_run_generates_and_second_run_reuses_credentials(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {}, clear=True):
            path = Path(directory) / "web.local.env"
            first = bootstrap_local_web_credentials(path)
            first_password = first["password"]

            self.assertTrue(first["generated"])
            self.assertTrue(first_password)
            self.assertTrue(path.exists())
            self.assertTrue(inspect_local_web_credentials(path)["complete"])
            self.assertEqual(os.environ[ADMIN_USERNAME_ENV], "admin")
            self.assertEqual(os.environ[ADMIN_PASSWORD_ENV], first_password)
            self.assertTrue(os.environ[SECRET_KEY_ENV])

            for key in [ADMIN_USERNAME_ENV, ADMIN_PASSWORD_ENV, SECRET_KEY_ENV]:
                os.environ.pop(key, None)
            second = bootstrap_local_web_credentials(path)

            self.assertFalse(second["generated"])
            self.assertEqual(second["source"], "file")
            self.assertIsNone(second["password"])
            self.assertEqual(os.environ[ADMIN_PASSWORD_ENV], first_password)

    def test_explicit_environment_password_has_priority_and_is_not_persisted(self):
        values = {
            ADMIN_USERNAME_ENV: "operator",
            ADMIN_PASSWORD_ENV: "explicit-test-password",
            SECRET_KEY_ENV: "explicit-test-secret",
        }
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, values, clear=True):
            path = Path(directory) / "web.local.env"
            result = bootstrap_local_web_credentials(path)

            self.assertEqual(result["source"], "environment")
            self.assertFalse(result["generated"])
            self.assertFalse(path.exists())

    def test_incomplete_existing_file_fails_instead_of_overwriting(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {}, clear=True):
            path = Path(directory) / "web.local.env"
            path.write_text("API_MANAGER_ADMIN_USERNAME=admin\n", encoding="utf-8")

            with self.assertRaises(RuntimeError):
                bootstrap_local_web_credentials(path)


if __name__ == "__main__":
    unittest.main()
