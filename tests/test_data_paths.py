import importlib.util
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


MODULE_PATH = Path(__file__).resolve().parents[1] / "apiAnalysis" / "conf" / "data_paths.py"
SPEC = importlib.util.spec_from_file_location("data_paths", str(MODULE_PATH))
data_paths = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(data_paths)


class PrivateDataPathTests(unittest.TestCase):
    def test_configured_external_root_is_used(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(
            os.environ, {data_paths.DATA_DIR_ENV: directory}, clear=False
        ):
            root = data_paths.private_data_root(create=True)
            upload_dir = data_paths.private_upload_dir(create=True)
            self.assertEqual(root, Path(directory).resolve())
            self.assertEqual(upload_dir, root / "uploads")
            self.assertTrue(upload_dir.exists())
            self.assertFalse(data_paths.is_repository_local(upload_dir))

    def test_repository_local_root_fails_closed(self):
        unsafe = data_paths.REPOSITORY_ROOT / ".runtime-private"
        with patch.dict(
            os.environ,
            {
                data_paths.DATA_DIR_ENV: str(unsafe),
                data_paths.ALLOW_UNSAFE_DATA_DIR_ENV: "0",
            },
            clear=False,
        ):
            with self.assertRaises(RuntimeError):
                data_paths.private_data_root()

    def test_migration_override_is_explicit(self):
        unsafe = data_paths.REPOSITORY_ROOT / ".runtime-private"
        with patch.dict(
            os.environ,
            {
                data_paths.DATA_DIR_ENV: str(unsafe),
                data_paths.ALLOW_UNSAFE_DATA_DIR_ENV: "1",
            },
            clear=False,
        ):
            root = data_paths.private_data_root(create=False)

        self.assertEqual(root, unsafe.resolve())
        self.assertTrue(data_paths.is_repository_local(root))

    def test_public_private_reference_never_contains_local_path(self):
        source = str(Path("D:/") / "private" / "evidence.json")
        reference = data_paths.public_private_reference(source)

        self.assertTrue(reference.startswith("private://sha256/"))
        self.assertNotIn("D:", reference)
        self.assertNotIn("evidence.json", reference)


if __name__ == "__main__":
    unittest.main()
