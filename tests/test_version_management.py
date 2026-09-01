import unittest

from apiAnalysis.version import __version__, version_info


class VersionManagementTests(unittest.TestCase):
    def test_public_version_and_contract_versions_have_one_source(self):
        info = version_info()

        self.assertEqual(info["version"], __version__)
        self.assertRegex(__version__, r"^\d+\.\d+\.\d+$")
        self.assertEqual(set(info["contracts"]), {"import", "execution", "result"})
        self.assertTrue(all(info["contracts"].values()))


if __name__ == "__main__":
    unittest.main()
