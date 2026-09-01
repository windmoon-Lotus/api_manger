import unittest
from pathlib import Path


class HomeShellTests(unittest.TestCase):
    def test_workbench_tab_opens_welcome_content_not_shell_itself(self):
        template = (
            Path(__file__).resolve().parents[1]
            / "apiAnalysis" / "templates" / "home.html"
        ).read_text(encoding="utf-8")

        self.assertIn("<a _href=\"{{ url_for('web.welcome') }}\">", template)
        self.assertNotIn("<a _href=\"{{ url_for('web.home') }}\">", template)


if __name__ == "__main__":
    unittest.main()
