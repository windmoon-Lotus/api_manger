import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
LINK_RE = re.compile(r"\[[^\]]*\]\(([^)]+)\)")


class DocumentationTests(unittest.TestCase):
    def test_local_markdown_links_resolve(self):
        paths = list(ROOT.glob("*.md")) + list((ROOT / "docs").glob("*.md"))
        broken = []
        for path in paths:
            text = path.read_text(encoding="utf-8")
            for match in LINK_RE.finditer(text):
                target = match.group(1).strip().strip("<>")
                if not target or target.startswith(
                    ("http://", "https://", "#", "mailto:")
                ):
                    continue
                relative = target.split("#", 1)[0]
                if relative and not (path.parent / relative).resolve().exists():
                    line = text.count("\n", 0, match.start()) + 1
                    broken.append(
                        "{}:{} -> {}".format(path.relative_to(ROOT), line, target)
                    )
        self.assertEqual(broken, [])

    def test_primary_docs_link_to_current_usage_reference(self):
        for relative in ("README.md", "START.md", "CONFIGURATION.md"):
            source = (ROOT / relative).read_text(encoding="utf-8")
            self.assertIn("docs/CLI_REFERENCE.md", source)


if __name__ == "__main__":
    unittest.main()
