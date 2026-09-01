import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
VIEW = (ROOT / "pseudonote_extended" / "view.py").read_text(encoding="utf-8")


class CommentedCodeHighlightingTests(unittest.TestCase):
    def test_commented_code_uses_shared_highlighter_lifecycle(self):
        self.assertIn("self.comments_ai_highlighter = None", VIEW)
        self.assertIn('self.comments_ai_highlighter.update_rules("C")', VIEW)
        self.assertIn("self.highlighters.append(self.comments_ai_highlighter)", VIEW)


if __name__ == "__main__":
    unittest.main()
