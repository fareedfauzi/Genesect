import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
PLUGIN = (ROOT / "pseudonote_extended" / "plugin.py").read_text(encoding="utf-8")
CONFIG = (ROOT / "pseudonote_extended" / "config.py").read_text(encoding="utf-8")
HIGHLIGHT = (ROOT / "pseudonote_extended" / "highlight.py").read_text(encoding="utf-8")
VIEW = (ROOT / "pseudonote_extended" / "view.py").read_text(encoding="utf-8")


class RequestedMenuAndHighlightDefaultsTests(unittest.TestCase):
    def test_highlight_actions_are_unambiguous(self):
        self.assertIn('"Toggle Call Highlight (Pseudocode)"', PLUGIN)
        self.assertIn('"Toggle Call Highlight (Assembly)"', PLUGIN)

    def test_default_highlight_is_pink(self):
        self.assertIn('self.highlight_color = "#ffaaff"', CONFIG)
        self.assertIn('fallback="#ffaaff"', CONFIG)
        self.assertIn("0xFFAAFF", HIGHLIGHT)

    def test_call_highlighting_is_opt_in_for_large_linear_views(self):
        self.assertIn("disasm_highlight_enabled = False", HIGHLIGHT)
        self.assertIn('"Ctrl+Shift+H"', PLUGIN)

    def test_saving_settings_does_not_require_api_key(self):
        self.assertIn("validate_profile(profile, require_api_key=False)", VIEW)
        self.assertIn("API Key (Optional for saving):", VIEW)


if __name__ == "__main__":
    unittest.main()
