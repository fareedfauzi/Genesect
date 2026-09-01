import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
TYPOGRAPHY = (ROOT / "pseudonote_extended" / "ui" / "typography.py").read_text(encoding="utf-8")
CHAT = (ROOT / "pseudonote_extended" / "chat.py").read_text(encoding="utf-8")
THEME = (ROOT / "pseudonote_extended" / "ui" / "theme.py").read_text(encoding="utf-8")


class TypographyTests(unittest.TestCase):
    def test_cross_platform_professional_font_stack(self):
        for family in ("SF Pro Text", "Segoe UI Variable Text", "Inter", "Noto Sans"):
            self.assertIn(family, TYPOGRAPHY)
        self.assertNotIn("hasFamily", TYPOGRAPHY)

    def test_shared_theme_applies_readable_ui_font(self):
        self.assertIn("apply_ui_font(widget, 9.5)", THEME)
        self.assertIn("font-size: 9.5pt", THEME)

    def test_chat_uses_larger_shared_font_and_line_height(self):
        self.assertIn("return ui_font(11.0)", CHAT)
        self.assertIn("line-height: 1.55", CHAT)

    def test_major_features_apply_shared_typography(self):
        features = (
            "view.py", "agentic_analyzer.py", "chat_chain.py", "summarizer.py",
            "deep_analyzer.py", "renamer.py", "var_renamer.py", "analyzer.py",
            "hexview.py", "floss_strings.py",
        )
        for name in features:
            source = (ROOT / "pseudonote_extended" / name).read_text(encoding="utf-8")
            self.assertTrue("ui.typography" in source or "ui.mac_workspace" in source, name)


if __name__ == "__main__":
    unittest.main()
