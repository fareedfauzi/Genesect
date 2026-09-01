import pathlib
import unittest


ROOT = pathlib.Path(__file__).parents[1]
MAC = (ROOT / "pseudonote_extended" / "ui" / "mac_workspace.py").read_text(encoding="utf-8")
THEME = (ROOT / "pseudonote_extended" / "ui" / "theme.py").read_text(encoding="utf-8")
CHAIN = (ROOT / "pseudonote_extended" / "chat_chain.py").read_text(encoding="utf-8")


class DisabledButtonContrastTests(unittest.TestCase):
    def test_disabled_primary_buttons_keep_readable_text_and_border(self):
        for source in (MAC, THEME):
            start = source.index('QPushButton[pnVariant="primary"]:disabled')
            rule = source[start:source.index("}}", start) + 2]
            self.assertIn("background: {t.surface_alt}", rule)
            self.assertIn("border-color: {t.border_strong}", rule)
            self.assertIn("color: {t.text_muted}", rule)
            self.assertNotIn("background: {t.selection}", rule)

    def test_graph_button_has_explanatory_tooltip(self):
        self.assertIn("Build or rebuild the selectable caller/callee function graph", CHAIN)

    def test_graph_button_has_local_high_contrast_state_rules(self):
        self.assertIn('setObjectName("buildFunctionGraphButton")', CHAIN)
        self.assertIn("QPushButton#buildFunctionGraphButton:disabled", CHAIN)
        self.assertIn("background: {button_theme.accent}", CHAIN)
        self.assertIn("color: {button_theme.accent_text}", CHAIN)
        self.assertIn("background: {button_theme.surface_alt}", CHAIN)
        self.assertIn("color: {button_theme.text_muted}", CHAIN)

    def test_valid_current_function_explicitly_enables_graph_button(self):
        self.assertIn("self.build_btn.setEnabled(True)", CHAIN)
        self.assertIn("self.build_btn.setEnabled(False)\n            self.status_lbl.setText(\"No function at cursor.\")", CHAIN)


if __name__ == "__main__":
    unittest.main()
