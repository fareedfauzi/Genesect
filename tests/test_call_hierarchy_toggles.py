import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
XREFS = (ROOT / "pseudonote_extended" / "xrefs.py").read_text(encoding="utf-8")
COMPONENTS = (ROOT / "pseudonote_extended" / "ui" / "components.py").read_text(encoding="utf-8")


class CallHierarchyToggleTests(unittest.TestCase):
    def test_filters_use_real_toggle_switches(self):
        self.assertIn('ToggleSwitch("API functions")', XREFS)
        self.assertIn('ToggleSwitch("Indirect calls")', XREFS)
        self.assertNotIn('QCheckBox("Show API Functions")', XREFS)
        self.assertNotIn('QCheckBox("Show Indirect Calls")', XREFS)

    def test_toggle_has_track_knob_and_theme_states(self):
        self.assertIn("class ToggleSwitch(QtWidgets.QCheckBox)", COMPONENTS)
        self.assertIn("painter.drawRoundedRect(track", COMPONENTS)
        self.assertIn("painter.drawEllipse(knob)", COMPONENTS)
        self.assertIn("theme.accent", COMPONENTS)
        self.assertIn("theme.border_strong", COMPONENTS)

    def test_toggle_retains_checkbox_accessibility(self):
        self.assertIn("super().__init__(text, parent)", COMPONENTS)
        self.assertIn("self.setCursor(QtCore.Qt.PointingHandCursor)", COMPONENTS)


if __name__ == "__main__":
    unittest.main()
