import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "pseudonote_extended"
SOURCES = {
    path.relative_to(PACKAGE).as_posix(): path.read_text(encoding="utf-8")
    for path in PACKAGE.rglob("*.py")
}


class UIPaintSafetyTests(unittest.TestCase):
    def test_no_global_or_native_paint_overrides(self):
        forbidden = (
            "WA_StyledBackground",
            "WA_NoSystemBackground",
            "WA_OpaquePaintEvent",
            "WA_NativeWindow",
            "WA_DontCreateNativeAncestors",
            "WA_PaintOnScreen",
            "WA_StaticContents",
            "setWindowOpacity(",
            "stabilize_widget_rendering",
            "stable_dialog_parent",
        )
        for relative, source in SOURCES.items():
            for marker in forbidden:
                self.assertNotIn(marker, source, f"{relative} reintroduced {marker}")

    def test_no_pseudonote_window_can_float_above_other_applications(self):
        for relative, source in SOURCES.items():
            self.assertNotIn("WindowStaysOnTopHint", source, relative)

    def test_progress_overlay_is_ida_owned_and_does_not_steal_focus(self):
        source = SOURCES["view.py"]
        start = source.index("class ProgressOverlay")
        end = source.index("_view_instance = None", start)
        section = source[start:end]
        self.assertIn("QtCore.Qt.Tool | QtCore.Qt.FramelessWindowHint", section)
        self.assertIn("self.parentWidget() or QtWidgets.QApplication.activeWindow()", section)
        self.assertNotIn("self.activateWindow()", section)

    def test_translucency_is_limited_to_known_overlays(self):
        occurrences = {
            relative: source.count("WA_TranslucentBackground")
            for relative, source in SOURCES.items()
            if "WA_TranslucentBackground" in source
        }
        self.assertEqual(occurrences, {"chat.py": 1, "view.py": 1})

    def test_no_full_window_forced_repaints(self):
        occurrences = {
            relative: source.count(".repaint(")
            for relative, source in SOURCES.items()
            if ".repaint(" in source
        }
        self.assertEqual(occurrences, {})

    def test_repolish_is_limited_to_button_state_refresh(self):
        occurrences = {
            relative: source.count(".unpolish(")
            for relative, source in SOURCES.items()
            if ".unpolish(" in source
        }
        self.assertEqual(occurrences, {"deep_analyzer.py": 1})
        self.assertIn("btn.style().unpolish(btn)", SOURCES["deep_analyzer.py"])


if __name__ == "__main__":
    unittest.main()
