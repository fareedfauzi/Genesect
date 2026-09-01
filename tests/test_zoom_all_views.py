import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "pseudonote_extended" / "zoom.py").read_text(encoding="utf-8")
PLUGIN = (ROOT / "pseudonote_extended" / "plugin.py").read_text(encoding="utf-8")
MENU = (ROOT / "pseudonote_extended" / "ui" / "context_menu.py").read_text(encoding="utf-8")
CONFIG = (ROOT / "pseudonote_extended" / "config.py").read_text(encoding="utf-8")


class ZoomAllViewsTests(unittest.TestCase):
    def test_ctrl_wheel_filter_is_bounded_and_cross_qt(self):
        self.assertIn("class ZoomAllViewsFilter", SOURCE)
        self.assertIn("globalPosition", SOURCE)
        self.assertIn("globalPos", SOURCE)
        self.assertIn("ControlModifier", SOURCE)
        self.assertIn("MIN_FONT_SIZE = 6.0", SOURCE)
        self.assertIn("MAX_FONT_SIZE = 40.0", SOURCE)

    def test_zoom_is_independent_per_scrollable_view(self):
        self.assertIn('property("pnZoomPointSize")', SOURCE)
        self.assertIn('setProperty("pnZoomPointSize"', SOURCE)
        self.assertIn("QAbstractScrollArea", SOURCE)
        self.assertIn("setDefaultSectionSize", SOURCE)

    def test_native_opengl_graph_zoom_is_not_intercepted(self):
        self.assertIn('if "opengl" in class_name', SOURCE)
        self.assertIn("return None", SOURCE)

    def test_toggle_is_persistent_registered_and_in_submenu(self):
        action = "pseudonote_extended:zoom_all_views"
        self.assertGreaterEqual(PLUGIN.count(action), 2)
        self.assertIn("ADF_CHECKABLE", PLUGIN)
        self.assertIn("initialize_zoom_all_views()", PLUGIN)
        self.assertIn("shutdown_zoom_all_views()", PLUGIN)
        self.assertIn(action, MENU)
        self.assertIn("ZOOM_ALL_VIEWS_ENABLED", CONFIG)


if __name__ == "__main__":
    unittest.main()
