import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
COMPAT = (ROOT / "pseudonote_extended" / "qt_compat.py").read_text(encoding="utf-8")
PLUGIN = (ROOT / "pseudonote_extended" / "plugin.py").read_text(encoding="utf-8")
ALL_SOURCE = "\n".join(path.read_text(encoding="utf-8") for path in (ROOT / "pseudonote_extended").rglob("*.py"))


class QtBindingCompatibilityTests(unittest.TestCase):
    def test_supported_bindings_are_loaded_in_safe_order(self):
        for binding in ("PyQt5", "PySide2", "PySide6", "PyQt6"):
            self.assertIn(f'"{binding}"', COMPAT)
        self.assertIn("QT_BINDING", COMPAT)
        self.assertIn("QT_MAJOR", COMPAT)
        self.assertIn("name in sys.modules", COMPAT)
        self.assertIn("_binding_candidates", COMPAT)

    def test_qt6_scoped_enums_are_flattened_for_qt5_style_callers(self):
        self.assertIn("def _flatten_enums", COMPAT)
        for marker in ("AlignmentFlag", "KeyboardModifier", "WindowType", "ItemDataRole", "StandardButton", "SelectionBehavior"):
            self.assertIn(marker, COMPAT)

    def test_removed_qt5_methods_have_qt6_shims(self):
        self.assertIn('"exec_", owner.exec', COMPAT)
        self.assertIn('"globalPos", globalPos', COMPAT)
        self.assertIn('"pos", pos', COMPAT)
        self.assertIn("setTabStopDistance", COMPAT)

    def test_qt6_widget_enums_and_ida_form_bridge_are_supported(self):
        for marker in ("RenderHint", "ColorRole", "GraphicsItemFlag", "ViewportUpdateMode", "EchoMode", "Shape"):
            self.assertIn(marker, COMPAT)
        self.assertIn('"FormToPySideWidget", "FormToPyQtWidget"', COMPAT)

    def test_active_binding_is_reported_at_plugin_startup(self):
        self.assertIn("QT_BINDING", PLUGIN)
        self.assertIn("QT_MAJOR", PLUGIN)
        self.assertIn("Qt backend:", PLUGIN)

    def test_features_do_not_import_a_binding_directly(self):
        for binding in ("from PyQt", "import PyQt", "from PySide", "import PySide"):
            occurrences = [line for line in ALL_SOURCE.splitlines() if binding in line and "_try_import" not in line]
            self.assertEqual([], occurrences, binding)


if __name__ == "__main__":
    unittest.main()
