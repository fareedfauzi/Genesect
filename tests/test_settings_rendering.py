import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
COMPONENTS = (ROOT / "pseudonote_extended" / "ui" / "components.py").read_text(encoding="utf-8")
THEME = (ROOT / "pseudonote_extended" / "ui" / "theme.py").read_text(encoding="utf-8")
VIEW = (ROOT / "pseudonote_extended" / "view.py").read_text(encoding="utf-8")


class SettingsRenderingTests(unittest.TestCase):
    def test_settings_tabs_avoid_transparent_document_mode_artifacts(self):
        self.assertIn("tabs.setDocumentMode(False)", COMPONENTS)
        self.assertIn('bar.setObjectName("settingsTabBar")', COMPONENTS)
        self.assertIn("bar.setAutoFillBackground(True)", COMPONENTS)

    def test_settings_tab_styles_are_opaque_and_scoped(self):
        self.assertIn("QTabBar#settingsTabBar", THEME)
        self.assertIn("background: {t.surface_alt}", THEME)
        self.assertNotIn("QTabWidget#settingsTabs QTabBar::tab", THEME)

    def test_settings_dialog_does_not_override_native_paint_attributes(self):
        self.assertNotIn("self.setAttribute(QtCore.Qt.WA_StyledBackground, True)", VIEW)

    def test_shared_themes_do_not_override_ida_native_painting(self):
        theme = (ROOT / "pseudonote_extended" / "ui" / "theme.py").read_text(encoding="utf-8")
        workspace = (ROOT / "pseudonote_extended" / "ui" / "mac_workspace.py").read_text(encoding="utf-8")
        proposals = (ROOT / "pseudonote_extended" / "ui" / "proposals.py").read_text(encoding="utf-8")
        self.assertNotIn("def stabilize_widget_rendering", theme)
        self.assertNotIn("WA_NoSystemBackground", theme)
        self.assertNotIn("WA_OpaquePaintEvent", theme)
        self.assertNotIn("stabilize_widget_rendering", workspace)
        self.assertIn('QWidget[pnMacWorkspace="true"]', workspace)
        self.assertIn("ThemeManager(self, \"system\")", proposals)
        self.assertIn("super().__init__(None)", proposals)
        self.assertIn("super().__init__(None)", VIEW)
        self.assertIn("self.setMinimumWidth(860)", VIEW)
        self.assertNotIn("self.setWindowModality(QtCore.Qt.ApplicationModal)", VIEW)
        self.assertNotIn("def _refresh_first_frame", VIEW)

    def test_pseudocode_settings_uses_safe_disassembly_host(self):
        handlers = (ROOT / "pseudonote_extended" / "handlers.py").read_text(encoding="utf-8")
        self.assertIn("source_type == idaapi.BWN_PSEUDOCODE", handlers)
        self.assertIn('open_disasm_window("PseudoNote Settings Host")', handlers)
        self.assertIn("activate_widget(source_widget, True)", handlers)
        self.assertIn("close_widget(safe_widget, close_later)", handlers)


if __name__ == "__main__":
    unittest.main()
