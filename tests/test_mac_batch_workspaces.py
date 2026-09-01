import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
MAC = (ROOT / "pseudonote_extended" / "ui" / "mac_workspace.py").read_text(encoding="utf-8")
COMPONENTS = (ROOT / "pseudonote_extended" / "ui" / "components.py").read_text(encoding="utf-8")


class TestCompactMacWorkspace(unittest.TestCase):
    def test_dense_controls_use_compact_metrics(self):
        self.assertIn("min-height: 26px", MAC)
        self.assertIn("font-size: 9pt", MAC)
        self.assertIn("padding: 0 9px", MAC)
        self.assertIn("apply_ui_font(widget, 9.5)", MAC)

    def test_workspace_actions_are_compact_tab_row_controls(self):
        source = (ROOT / "pseudonote_extended" / "view.py").read_text(encoding="utf-8")
        self.assertIn("setCornerWidget(self.corner_widget", source)
        self.assertIn("setCornerWidget(self.note_corner_widget", source)
        self.assertIn("control.setFixedHeight(26)", source)
        self.assertIn('setObjectName("workspaceLanguageSelector")', source)
        self.assertIn("min-height: 22px; max-height: 22px", source)

    def test_custom_prompt_points_to_conversational_tools(self):
        source = (ROOT / "pseudonote_extended" / "view.py").read_text(encoding="utf-8")
        self.assertIn("Need a deeper conversation?", source)
        self.assertIn("PseudoNote Chat for the current", source)
        self.assertIn("Function Chain Chat", source)
        self.assertIn('setProperty("pnMuted", True)', source)
        self.assertIn('QPushButton("Open Function Chat")', source)
        self.assertIn('QPushButton("Open Chain Chat")', source)
        self.assertIn('process_ui_action("pseudonote_extended:ask_chat")', source)
        self.assertIn('process_ui_action("pseudonote_extended:ask_chat_chain")', source)

    def test_chain_chat_graph_action_is_clear_and_primary(self):
        source = (ROOT / "pseudonote_extended" / "chat_chain.py").read_text(encoding="utf-8")
        self.assertIn('QPushButton("Build Function Graph")', source)
        self.assertIn('self.build_btn.setProperty("pnVariant", "primary")', source)
        self.assertNotIn('self.build_btn.setObjectName("primary")', source)
        self.assertNotIn("Load Functions List", source)

    def test_disabled_primary_buttons_use_neutral_readable_contrast(self):
        self.assertIn(
            'background: {t.surface_alt}; border-color: {t.border_strong}; color: {t.text_muted};',
            MAC,
        )
        self.assertNotIn(
            'background: {t.selection}; border-color: {t.accent}; color: {t.accent_pressed};',
            MAC,
        )

    def test_bulk_progress_bars_are_prominent(self):
        for name in ("renamer.py", "var_renamer.py", "analyzer.py", "summarizer.py", "deep_analyzer.py"):
            source = (ROOT / "pseudonote_extended" / name).read_text(encoding="utf-8")
            self.assertIn('setProperty("pnProminent", True)', source, name)
            self.assertIn("setFixedHeight(20)", source, name)
        self.assertIn('QProgressBar[pnProminent="true"]', MAC)

    def test_bulk_rate_limit_defaults_are_zero(self):
        source = (ROOT / "pseudonote_extended" / "config.py").read_text(encoding="utf-8")
        for field in ("cooldown_seconds", "bulk_cooldown", "var_cooldown", "analyze_cooldown", "deep_cooldown"):
            self.assertIn(f"self.{field} = 0", source, field)

    def test_settings_tabs_scroll_without_truncating_labels(self):
        self.assertIn("def configure_settings_tabs", COMPONENTS)

    def test_summarizer_report_tabs_have_high_dpi_safe_widths(self):
        source = (ROOT / "pseudonote_extended" / "summarizer.py").read_text(encoding="utf-8")
        self.assertIn('setObjectName("summarizerTabs")', source)
        self.assertNotIn("self.tabs.tabBar().setExpanding(True)", source)
        self.assertNotIn("self.tabs.tabBar().setUsesScrollButtons(False)", source)
        self.assertIn("QTabWidget#summarizerTabs QTabBar::tab", MAC)
        self.assertIn("min-width: 150px", MAC)
        self.assertIn("setUsesScrollButtons(True)", COMPONENTS)
        self.assertIn("setExpanding(False)", COMPONENTS)
        self.assertIn("setElideMode(QtCore.Qt.ElideNone)", COMPONENTS)
        self.assertIn('QTabBar#settingsTabBar::tab', MAC)

    def test_content_tabs_scroll_without_eliding_labels(self):
        self.assertIn("def configure_content_tabs", COMPONENTS)
        self.assertGreaterEqual(COMPONENTS.count("setUsesScrollButtons(True)"), 2)
        self.assertGreaterEqual(COMPONENTS.count("setElideMode(QtCore.Qt.ElideNone)"), 2)
        for name in ("view.py", "summarizer.py", "deep_analyzer.py", "floss_strings.py"):
            source = (ROOT / "pseudonote_extended" / name).read_text(encoding="utf-8")
            self.assertIn("configure_content_tabs", source, name)

    def test_deep_analyzer_result_tabs_are_full_width_and_unclipped(self):
        source = (ROOT / "pseudonote_extended" / "deep_analyzer.py").read_text(encoding="utf-8")
        self.assertIn("self.tabs.setUsesScrollButtons(False)", source)
        self.assertIn("self.tabs.tabBar().setUsesScrollButtons(False)", source)
        self.assertIn("self.tabs.tabBar().setExpanding(False)", source)
        self.assertIn('QTabBar::tab { min-width: 140px; }', source)

    def test_legacy_analyzer_styles_do_not_override_shared_theme(self):
        for name in ("chat_chain.py", "summarizer.py", "deep_analyzer.py"):
            source = (ROOT / "pseudonote_extended" / name).read_text(encoding="utf-8")
            self.assertNotIn("self.setStyleSheet(STYLES_ANALYZER)", source, name)


class MacBatchWorkspaceTests(unittest.TestCase):
    def test_shared_style_has_mac_surfaces_and_controls(self):
        self.assertIn("border-radius: 12px", MAC)
        self.assertIn("QTableView, QTableWidget, QTreeView, QTreeWidget", MAC)
        self.assertIn("QTabBar::tab:selected", MAC)
        self.assertIn("QScrollBar::handle:vertical", MAC)
        self.assertIn('QPushButton[pnVariant="primary"]', MAC)
        self.assertIn('QPushButton[pnVariant="primary"]:disabled', MAC)
        self.assertIn('QPushButton#primary:disabled', MAC)

    def test_requested_workspaces_apply_shared_theme(self):
        for name in ("renamer.py", "var_renamer.py", "summarizer.py", "deep_analyzer.py"):
            source = (ROOT / "pseudonote_extended" / name).read_text(encoding="utf-8")
            self.assertIn("apply_mac_workspace(self)", source, name)

    def test_each_workspace_has_visible_professional_header(self):
        expected = {
            "renamer.py": "Bulk Function Renamer",
            "var_renamer.py": "Bulk Variable Renamer",
            "summarizer.py": "Function Chain Summarizer",
            "deep_analyzer.py": "Deep Analyzer with Report",
        }
        for name, title in expected.items():
            source = (ROOT / "pseudonote_extended" / name).read_text(encoding="utf-8")
            self.assertIn(f'QLabel("{title}")', source, name)
            self.assertIn('setProperty("pnTitle", True)', source, name)

    def test_primary_and_stop_actions_have_roles(self):
        for name in ("renamer.py", "var_renamer.py", "summarizer.py", "deep_analyzer.py"):
            source = (ROOT / "pseudonote_extended" / name).read_text(encoding="utf-8")
            self.assertIn('setProperty("pnVariant", "primary")', source, name)
            self.assertIn('setProperty("pnVariant", "danger")', source, name)


if __name__ == "__main__":
    unittest.main()
