import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "pseudonote_extended" / "agentic_analyzer.py").read_text(encoding="utf-8")
ACTIVE_UI = SOURCE[
    SOURCE.index("def _setup_professional_ui"):
    SOURCE.index("def _refresh_agent_dashboard")
]


class AgenticUIWorkflowTests(unittest.TestCase):
    def test_workspace_uses_shared_professional_theme_components(self):
        self.assertIn("ThemeManager(self.parent, \"system\")", SOURCE)
        self.assertIn("PageHeader(", SOURCE)
        self.assertIn('Card("Activity")', ACTIVE_UI)
        self.assertIn("StatusBadge(\"Ready\"", SOURCE)

    def test_layout_keeps_agentic_activity_focused(self):
        self.assertIn('Card("Activity")', ACTIVE_UI)
        self.assertIn("self.scroll_layout", ACTIVE_UI)
        self.assertNotIn("QSplitter(QtCore.Qt.Horizontal)", ACTIVE_UI)
        self.assertNotIn('Card("Tools")', ACTIVE_UI)
        self.assertNotIn("Evidence notebook", ACTIVE_UI)
        self.assertNotIn("Investigation mission", ACTIVE_UI)
        self.assertNotIn('QPushButton("Knowledge")', ACTIVE_UI)

    def test_manual_tool_sidebar_is_not_in_agentic_workspace(self):
        self.assertNotIn("self.tools_tree", ACTIVE_UI)
        self.assertNotIn("_insert_tool_intent", SOURCE)

    def test_ida_changes_toggle_is_visible_in_header(self):
        self.assertIn('ToggleSwitch("Enable IDA changes")', ACTIVE_UI)
        self.assertIn("header.add_action(self.allow_changes_cb)", ACTIVE_UI)
        self.assertNotIn("controls.addWidget(self.allow_changes_cb)", ACTIVE_UI)

    def test_controls_are_floating_buttons_with_clear_labels(self):
        self.assertIn('QPushButton("Start Investigation")', SOURCE)
        self.assertIn('self.btn_start.setProperty("pnVariant", "primary")', SOURCE)
        self.assertIn('QPushButton("Pause")', SOURCE)
        self.assertIn('QPushButton("Resume")', SOURCE)
        self.assertIn("self.btn_pause.setVisible(False)", SOURCE)
        self.assertIn("self.btn_continue.setVisible(False)", SOURCE)
        self.assertIn('QPushButton("Stop")', ACTIVE_UI)
        self.assertIn('self.btn_stop.setProperty("pnVariant", "danger")', ACTIVE_UI)
        self.assertIn("self.btn_stop.clicked.connect(self.on_stop)", ACTIVE_UI)

    def test_stop_cancels_request_and_blocks_late_callbacks(self):
        self.assertIn("def on_stop(self):", SOURCE)
        self.assertIn("def _finish_stopped(self, message):", SOURCE)
        self.assertIn("self.stop_active_request()", SOURCE)
        self.assertIn("self._request_generation += 1", SOURCE)
        self.assertIn("request_generation != self._request_generation", SOURCE)
        self.assertIn("self._remove_live_bubble()", SOURCE)

    def test_host_enforces_final_answer_after_bounded_tool_rounds(self):
        self.assertIn("self._max_tool_rounds = 12", SOURCE)
        self.assertIn("self._max_tool_rounds = 1 if self._focused_request else 8", SOURCE)
        self.assertIn("if self._must_finalize:", SOURCE)
        self.assertIn("ignored the final-answer limit twice", SOURCE)

    def test_steering_input_is_compact(self):
        self.assertIn("self.chat_input.input_box.setMaximumHeight(60)", ACTIVE_UI)
        self.assertIn("self.chat_input.setMaximumHeight(78)", ACTIVE_UI)

    def test_dashboard_updates_for_running_paused_and_complete_states(self):
        self.assertIn('self.agent_status_badge.setText("Running")', SOURCE)
        self.assertIn('self.agent_status_badge.setText("Paused")', SOURCE)
        self.assertIn('self.agent_status_badge.setText("Complete")', SOURCE)
        self.assertIn("self._refresh_agent_dashboard()", SOURCE)

    def test_focused_requests_use_fast_ioc_path(self):
        self.assertIn("def _looks_like_focused_request", SOURCE)
        self.assertIn('"search_strings": lambda:', SOURCE)
        self.assertIn("max_steps=12, max_seconds=180", SOURCE)
        self.assertIn("TOOL LIMIT REACHED: Return action=final now", SOURCE)
        self.assertIn("if repeated >= 2", SOURCE)

    def test_agentic_workspace_has_native_mac_style_finish(self):
        self.assertIn("def _agentic_ui_font", SOURCE)
        self.assertIn("return ui_font(11.0)", SOURCE)
        self.assertIn('self.parent.setObjectName("agenticRoot")', ACTIVE_UI)
        self.assertIn("self._apply_agentic_visual_style(tokens)", ACTIVE_UI)
        self.assertIn('border-radius: 12px', SOURCE)
        self.assertIn("bubble.bubble.setMinimumWidth(300)", SOURCE)
        self.assertIn('self.chat_input.send_btn.setText("↑")', ACTIVE_UI)


if __name__ == "__main__":
    unittest.main()
