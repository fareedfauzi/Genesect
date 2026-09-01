import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "pseudonote_extended" / "chat.py").read_text(encoding="utf-8")


class ChatToolsUIWorkflowTests(unittest.TestCase):
    def test_manual_tools_sidebar_belongs_to_regular_chat(self):
        self.assertIn("CHAT_TOOL_GROUPS = (", SOURCE)
        self.assertIn("workspace = QtWidgets.QSplitter(QtCore.Qt.Horizontal)", SOURCE)
        self.assertIn("workspace.addWidget(self._build_tools_panel(colors))", SOURCE)
        self.assertIn('QtWidgets.QLabel("Tools")', SOURCE)

    def test_prompts_use_single_click_but_workflows_require_double_click(self):
        self.assertIn("self.tools_tree.setFocusPolicy(QtCore.Qt.NoFocus)", SOURCE)
        self.assertIn("self.tools_tree.setSelectionMode(QtWidgets.QAbstractItemView.NoSelection)", SOURCE)
        self.assertIn("self.tools_tree.itemClicked.connect(self._activate_chat_prompt)", SOURCE)
        self.assertIn("self.tools_tree.itemDoubleClicked.connect(self._activate_chat_action)", SOURCE)
        self.assertIn('== "prompt"', SOURCE)
        self.assertIn('== "action"', SOURCE)

    def test_rename_and_comment_workflows_require_confirmation(self):
        self.assertIn("CONFIRM_CHAT_ACTIONS = {", SOURCE)
        self.assertIn('"pseudonote_extended:rename_function"', SOURCE)
        self.assertIn('"pseudonote_extended:rename_function_malware"', SOURCE)
        self.assertIn('"pseudonote_extended:rename_variables"', SOURCE)
        self.assertIn('"pseudonote_extended:add_comments"', SOURCE)
        self.assertIn("QtWidgets.QMessageBox.question(", SOURCE)
        self.assertIn("Are you sure you want to {confirmation}?", SOURCE)

    def test_analysis_tools_prepare_editable_chat_prompt(self):
        self.assertIn('("Explain function", "prompt"', SOURCE)
        self.assertIn('("Find IOCs / C2", "prompt"', SOURCE)
        self.assertIn("self.input_box.input_box.setPlainText(str(payload))", SOURCE)
        self.assertIn("self.input_box.setFocus()", SOURCE)

    def test_investigation_skills_category_is_not_exposed(self):
        self.assertNotIn('("Investigation Skills", (', SOURCE)
        for label in (
            "Survey binary", "Trace data flow", "Recover structure", "Compare with callees",
            "Analyze network protocol", "Find crypto behavior",
        ):
            self.assertNotIn(f'("{label}", "prompt"', SOURCE)

    def test_tool_orchestration_repairs_invalid_envelopes_without_showing_json(self):
        self.assertIn("Correcting invalid tool request...", SOURCE)
        self.assertIn("split additional calls into a later round", SOURCE)
        self.assertIn("stopped without displaying protocol JSON", SOURCE)

    def test_duplicate_tool_call_does_not_prematurely_end_investigation(self):
        self.assertNotIn("if duplicate_call:", SOURCE)
        self.assertIn("Skipped: Identical tool call already attempted", SOURCE)

    def test_tools_show_ai_or_local_tool_tags(self):
        self.assertIn('return "Tool" if direct_read_tool(payload) else "AI"', SOURCE)
        self.assertIn('QtWidgets.QTreeWidgetItem([f"[{execution_type}] {label}"])', SOURCE)
        self.assertIn("Click prompts", SOURCE)
        self.assertIn("Double-click tools and workflows", SOURCE)
        self.assertIn('item.setData(0, role + 2, execution_type)', SOURCE)

    def test_ida_tools_reuse_reviewed_existing_workflows(self):
        self.assertIn('"pseudonote_extended:rename_function"', SOURCE)
        self.assertIn('"pseudonote_extended:rename_variables"', SOURCE)
        self.assertIn('"pseudonote_extended:suggest_function_prototype"', SOURCE)
        self.assertIn('"pseudonote_extended:add_comments"', SOURCE)
        self.assertIn("ida_hexrays.open_pseudocode(self.address, 0)", SOURCE)
        self.assertIn("ida_kernwin.process_ui_action(str(payload))", SOURCE)

    def test_welcome_text_no_longer_claims_ida_actions_are_unavailable(self):
        self.assertNotIn("I cannot directly perform IDA actions", SOURCE)
        self.assertIn("Use the Tools sidebar", SOURCE)

    def test_chat_bubbles_resize_with_the_viewport(self):
        self.assertIn("class ResponsiveChatScrollArea", SOURCE)
        self.assertIn("def set_available_width", SOURCE)
        self.assertIn("minimum_ratio = 0.24 if self.is_user else 0.38", SOURCE)
        self.assertIn("self.scroll.viewportResized.connect(self._resize_message_bubbles)", SOURCE)

    def test_send_button_uses_requested_glyph(self):
        self.assertIn('self.send_btn = QtWidgets.QPushButton("⌲")', SOURCE)

    def test_chain_chat_reuses_responsive_bubbles(self):
        chain = (ROOT / "pseudonote_extended" / "chat_chain.py").read_text(encoding="utf-8")
        self.assertIn("ResponsiveChatScrollArea", chain)
        self.assertIn("viewportResized.connect(self._resize_chat_bubbles)", chain)


if __name__ == "__main__":
    unittest.main()
