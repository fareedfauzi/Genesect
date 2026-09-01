import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
CHAT = (ROOT / "pseudonote_extended" / "chat.py").read_text(encoding="utf-8")
RUNTIME = (ROOT / "pseudonote_extended" / "chat_tool_runtime.py").read_text(encoding="utf-8")


class ChatActionReliabilityTests(unittest.TestCase):
    def test_chat_exposes_reviewed_ida_change_control(self):
        self.assertIn('QCheckBox("Enable IDA changes")', CHAT)
        self.assertIn("self.allow_changes_cb.setChecked(True)", CHAT)
        self.assertIn("self.tool_policy.allow_mutations = self.allow_changes_cb.isChecked()", CHAT)

    def test_cancelled_change_stops_instead_of_retrying(self):
        self.assertIn("change_cancelled = False", CHAT)
        self.assertIn("changes_disabled = False", CHAT)
        self.assertIn("IDA change cancelled. Nothing was modified.", CHAT)
        self.assertIn("IDA changes are disabled.", CHAT)
        self.assertIn("self.input_box.setEnabled(True)", CHAT)

    def test_identical_tool_calls_are_suppressed_per_request(self):
        self.assertIn("self._chat_tool_signatures = set()", CHAT)
        self.assertIn("Identical tool call already attempted", CHAT)

    def test_function_tools_fall_back_to_current_chat_function(self):
        self.assertIn('"stack_layout",', RUNTIME)
        self.assertIn("func = ida_funcs.get_func(int(address))", RUNTIME)
        self.assertIn('args["ea"] = int(func.start_ea)', RUNTIME)

    def test_confirmation_dialog_has_explicit_actions(self):
        self.assertIn('dialog.addButton("Apply Change"', CHAT)
        self.assertIn('dialog.addButton("Cancel"', CHAT)


if __name__ == "__main__":
    unittest.main()
