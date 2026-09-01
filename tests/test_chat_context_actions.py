import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "pseudonote_extended" / "chat.py").read_text(encoding="utf-8")


class ChatContextActionTests(unittest.TestCase):
    def test_structure_action_explains_required_variable_context(self):
        self.assertIn('payload) == "pseudonote_extended:analyze_struct"', SOURCE)
        self.assertIn("right-click directly on the variable name", SOURCE)

    def test_action_failures_stay_inside_chat(self):
        section = SOURCE[SOURCE.index("def _activate_chat_tool"):SOURCE.index("def add_message", SOURCE.index("def _activate_chat_tool"))]
        self.assertNotIn("ida_kernwin.warning", section)
        self.assertIn("self.add_message", section)


if __name__ == "__main__":
    unittest.main()
