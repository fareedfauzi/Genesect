import pathlib
import unittest

ROOT = pathlib.Path(__file__).parents[1]
CHAT = (ROOT / "pseudonote_extended" / "chat.py").read_text(encoding="utf-8")

class PlainChatUITests(unittest.TestCase):
    def test_manual_prompt_and_shortcut_sidebar_is_present(self):
        self.assertIn("CHAT_SIDEBAR_GROUPS", CHAT)
        self.assertIn("def _build_sidebar", CHAT)
        self.assertIn('QLabel("Prompts & Shortcuts")', CHAT)
        self.assertIn('tag = "Prompt" if kind == "prompt" else "Shortcut"', CHAT)
        self.assertIn('f"[{tag}] {label}"', CHAT)

    def test_sidebar_does_not_restore_autonomous_tools(self):
        self.assertNotIn("execute_chat_tool", CHAT)
        self.assertNotIn("parse_agent_response", CHAT)
        self.assertNotIn("_request_chat_tool_followup", CHAT)

    def test_prompt_is_single_click_and_shortcut_is_double_click(self):
        self.assertIn("itemClicked.connect(self._sidebar_prompt_clicked)", CHAT)
        self.assertIn("itemDoubleClicked.connect(self._sidebar_shortcut_clicked)", CHAT)
        self.assertIn("setPlainText", CHAT)

    def test_chat_keeps_conversation_controls(self):
        for label in ("Context Preview", "Export Log", "Regenerate", "Clear Conversation"):
            self.assertIn(label, CHAT)

    def test_welcome_text_describes_conversation(self):
        self.assertIn("questions conversationally from the supplied source", CHAT)
        self.assertIn("optional prompt templates and manual PseudoNote shortcuts", CHAT)

if __name__ == "__main__":
    unittest.main()
