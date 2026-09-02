import pathlib
import unittest

ROOT = pathlib.Path(__file__).parents[1]
CHAT = (ROOT / "pseudonote_extended" / "chat.py").read_text(encoding="utf-8")

class PlainChatRuntimeTests(unittest.TestCase):
    def test_chat_does_not_import_tool_runtime(self):
        self.assertNotIn("chat_tool_runtime", CHAT)
        self.assertNotIn("execute_chat_tool", CHAT)
        self.assertNotIn("parse_agent_response", CHAT)

    def test_chat_sends_history_directly_to_model(self):
        self.assertIn("AI_CLIENT.query_model_async(self.history, callback, on_chunk=on_chunk)", CHAT)

    def test_sidebar_shortcuts_are_only_user_initiated(self):
        self.assertIn("def _sidebar_shortcut_clicked", CHAT)
        self.assertIn("itemDoubleClicked.connect(self._sidebar_shortcut_clicked)", CHAT)

if __name__ == "__main__":
    unittest.main()
