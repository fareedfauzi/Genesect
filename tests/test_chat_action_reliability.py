import pathlib
import unittest

ROOT = pathlib.Path(__file__).parents[1]
CHAT = (ROOT / "pseudonote_extended" / "chat.py").read_text(encoding="utf-8")

class PlainChatActionTests(unittest.TestCase):
    def test_model_cannot_autonomously_mutate_ida(self):
        for token in ("Enable IDA changes", "_confirm_chat_tool", "execute_chat_tool"):
            self.assertNotIn(token, CHAT)

    def test_manual_mutating_shortcuts_require_confirmation(self):
        self.assertIn("CONFIRM_SIDEBAR_SHORTCUTS", CHAT)
        self.assertIn('"Confirm PseudoNote Shortcut"', CHAT)
        self.assertIn("QMessageBox.question", CHAT)

    def test_chat_still_supports_request_cancellation(self):
        self.assertIn("def stop_request(self):", CHAT)
        self.assertIn("client.cancel_request(request_id)", CHAT)

if __name__ == "__main__":
    unittest.main()
