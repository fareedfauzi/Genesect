import pathlib
import unittest

ROOT = pathlib.Path(__file__).parents[1]
CHAT = (ROOT / "pseudonote_extended" / "chat.py").read_text(encoding="utf-8")

class PlainChatDecisionTests(unittest.TestCase):
    def test_chat_has_no_autonomous_decision_controller(self):
        for token in ("_chat_tool_rounds", "_request_chat_tool_followup", "_try_direct_read_request"):
            self.assertNotIn(token, CHAT)

    def test_model_text_is_displayed_directly(self):
        section = CHAT[CHAT.index("    def handle_response"):CHAT.index("    def OnClose")]
        self.assertIn("self.add_message(response, is_user=False)", section)
        self.assertNotIn("envelope", section)

if __name__ == "__main__":
    unittest.main()
