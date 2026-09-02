import pathlib
import unittest

ROOT = pathlib.Path(__file__).parents[1]
CHAT = (ROOT / "pseudonote_extended" / "chat.py").read_text(encoding="utf-8")

class PlainChatProtocolTests(unittest.TestCase):
    def test_system_prompt_forbids_tool_protocol(self):
        self.assertIn("Do not request tools, emit tool-call JSON, or make autonomous decisions.", CHAT)
        self.assertNotIn("chat_tool_execution_type", CHAT)

if __name__ == "__main__":
    unittest.main()
