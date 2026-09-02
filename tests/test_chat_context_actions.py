import pathlib
import unittest

ROOT = pathlib.Path(__file__).parents[1]
CHAT = (ROOT / "pseudonote_extended" / "chat.py").read_text(encoding="utf-8")

class PlainChatContextTests(unittest.TestCase):
    def test_function_context_is_embedded_in_system_prompt(self):
        self.assertIn("def build_chat_prompt(function_name, decompiled_code, caller_context=", CHAT)
        self.assertIn("Source:", CHAT)

    def test_navigation_rebuilds_plain_context(self):
        section = CHAT[CHAT.index("    def change_context"):CHAT.index("    def save_history")]
        self.assertIn("self.system_prompt = build_chat_prompt(", section)

if __name__ == "__main__":
    unittest.main()
