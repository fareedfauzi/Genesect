import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
EXPORT = (ROOT / "pseudonote_extended" / "chat_export.py").read_text(encoding="utf-8")
CHAT = (ROOT / "pseudonote_extended" / "chat.py").read_text(encoding="utf-8")
CHAIN = (ROOT / "pseudonote_extended" / "chat_chain.py").read_text(encoding="utf-8")
AGENT = (ROOT / "pseudonote_extended" / "agentic_analyzer.py").read_text(encoding="utf-8")


class ChatLogExportTests(unittest.TestCase):
    def test_shared_export_supports_markdown_and_json(self):
        self.assertIn("Markdown log (*.md);;JSON log (*.json)", EXPORT)
        self.assertIn("pseudonote.chat-log.v1", EXPORT)
        self.assertIn("chat_log_markdown", EXPORT)

    def test_single_and_chain_chat_use_shared_exporter(self):
        self.assertIn("export_chat_log", CHAT)
        self.assertNotIn('"tool_audit"', CHAT)
        self.assertIn('"context": {"decompiled_characters"', CHAT)
        self.assertIn("export_chat_log", CHAIN)
        self.assertIn('"selected_functions"', CHAIN)

    def test_agent_export_is_conversation_only_and_audit_is_separate(self):
        for marker in ("Export Log", "export_investigation_log", "export_transcript", "Export Autonomous Conversation", "on_view_audit"):
            self.assertIn(marker, AGENT)
        section = AGENT.split("def export_investigation_log", 1)[1].split("def on_user_chat", 1)[0]
        for internal in ("session_snapshot", "function_ledger", "tool_audit"):
            self.assertNotIn(internal, section)

    def test_system_prompts_are_excluded_by_default(self):
        self.assertIn("include_system=False", EXPORT)
        self.assertIn('role == "system" and not include_system', EXPORT)


if __name__ == "__main__":
    unittest.main()
