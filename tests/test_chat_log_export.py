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
        self.assertIn('"tool_audit"', CHAT)
        self.assertIn("export_chat_log", CHAIN)
        self.assertIn('"selected_functions"', CHAIN)

    def test_agent_exports_transcript_session_report_and_audit(self):
        for marker in ("Export Log", "export_investigation_log", "export_transcript", "session_snapshot", "final_analysis", "tool_audit"):
            self.assertIn(marker, AGENT)

    def test_system_prompts_are_excluded_by_default(self):
        self.assertIn("include_system=False", EXPORT)
        self.assertIn('role == "system" and not include_system', EXPORT)


if __name__ == "__main__":
    unittest.main()
