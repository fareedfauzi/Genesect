import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
CHAT = (ROOT / "pseudonote_extended" / "chat.py").read_text(encoding="utf-8")
AGENT = (ROOT / "pseudonote_extended" / "agentic_analyzer.py").read_text(encoding="utf-8")


class ChatStructuredDisplayTests(unittest.TestCase):
    def test_structured_tool_formatting_remains_in_autonomous_analyzer_only(self):
        self.assertNotIn('if tool_name == "stack_layout"', CHAT)
        self.assertNotIn('if tool_name == "basic_blocks"', CHAT)
        self.assertIn("readable_location(variable, argument, result)", AGENT)
        self.assertIn("return-value storage", AGENT)
        self.assertIn("Swig Object", AGENT)

    def test_basic_blocks_exclude_remote_tails_and_duplicate_edges(self):
        self.assertIn("int(func.start_ea) <= int(block.start_ea) < int(func.end_ea)", AGENT)
        self.assertIn("primary_ids = {int(block.id) for block in blocks}", AGENT)
        self.assertIn("sorted({int(item.id) for item in block.succs()} & primary_ids)", AGENT)
        self.assertNotIn('if tool_name == "basic_blocks"', CHAT)


if __name__ == "__main__":
    unittest.main()
