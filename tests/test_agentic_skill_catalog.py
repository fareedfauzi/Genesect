import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "pseudonote_extended" / "agentic_analyzer.py").read_text(encoding="utf-8")


class AgenticSkillCatalogTests(unittest.TestCase):
    def test_structured_read_tools_are_catalogued_and_dispatched(self):
        for tool in (
            "binary_overview", "list_imports", "list_exports", "list_segments",
            "list_entrypoints", "basic_blocks", "stack_layout", "function_evidence", "int_convert",
        ):
            self.assertIn(f'"{tool}":', SOURCE, tool)

    def test_bounded_structured_collectors_exist(self):
        self.assertIn("def tool_binary_overview", SOURCE)
        self.assertIn("def tool_basic_blocks", SOURCE)
        self.assertIn("def tool_stack_layout", SOURCE)
        self.assertIn("def tool_function_evidence", SOURCE)
        self.assertIn("max(1, min(int(max_blocks or 500), 2000))", SOURCE)
        self.assertIn("max(1, min(int(max_items or 200), 1000))", SOURCE)

    def test_autonomous_triage_uses_overview_and_decompiler_first(self):
        self.assertIn("First obtain a compact binary_overview", SOURCE)
        self.assertIn("then decompile the", SOURCE)
        self.assertIn("only to resolve specific uncertainties", SOURCE)


if __name__ == "__main__":
    unittest.main()
