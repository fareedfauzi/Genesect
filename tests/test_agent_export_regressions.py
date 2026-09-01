import ast
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "pseudonote_extended" / "agentic_analyzer.py").read_text(encoding="utf-8")


class AgentExportRegressionTests(unittest.TestCase):
    def test_agent_module_parses(self):
        ast.parse(SOURCE)

    def test_binary_overview_uses_ida_8_and_9_compatible_architecture_helper(self):
        self.assertIn("def _database_architecture", SOURCE)
        self.assertIn("ida_ida.inf_get_procname()", SOURCE)
        overview = SOURCE[SOURCE.index("def tool_binary_overview"):SOURCE.index("def tool_basic_blocks")]
        self.assertIn("_database_architecture()", overview)
        self.assertNotIn("get_inf_structure()", overview)

    def test_network_iocs_reject_decompiler_member_names(self):
        node = ast.parse(SOURCE)
        function = next(item for item in node.body if isinstance(item, ast.FunctionDef) and item.name == "_network_iocs")
        function_source = ast.get_source_segment(SOURCE, function)
        self.assertIn("item == item.lower()", function_source)

    def test_one_fully_repeated_batch_forces_synthesis(self):
        self.assertIn("all_calls_repeated = True", SOURCE)
        self.assertRegex(SOURCE, re.compile(r"if all_calls_repeated:\s+self\._must_finalize = True"))


if __name__ == "__main__":
    unittest.main()
