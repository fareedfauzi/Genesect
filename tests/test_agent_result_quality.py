import importlib.util
import pathlib
import sys
import unittest


ROOT = pathlib.Path(__file__).parents[1]
PATH = ROOT / "pseudonote_extended" / "agent_runtime.py"
SPEC = importlib.util.spec_from_file_location("pseudonote_extended_agent_result_quality", PATH)
runtime = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = runtime
SPEC.loader.exec_module(runtime)
ANALYZER = (ROOT / "pseudonote_extended" / "agentic_analyzer.py").read_text(encoding="utf-8")


class AgentResultQualityTests(unittest.TestCase):
    def test_empty_structured_and_negative_results_are_not_progress(self):
        for value in ("[]", "{}", "No matching IDB strings found.", "No findings"):
            self.assertEqual(runtime.result_status(value), "empty", value)

    def test_decompiler_is_paginated(self):
        self.assertIn("def tool_decompile(ea, start_line=0, max_lines=200)", ANALYZER)
        self.assertIn("request start_line=", ANALYZER)
        self.assertIn("_full_decompile_text(func.start_ea)", ANALYZER)

    def test_binary_overview_preserves_capability_imports(self):
        self.assertIn('"capability_imports": capability_imports[:500]', ANALYZER)
        self.assertIn('"imports_truncated": len(imports) > 100', ANALYZER)


if __name__ == "__main__":
    unittest.main()
