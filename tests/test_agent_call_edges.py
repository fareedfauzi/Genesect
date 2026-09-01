import pathlib
import unittest


SOURCE = (pathlib.Path(__file__).parents[1] / "pseudonote_extended" / "agentic_analyzer.py").read_text(encoding="utf-8")


class AgentCallEdgeTests(unittest.TestCase):
    def test_call_graph_uses_typed_call_xrefs_only(self):
        self.assertIn("idaapi.fl_JN, idaapi.fl_JF", SOURCE)
        self.assertIn("def _edge_kind", SOURCE)
        self.assertIn("def _interfunction_callees", SOURCE)
        self.assertIn("if xref.type not in _CALL_XREF_TYPES", SOURCE)
        self.assertIn("target_func.start_ea == func.start_ea", SOURCE)

    def test_unresolved_indirect_calls_are_reported_not_silently_dropped(self):
        self.assertIn('"unresolved_indirect_calls"', SOURCE)
        self.assertIn("idc.print_insn_mnem(head)", SOURCE)

    def test_function_scoped_calls_are_canonicalized(self):
        self.assertIn("FUNCTION_SCOPED_AGENT_TOOLS", SOURCE)
        self.assertIn('args["ea"] = f"0x{int(requested_func.start_ea):X}"', SOURCE)

    def test_evidence_no_longer_collects_untyped_code_refs_as_callees(self):
        start = SOURCE.index("def tool_function_evidence")
        end = SOURCE.index("def tool_int_convert", start)
        section = SOURCE[start:end]
        self.assertIn("_interfunction_callees(func)", section)
        self.assertNotIn("idautils.CodeRefsFrom", section)


if __name__ == "__main__":
    unittest.main()
