import pathlib
import unittest


SOURCE = (pathlib.Path(__file__).parents[1] / "pseudonote_extended" / "agentic_analyzer.py").read_text(encoding="utf-8")


class AgentIocEvidenceTests(unittest.TestCase):
    def test_wide_strings_are_read_with_the_ida_string_type(self):
        self.assertIn("def _decode_ida_string", SOURCE)
        self.assertIn("idc.get_str_type(ea)", SOURCE)
        self.assertIn('raw.decode("utf-16-le"', SOURCE)
        evidence = SOURCE[SOURCE.index("def tool_function_evidence"):SOURCE.index("def tool_int_convert")]
        self.assertIn("_decode_ida_string(ref)", evidence)

    def test_imports_and_symbols_are_preferred_over_fake_sub_names(self):
        self.assertIn("def _resolved_ida_name", SOURCE)
        xrefs = SOURCE[SOURCE.index("def tool_get_xrefs"):SOURCE.index("def tool_search_strings")]
        self.assertGreaterEqual(xrefs.count("_resolved_ida_name(ref)"), 2)
        self.assertIn('"callee_details"', SOURCE)

    def test_function_evidence_extracts_and_records_network_iocs(self):
        self.assertIn("def _network_iocs", SOURCE)
        self.assertIn('"network_iocs": iocs[:100]', SOURCE)
        self.assertIn('tool_name == "function_evidence"', SOURCE)
        self.assertIn('["network", "ioc"]', SOURCE)


if __name__ == "__main__":
    unittest.main()
