import pathlib
import unittest


SOURCE = (pathlib.Path(__file__).parents[1] / "pseudonote_extended" / "handlers.py").read_text(encoding="utf-8")
SECTION = SOURCE[SOURCE.index("# IDA-View Advanced Copy handlers"):SOURCE.index("# Function Copy Mapper")]


class AdvancedCopyWorkflowTests(unittest.TestCase):
    def test_selection_uses_invoking_widget_and_validates_exact_range(self):
        self.assertIn("read_range_selection(widget)", SECTION)
        self.assertIn("validate_byte_range(", SECTION)
        self.assertIn("raw is None or len(raw) != size", SECTION)

    def test_copy_input_and_output_are_bounded(self):
        self.assertIn("_MAX_ADVANCED_COPY_BYTES = 2 * 1024 * 1024", SECTION)
        self.assertIn("_MAX_ADVANCED_COPY_OUTPUT = 10_000_000", SECTION)
        self.assertIn("_MAX_ADVANCED_COPY_INSTRUCTIONS = 200000", SECTION)
        self.assertIn("Selection exceeds the 200,000-instruction safety limit", SECTION)

    def test_operand_masking_uses_operand_boundaries(self):
        self.assertIn("def mask_operand(op):", SECTION)
        self.assertIn("end = min(later) if later else insn.size", SECTION)
        self.assertNotIn("for i in range(op.offb, insn.size)", SECTION)

    def test_yara_rule_uses_masked_pattern_and_requires_stable_bytes(self):
        self.assertIn('mask_mode = "yara_mask" if self.mode == "yara_rule"', SECTION)
        self.assertIn("if concrete < 4:", SECTION)
        self.assertIn("source = \\\"PseudoNote Extended\\\"", SECTION)

    def test_python_and_c_outputs_are_readable_and_sized(self):
        self.assertIn("def _format_python_bytes", SECTION)
        self.assertIn("def _format_c_array", SECTION)
        self.assertIn("static const uint8_t data[{len(values)}]", SECTION)

    def test_disassembly_includes_addresses_and_rejects_empty_selection(self):
        self.assertIn('lines.append(f"0x{ea:X}:', SECTION)
        self.assertIn("contains no decoded instructions", SECTION)

    def test_modes_and_view_context_are_restricted(self):
        self.assertIn("if self.mode not in _COPY_MODES", SECTION)
        self.assertIn("idaapi.BWN_DISASM, idaapi.BWN_DISASMS", SECTION)

    def test_copy_actions_are_visible_in_pseudocode_submenu(self):
        self.assertIn("idaapi.BWN_PSEUDOCODE", SECTION)
        self.assertIn("_resolve_advanced_copy_range(ctx.widget)", SECTION)
        self.assertIn("falls back to the decoded item at that address", SECTION)


if __name__ == "__main__":
    unittest.main()
