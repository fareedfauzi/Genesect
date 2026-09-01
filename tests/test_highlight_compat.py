import pathlib
import unittest


HIGHLIGHT = pathlib.Path(__file__).resolve().parents[1] / "pseudonote_extended" / "highlight.py"
PLUGIN = HIGHLIGHT.parent / "plugin.py"


class HighlightCompatibilityTests(unittest.TestCase):
    def test_ida_83_func_printed_callback_is_supported(self):
        source = HIGHLIGHT.read_text(encoding="utf-8-sig")
        self.assertIn("def func_printed(self, cfunc):", source)

    def test_pseudocode_and_disassembly_states_are_independent(self):
        source = HIGHLIGHT.read_text(encoding="utf-8-sig")
        self.assertIn("pseudocode_highlight_enabled = False", source)
        self.assertIn("disasm_highlight_enabled = True", source)

    def test_disassembly_highlighting_runs_on_the_initial_ui_tick(self):
        source = PLUGIN.read_text(encoding="utf-8-sig")
        self.assertIn("create_default_visual_hooks()", source)
        lifecycle = (HIGHLIGHT.parent / "default_visuals.py").read_text(encoding="utf-8-sig")
        self.assertIn("refresh_disasm_highlighting()", lifecycle)
        self.assertIn("def screen_ea_changed", lifecycle)

    def test_disassembly_restores_only_owned_unchanged_colors(self):
        source = HIGHLIGHT.read_text(encoding="utf-8")
        self.assertIn("_disasm_owned_colors = {}", source)
        self.assertIn("if idaapi.get_item_color(ea) == applied:", source)
        self.assertNotIn("for ea in range(start, end)", source)

    def test_instruction_detection_uses_mnemonics_not_substrings(self):
        source = HIGHLIGHT.read_text(encoding="utf-8")
        self.assertIn("_CALL_OR_TAIL_MNEMONICS", source)
        self.assertIn("idc.print_insn_mnem(ea)", source)
        self.assertNotIn('if "call" in lower_line', source)

    def test_highlighting_is_bounded(self):
        source = HIGHLIGHT.read_text(encoding="utf-8")
        self.assertIn("_MAX_PSEUDOCODE_LINES = 5000", source)
        self.assertIn("_MAX_DISASM_ITEMS = 200000", source)

    def test_pseudocode_ignores_strings_comments_and_signature(self):
        source = HIGHLIGHT.read_text(encoding="utf-8")
        self.assertIn("def _clean_pseudocode_for_matching", source)
        self.assertIn("def _strip_block_comments", source)
        self.assertIn("looks_like_declaration", source)
        self.assertIn("body_started = False", source)
        self.assertIn("not body_started and clean_line.endswith", source)
        self.assertIn("shape-only detection hid valid call sites", source)

    def test_enabling_pseudocode_highlight_sets_right_margin_to_120(self):
        source = HIGHLIGHT.read_text(encoding="utf-8")
        self.assertIn("PSEUDOCODE_HIGHLIGHT_RIGHT_MARGIN = 120", source)
        self.assertIn('change_config("RIGHT_MARGIN = %d"', source)
        self.assertIn("configure_highlight_right_margin()", source)
        self.assertIn("vu.refresh_view(True)", source)

    def test_hooks_have_explicit_teardown(self):
        source = HIGHLIGHT.read_text(encoding="utf-8")
        plugin = (HIGHLIGHT.parent / "plugin.py").read_text(encoding="utf-8")
        self.assertIn("def destroy_highlight_hooks", source)
        self.assertIn("destroy_highlight_hooks()", plugin)


if __name__ == "__main__":
    unittest.main()
