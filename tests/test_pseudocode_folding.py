import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "pseudonote_extended" / "pseudocode_folding.py").read_text(encoding="utf-8")
PLUGIN = (ROOT / "pseudonote_extended" / "plugin.py").read_text(encoding="utf-8-sig")
MENU = (ROOT / "pseudonote_extended" / "ui" / "context_menu.py").read_text(encoding="utf-8")


class PseudocodeFoldingTests(unittest.TestCase):
    def test_hexrays_double_click_hook_and_manual_action_are_present(self):
        self.assertIn("def double_click(self, vu, shift_state)", SOURCE)
        self.assertIn("class TogglePseudocodeBlockHandler", SOURCE)
        self.assertIn('"pseudonote_extended:toggle_pseudocode_block"', PLUGIN)
        self.assertIn('"pseudonote_extended:toggle_pseudocode_block"', MENU)

    def test_menu_action_remains_visible_when_ida_omits_context_widget(self):
        self.assertIn("Some IDA builds", SOURCE)
        self.assertIn("return ida_kernwin.AST_ENABLE_ALWAYS", SOURCE)

    def test_folding_is_scoped_and_does_not_use_qt_event_filters(self):
        self.assertIn("class PseudocodeFoldingHooks(ida_hexrays.Hexrays_Hooks)", SOURCE)
        self.assertNotIn("eventFilter", SOURCE)
        self.assertNotIn("installEventFilter", SOURCE)
        self.assertIn("refresh_pseudocode", SOURCE)
        self.assertIn("close_pseudocode", SOURCE)

    def test_original_tagged_lines_are_retained_for_expand(self):
        self.assertIn('"lines": self._snapshot(pseudocode)', SOURCE)
        self.assertIn("pseudocode.push_back", SOURCE)
        self.assertIn("return [_line_text(line) for line in pseudocode]", SOURCE)

    def test_generated_ellipsis_row_expands_its_owning_fold(self):
        self.assertIn("def _folded_range_at_visible_line", SOURCE)
        self.assertIn("visible_start <= visible_line <= visible_start + 2", SOURCE)
        self.assertLess(
            SOURCE.index("folded = self._folded_range_at_visible_line"),
            SOURCE.index("original_line = self._visible_to_original"),
        )

    def test_redraw_does_not_discard_live_fold_state(self):
        self.assertIn("_FOLD_MARKER", SOURCE)
        self.assertIn("still_folded = any", SOURCE)
        self.assertIn("idaapi.refresh_idaview_anyway()", SOURCE)
        self.assertNotIn("refresh_custom_viewer(vu.ct)", SOURCE)
        self.assertNotIn('str(getattr(vu, "ct"', SOURCE)

    def test_single_click_highlights_matching_brace_block_persistently(self):
        for marker in (
            "def _brace_block", "def view_click(self, view, event)",
            "LROEF_FULL_LINE", "_block_highlights", "CK_EXTRA10",
            "execute_ui_requests",
        ):
            self.assertIn(marker, SOURCE)
        self.assertNotIn("sl.bgcolor", SOURCE)

    def test_clicking_same_block_toggles_highlight_off(self):
        self.assertIn("if _block_highlights.get(key) == block", SOURCE)
        self.assertIn("_block_highlights.pop(key, None)", SOURCE)

    def test_swig_simpleline_values_are_normalized_before_tag_removal(self):
        self.assertIn("def _line_text(line):", SOURCE)
        self.assertIn('getattr(line, "line", line)', SOURCE)
        self.assertIn("ida_lines.tag_remove(_line_text(line))", SOURCE)
        self.assertNotIn("ida_lines.tag_remove(line or", SOURCE)

    def test_combined_feature_has_an_accurate_action_title(self):
        self.assertIn('"Interactive Code Blocks"', PLUGIN)
        self.assertIn("Single-click a brace to highlight its block", PLUGIN)


if __name__ == "__main__":
    unittest.main()
