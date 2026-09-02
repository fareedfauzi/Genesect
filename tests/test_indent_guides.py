import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "pseudonote_extended" / "indent.py").read_text(encoding="utf-8")
CONFIG = (ROOT / "pseudonote_extended" / "config.py").read_text(encoding="utf-8")
VIEW = (ROOT / "pseudonote_extended" / "view.py").read_text(encoding="utf-8")
PLUGIN = (ROOT / "pseudonote_extended" / "plugin.py").read_text(encoding="utf-8")
MENU = (ROOT / "pseudonote_extended" / "ui" / "context_menu.py").read_text(encoding="utf-8")


class IndentGuideTests(unittest.TestCase):
    def test_uses_actual_hexrays_whitespace(self):
        self.assertIn("_leading_spaces", SOURCE)
        self.assertIn("_detect_indent", SOURCE)
        self.assertNotIn("count_indents", SOURCE)

    def test_uses_one_stable_overlay_style(self):
        self.assertIn('_FALLBACK_COLOR = "CK_EXTRA14"', SOURCE)
        self.assertIn("_blank_levels", SOURCE)

    def test_settings_are_persistent_and_exposed(self):
        for marker in ("INDENT_GUIDES_ENABLED", "INDENT_GUIDES_COLOR"):
            self.assertIn(marker, CONFIG)
        self.assertIn("Pseudocode Indent Marks", VIEW)
        self.assertIn("Mark Color:", VIEW)
        for removed in ("Render Mode:", "ASCII Mark Pattern:", "Mark Spacing:", "Continue marks through empty lines"):
            self.assertNotIn(removed, VIEW)
        for removed_widget in ("indent_guides_mode_combo", "indent_guides_style_combo", "indent_guides_symbol_combo", "indent_guides_width_spin", "indent_guides_empty_cb"):
            self.assertNotIn(removed_widget, VIEW)
        for removed in ("INDENT_GUIDES_MODE", "INDENT_GUIDES_STYLE", "INDENT_GUIDES_SYMBOL", "INDENT_GUIDES_WIDTH", "INDENT_GUIDES_EMPTY_LINES"):
            self.assertNotIn(removed, CONFIG)

    def test_custom_color_uses_safe_read_only_overlay(self):
        self.assertIn("0xAABBGGRR", SOURCE)
        self.assertIn("indent_guides_color", SOURCE)
        self.assertIn("entry.nchars = 1", SOURCE)
        self.assertNotIn("line.line =", SOURCE)
        self.assertNotIn("ASCII Pattern", SOURCE)

    def test_hook_and_toggle_are_lifecycle_managed(self):
        self.assertIn("create_indent_guide_hooks", PLUGIN)
        self.assertIn("destroy_indent_guide_hooks", PLUGIN)
        action = "pseudonote_extended:toggle_indent_guides"
        self.assertGreaterEqual(PLUGIN.count(action), 2)
        self.assertIn(action, MENU)

    def test_does_not_mutate_hexrays_owned_line_text(self):
        self.assertIn("without modifying Hex-Rays-owned text", SOURCE)
        self.assertNotIn("line.line =", SOURCE)
        self.assertNotIn("func_printed", SOURCE)
        self.assertNotIn("text_ready", SOURCE)

    def test_ida_83_swig_vector_is_not_sliced(self):
        self.assertNotIn("lines[:_MAX_LINES]", SOURCE)
        self.assertIn("index >= min(len(levels), _MAX_LINES)", SOURCE)

    def test_hooks_do_not_leak_rendering_errors_into_hexrays(self):
        self.assertIn("Indent mark rendering skipped", SOURCE)

    def test_guides_use_supported_character_range_rendering(self):
        self.assertIn("get_lines_rendering_info", SOURCE)
        self.assertIn("line_rendering_output_entry_t", SOURCE)
        self.assertIn("LROEF_CPS_RANGE", SOURCE)
        self.assertIn("entry.cpx = nesting * indent", SOURCE)
        self.assertIn("for nesting in range(level)", SOURCE)

    def test_tagged_lines_are_read_only_inputs(self):
        self.assertIn("ida_lines.tag_remove(lines[index].line)", SOURCE)
        self.assertNotIn("raw_offset", SOURCE)

    def test_enabled_startup_schedules_an_initial_refresh(self):
        self.assertIn("self.indent_guides_enabled = True", CONFIG)
        self.assertIn('self.indent_guides_color = "#57CFDC"', CONFIG)
        self.assertIn("self.indent_guide_hooks = create_indent_guide_hooks()", PLUGIN)
        self.assertIn("create_default_visual_hooks()", PLUGIN)
        lifecycle = (ROOT / "pseudonote_extended" / "default_visuals.py").read_text(encoding="utf-8-sig")
        self.assertIn("refresh_pseudocode_widget(widget)", lifecycle)
        self.assertIn("create_indent_guide_hooks()", lifecycle)
        self.assertIn("def widget_visible", lifecycle)

    def test_startup_refresh_targets_restored_pseudocode_widgets(self):
        self.assertIn("def refresh_open_pseudocode_widgets", SOURCE)
        lifecycle = (ROOT / "pseudonote_extended" / "default_visuals.py").read_text(encoding="utf-8-sig")
        self.assertIn("widget=widget", lifecycle)
        self.assertIn("scan_pseudocode=True", lifecycle)
        self.assertIn("refresh_open_pseudocode_widgets()", lifecycle)

    def test_blank_lines_are_not_synthesized(self):
        self.assertNotIn("previous = next", SOURCE)
        self.assertNotIn("following = next", SOURCE)


if __name__ == "__main__":
    unittest.main()
