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

    def test_has_clean_guide_styles_and_empty_line_continuity(self):
        for marker in ('"Subtle": "│"', '"Dotted": "┊"', '"Strong": "┃"', "_blank_levels"):
            self.assertIn(marker, SOURCE)

    def test_settings_are_persistent_and_exposed(self):
        for marker in ("INDENT_GUIDES_ENABLED", "INDENT_GUIDES_STYLE", "INDENT_GUIDES_WIDTH", "INDENT_GUIDES_EMPTY_LINES"):
            self.assertIn(marker, CONFIG)
        self.assertIn("Pseudocode Indent Marks", VIEW)
        self.assertIn("Continue marks through empty lines", VIEW)

    def test_hook_and_toggle_are_lifecycle_managed(self):
        self.assertIn("create_indent_guide_hooks", PLUGIN)
        self.assertIn("destroy_indent_guide_hooks", PLUGIN)
        action = "pseudonote_extended:toggle_indent_guides"
        self.assertGreaterEqual(PLUGIN.count(action), 2)
        self.assertIn(action, MENU)

    def test_does_not_replace_spacing_inside_code(self):
        self.assertIn("never spacing inside code or strings", SOURCE)

    def test_ida_83_swig_vector_is_not_sliced(self):
        self.assertNotIn("lines[:_MAX_LINES]", SOURCE)
        self.assertIn("range(min(len(lines), _MAX_LINES))", SOURCE)

    def test_hooks_do_not_leak_rendering_errors_into_hexrays(self):
        self.assertIn("Indent mark rendering skipped", SOURCE)

    def test_guides_use_a_light_theme_aware_color(self):
        self.assertIn('_GUIDE_COLOR_NAME = "SCOLOR_AUTOCMT"', SOURCE)
        self.assertIn("def _level_mark", SOURCE)
        self.assertIn("for nesting in range(level)", SOURCE)

    def test_tagged_lines_only_replace_the_real_leading_run(self):
        self.assertIn("raw_offset = line.line.find(prefix)", SOURCE)
        self.assertNotIn('line.line.replace(" " * indent', SOURCE)

    def test_enabled_startup_schedules_an_initial_refresh(self):
        self.assertIn("self.indent_guides_enabled = True", CONFIG)
        self.assertIn("self.indent_guide_hooks = create_indent_guide_hooks()", PLUGIN)
        self.assertIn("create_default_visual_hooks()", PLUGIN)
        lifecycle = (ROOT / "pseudonote_extended" / "default_visuals.py").read_text(encoding="utf-8-sig")
        self.assertIn("refresh_pseudocode_widget(widget, regenerate=installed_late)", lifecycle)
        self.assertIn("create_indent_guide_hooks()", lifecycle)
        self.assertIn("def widget_visible", lifecycle)

    def test_startup_refresh_targets_restored_pseudocode_widgets(self):
        self.assertIn("def refresh_open_pseudocode_widgets", SOURCE)
        lifecycle = (ROOT / "pseudonote_extended" / "default_visuals.py").read_text(encoding="utf-8-sig")
        self.assertIn("widget=widget", lifecycle)
        self.assertIn("scan_pseudocode=True", lifecycle)
        self.assertIn("refresh_open_pseudocode_widgets(regenerate=installed_late)", lifecycle)

    def test_blank_line_guides_are_quiet_by_default(self):
        self.assertIn("self.indent_guides_empty_lines = False", CONFIG)
        self.assertIn('"INDENT_GUIDES_EMPTY_LINES", fallback=False', CONFIG)


if __name__ == "__main__":
    unittest.main()
