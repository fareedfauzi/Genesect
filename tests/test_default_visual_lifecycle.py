import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "pseudonote_extended" / "default_visuals.py").read_text(encoding="utf-8-sig")
PLUGIN = (ROOT / "pseudonote_extended" / "plugin.py").read_text(encoding="utf-8-sig")
INDENT = (ROOT / "pseudonote_extended" / "indent.py").read_text(encoding="utf-8-sig")


class DefaultVisualLifecycleTests(unittest.TestCase):
    def test_session_restore_has_bounded_delayed_retries(self):
        self.assertIn("for delay in (0, 250, 1000, 2500):", SOURCE)
        self.assertIn("coalesce=False", SOURCE)
        self.assertIn("scan_pseudocode=True", SOURCE)

    def test_view_lifecycle_and_navigation_reapply_defaults(self):
        for callback in ("ready_to_run", "current_widget_changed", "widget_visible", "screen_ea_changed"):
            self.assertIn(f"def {callback}", SOURCE)
        self.assertIn("schedule_default_visual_activation(75, widget=widget)", SOURCE)

    def test_cached_pseudocode_is_modified_before_refresh(self):
        self.assertIn("def refresh_pseudocode_widget(widget, regenerate=False):", INDENT)
        self.assertIn("apply_indent_guides(vu.cfunc.get_pseudocode())", INDENT)
        self.assertIn("vu.refresh_view(True)", INDENT)

    def test_lifecycle_retries_hook_after_hexrays_becomes_available(self):
        self.assertIn("create_indent_guide_hooks", SOURCE)
        self.assertIn("create_indent_guide_hooks()", SOURCE)
        self.assertIn("idempotent once installed", SOURCE)

    def test_pending_callbacks_are_invalidated_on_teardown(self):
        self.assertIn("if not _active:", SOURCE)
        self.assertIn("_activation_generation += 1", SOURCE)
        self.assertIn("destroy_default_visual_hooks()", PLUGIN)


if __name__ == "__main__":
    unittest.main()
