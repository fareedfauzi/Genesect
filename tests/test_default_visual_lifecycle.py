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

    def test_view_lifecycle_reapplies_defaults_without_per_address_timers(self):
        for callback in ("ready_to_run", "current_widget_changed", "widget_visible"):
            self.assertIn(f"def {callback}", SOURCE)
        self.assertNotIn("def screen_ea_changed", SOURCE)
        self.assertIn("schedule_default_visual_activation(75, widget=widget)", SOURCE)

    def test_autoanalysis_does_not_enqueue_visual_timers(self):
        self.assertIn("import ida_auto", SOURCE)
        self.assertIn("if not _active or not _autoanalysis_complete():", SOURCE)

    def test_cached_pseudocode_is_never_modified_during_refresh(self):
        self.assertIn("def refresh_pseudocode_widget(widget):", INDENT)
        self.assertIn("refresh_custom_viewer(widget)", INDENT)
        self.assertNotIn("vu.refresh_view(True)", INDENT)
        self.assertNotIn("vu.refresh_ctext()", INDENT)

    def test_lifecycle_retries_hook_after_hexrays_becomes_available(self):
        self.assertIn("create_indent_guide_hooks", SOURCE)
        self.assertIn("create_indent_guide_hooks()", SOURCE)
        self.assertIn("idempotent once installed", SOURCE)

    def test_pending_callbacks_are_invalidated_on_teardown(self):
        self.assertIn("if not _active or not _autoanalysis_complete():", SOURCE)
        self.assertIn("_activation_generation += 1", SOURCE)
        self.assertIn("destroy_default_visual_hooks()", PLUGIN)


if __name__ == "__main__":
    unittest.main()
