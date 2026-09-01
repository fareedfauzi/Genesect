import pathlib
import unittest


SOURCE = (pathlib.Path(__file__).parents[1] / "pseudonote_extended" / "var_renamer.py").read_text(encoding="utf-8")


class BulkVariableRenamerCompatibilityTests(unittest.TestCase):
    def test_reads_the_marker_tag_it_writes(self):
        self.assertIn("_IDB_TAG = 86", SOURCE)
        self.assertIn('save_to_idb(fe, "variables_renamed", tag=86)', SOURCE)

    def test_local_variable_tool_cannot_rename_globals(self):
        self.assertNotIn("global_plan", SOURCE)
        self.assertNotIn("Attempting global rename", SOURCE)

    def test_apply_respects_checked_function_selection(self):
        section = SOURCE[SOURCE.index("    def apply_suggestions(self):"):SOURCE.index("    def _unload_table", SOURCE.index("    def apply_suggestions(self):"))]
        self.assertNotIn("Fallback: apply to all", section)
        self.assertIn("self.model.get_checked()", section)

    def test_failed_suggestions_are_retained_for_retry(self):
        self.assertIn("def pending_var_suggestions", SOURCE)
        self.assertGreaterEqual(SOURCE.count("pending_var_suggestions("), 4)

    def test_cancellation_is_owned_by_this_dialog(self):
        self.assertIn("cancel_checker=lambda: not self.running", SOURCE)
        self.assertIn("self._cancel_requested = True", SOURCE)
        self.assertNotIn("AI_CANCEL_REQUESTED = True", SOURCE)

    def test_activity_starts_after_selection_validation(self):
        section = SOURCE[SOURCE.index("    def start_rename(self):"):SOURCE.index("    def _start_worker", SOURCE.index("    def start_rename(self):"))]
        self.assertGreater(section.index("self.batch_bar.set_running(True)"), section.index("if not items:"))

    def test_json_parsers_require_an_object(self):
        self.assertIn("isinstance(parsed, dict)", SOURCE)
        self.assertIn("isinstance(data, dict)", SOURCE)

    def test_worker_lifecycle_is_closed_safely(self):
        self.assertIn("def closeEvent(self, event):", SOURCE)
        self.assertIn("self.batch_bar.set_running(False)", SOURCE)
        self.assertIn("worker.wait(remaining_ms)", SOURCE)


if __name__ == "__main__":
    unittest.main()
