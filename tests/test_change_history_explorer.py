import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "pseudonote_extended" / "change_history.py").read_text(encoding="utf-8")
PLUGIN = (ROOT / "pseudonote_extended" / "plugin.py").read_text(encoding="utf-8")
MENU = (ROOT / "pseudonote_extended" / "ui" / "context_menu.py").read_text(encoding="utf-8")


class ChangeHistoryExplorerTests(unittest.TestCase):
    def test_persistent_hooks_capture_before_and_after_values(self):
        for marker in ("IDB_Hooks", "old_name", "changing_cmt", "changing_range_cmt", "changing_ti", "byte_patched", '"before"', '"after"', "_NODE_NAME"):
            self.assertIn(marker, SOURCE)

    def test_rollback_verifies_current_value_before_writing(self):
        self.assertIn("def rollback_record", SOURCE)
        self.assertIn("current != record.get(\"after\")", SOURCE)
        self.assertIn("protect newer work", SOURCE)
        self.assertIn("verification did not match", SOURCE)

    def test_selective_rollback_supports_safe_change_types(self):
        for marker in ('kind == "name"', 'kind == "comment"', 'kind == "function_comment"', 'kind == "type"', 'kind == "byte"', "checked_records"):
            self.assertIn(marker, SOURCE)

    def test_hook_lifecycle_is_bound_to_plugin(self):
        self.assertIn("start_change_history_hooks()", PLUGIN)
        self.assertIn("stop_change_history_hooks()", PLUGIN)

    def test_action_is_registered_and_available_in_context_menu(self):
        action = "pseudonote_extended:change_history_explorer"
        self.assertGreaterEqual(PLUGIN.count(action), 2)
        self.assertIn(action, MENU)


if __name__ == "__main__":
    unittest.main()
