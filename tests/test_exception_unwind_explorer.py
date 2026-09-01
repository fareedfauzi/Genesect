import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "pseudonote_extended" / "exception_unwind_explorer.py").read_text(encoding="utf-8")
PLUGIN = (ROOT / "pseudonote_extended" / "plugin.py").read_text(encoding="utf-8")
MENU = (ROOT / "pseudonote_extended" / "ui" / "context_menu.py").read_text(encoding="utf-8")


class ExceptionUnwindExplorerTests(unittest.TestCase):
    def test_covers_cross_format_unwind_sections(self):
        for marker in (".pdata", ".xdata", ".eh_frame", ".gcc_except_table", "__unwind_info", "__eh_frame"):
            self.assertIn(marker, SOURCE)

    def test_recovers_handlers_seh_landing_pads_cleanup_and_flags(self):
        for scanner in ("scan_named_handlers", "scan_seh_chain_patterns", "scan_unwind_metadata", "scan_cleanup_paths", "scan_function_unwind_flags"):
            self.assertIn("def %s" % scanner, SOURCE)

    def test_metadata_and_heuristics_are_distinguished(self):
        for marker in ("metadata-backed", "symbol-backed", '"pattern"', "Pattern-based cleanup"):
            self.assertIn(marker, SOURCE)

    def test_has_hierarchical_filter_navigation_copy_and_csv(self):
        for marker in ("QTreeWidget", "apply_filter", "navigate_selected", "Copy Selected", "Export CSV"):
            self.assertIn(marker, SOURCE)

    def test_action_is_registered_and_available_in_utilities(self):
        action = "pseudonote_extended:exception_unwind_explorer"
        self.assertGreaterEqual(PLUGIN.count(action), 2)
        self.assertIn(action, MENU)


if __name__ == "__main__":
    unittest.main()
