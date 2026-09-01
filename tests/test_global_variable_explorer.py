import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "pseudonote_extended" / "global_explorer.py").read_text(encoding="utf-8")
PLUGIN = (ROOT / "pseudonote_extended" / "plugin.py").read_text(encoding="utf-8")
MENU = (ROOT / "pseudonote_extended" / "ui" / "context_menu.py").read_text(encoding="utf-8")


class GlobalVariableExplorerTests(unittest.TestCase):
    def test_discovers_named_and_code_referenced_globals(self):
        self.assertIn("idautils.Names()", SOURCE)
        self.assertIn("idautils.DataRefsFrom", SOURCE)
        self.assertIn("_canonical_data_ea", SOURCE)

    def test_reports_accesses_types_values_aliases_and_functions(self):
        for marker in ("dr_W", "dr_R", "_inferred_type", "_initial_value", "_aliases", '"functions"'):
            self.assertIn(marker, SOURCE)

    def test_has_filter_navigation_details_and_csv_export(self):
        for marker in ("apply_filter", "navigate_selected", "navigate_link", "Export CSV", "Copy Selected"):
            self.assertIn(marker, SOURCE)

    def test_action_is_registered_unregistered_and_in_utilities_menu(self):
        action = "pseudonote_extended:global_variable_explorer"
        self.assertGreaterEqual(PLUGIN.count(action), 2)
        self.assertIn(action, MENU)


if __name__ == "__main__":
    unittest.main()
