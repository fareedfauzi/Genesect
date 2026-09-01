import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "pseudonote_extended" / "entry_point_explorer.py").read_text(encoding="utf-8")
PLUGIN = (ROOT / "pseudonote_extended" / "plugin.py").read_text(encoding="utf-8")
MENU = (ROOT / "pseudonote_extended" / "ui" / "context_menu.py").read_text(encoding="utf-8")


class EntryPointExplorerTests(unittest.TestCase):
    def test_distinguishes_executable_entry_and_exports(self):
        self.assertIn("idautils.Entries()", SOURCE)
        self.assertIn('"Executable entry"', SOURCE)
        self.assertIn('"Export"', SOURCE)
        self.assertIn("_start_ea", SOURCE)

    def test_recovers_tls_initializers_constructors_and_thread_entries(self):
        for marker in ("scan_tls_callbacks", "scan_initialization_arrays", "scan_named_initialization_ranges", "scan_named_startup_functions", "scan_thread_entry_points", "scan_thread_entries"):
            self.assertIn(marker, SOURCE)

    def test_supports_major_initialization_array_formats(self):
        for marker in (".init_array", ".preinit_array", ".fini_array", ".ctors", "__mod_init_func", ".crt"):
            self.assertIn(marker.lower(), SOURCE.lower())

    def test_has_filter_navigation_details_copy_and_csv(self):
        for marker in ("apply_filter", "navigate_selected", "Entry evidence", "Copy Selected", "Export CSV"):
            self.assertIn(marker, SOURCE)

    def test_action_is_registered_and_available_in_utilities(self):
        action = "pseudonote_extended:entry_point_explorer"
        self.assertGreaterEqual(PLUGIN.count(action), 2)
        self.assertIn(action, MENU)


if __name__ == "__main__":
    unittest.main()
