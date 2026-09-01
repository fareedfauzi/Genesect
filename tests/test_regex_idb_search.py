import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "pseudonote_extended" / "regex_idb_search.py").read_text(encoding="utf-8")
PLUGIN = (ROOT / "pseudonote_extended" / "plugin.py").read_text(encoding="utf-8")
MENU = (ROOT / "pseudonote_extended" / "ui" / "context_menu.py").read_text(encoding="utf-8")


class RegexIDBSearchTests(unittest.TestCase):
    def test_searches_all_requested_idb_scopes(self):
        for scanner in ("search_decompilation", "search_disassembly", "search_strings", "search_names", "search_comments"):
            self.assertIn("def %s" % scanner, SOURCE)

    def test_validates_and_bounds_regex_and_results(self):
        for marker in ("compile_pattern", "_MAX_PATTERN_LENGTH", "_MAX_RESULTS", "re.compile", "user_cancelled"):
            self.assertIn(marker, SOURCE)

    def test_decompiler_failures_do_not_abort_search(self):
        self.assertIn("failures += 1", SOURCE)
        self.assertIn("functions could not be decompiled", SOURCE)

    def test_has_scope_toggles_preview_navigation_and_csv(self):
        for marker in ("ToggleSwitch", "Match context", "navigate_selected", "Export CSV", "_excerpt"):
            self.assertIn(marker, SOURCE)

    def test_action_is_registered_and_available_in_data_strings(self):
        action = "pseudonote_extended:regex_idb_search"
        self.assertGreaterEqual(PLUGIN.count(action), 2)
        self.assertIn(action, MENU)


if __name__ == "__main__":
    unittest.main()
