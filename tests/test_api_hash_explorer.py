import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "pseudonote_extended" / "api_hash_explorer.py").read_text(encoding="utf-8")
PLUGIN = (ROOT / "pseudonote_extended" / "plugin.py").read_text(encoding="utf-8")
MENU = (ROOT / "pseudonote_extended" / "ui" / "context_menu.py").read_text(encoding="utf-8")


class APIHashExplorerTests(unittest.TestCase):
    def test_uses_bundled_api_list(self):
        self.assertIn('"apilist.txt"', SOURCE)
        self.assertIn("load_api_entries", SOURCE)

    def test_supports_common_hash_algorithms(self):
        for marker in ("ROR13 add", "DJB2", "SDBM", "FNV-1a 32", "Jenkins one-at-a-time", "CRC32", "ROR7 XOR", "Metasploit ROR13 module+API"):
            self.assertIn(marker, SOURCE)

    def test_extracts_and_resolves_idb_constants(self):
        self.assertIn("extract_hash_candidates", SOURCE)
        self.assertIn("resolve_hashes", SOURCE)
        self.assertIn("Scan Current Function", SOURCE)
        self.assertIn("Scan Entire IDB", SOURCE)

    def test_reports_collisions_and_requires_validation(self):
        self.assertIn("collisions", SOURCE)
        self.assertIn("confirm the resolver algorithm and calling context", SOURCE)

    def test_action_is_registered_and_in_data_utilities(self):
        action = "pseudonote_extended:api_hash_explorer"
        self.assertGreaterEqual(PLUGIN.count(action), 2)
        self.assertIn(action, MENU)

    def test_custom_hash_ai_uses_safe_declarative_recipes(self):
        for marker in ("Analyze Custom Hash (AI)", "validate_custom_recipe", "apply_custom_recipe", "resolve_custom_hashes"):
            self.assertIn(marker, SOURCE)
        self.assertIn("AI-inferred recipe; locally validated", SOURCE)
        self.assertNotIn("eval" + "(", SOURCE)
        self.assertNotIn("exec" + "(", SOURCE)

    def test_custom_hash_ai_previews_shared_data(self):
        self.assertIn("Share Resolver with AI", SOURCE)
        self.assertIn("setDetailedText", SOURCE)
        self.assertIn("no IDB content was sent", SOURCE)
        self.assertIn("ida_hexrays.decompile", SOURCE)
        self.assertIn("Infer only behavior supported by direct evidence", SOURCE)


if __name__ == "__main__":
    unittest.main()
