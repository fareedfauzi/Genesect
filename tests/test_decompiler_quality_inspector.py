import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "pseudonote_extended" / "decompiler_quality_inspector.py").read_text(encoding="utf-8")
PLUGIN = (ROOT / "pseudonote_extended" / "plugin.py").read_text(encoding="utf-8")
MENU = (ROOT / "pseudonote_extended" / "ui" / "context_menu.py").read_text(encoding="utf-8")


class DecompilerQualityInspectorTests(unittest.TestCase):
    def test_reports_decompilation_and_stack_failures(self):
        for marker in ("Decompilation failed", "Stack analysis incomplete", "Stack inconsistency warning", "FUNC_SP_READY"):
            self.assertIn(marker, SOURCE)

    def test_reports_prototypes_casts_and_calls(self):
        for marker in ("Missing function prototype", "Generic inferred prototype", "Cast-heavy pseudocode", "Unresolved indirect call", "Call target unresolved"):
            self.assertIn(marker, SOURCE)

    def test_reports_variables_needing_types(self):
        self.assertIn("Variable needs a type", SOURCE)
        self.assertIn("cfunc.get_lvars", SOURCE)

    def test_supports_current_and_full_idb_scans(self):
        self.assertIn("Inspect Current Function", SOURCE)
        self.assertIn("Inspect Entire IDB", SOURCE)
        self.assertIn("no IDB changes made", SOURCE)

    def test_action_is_registered_and_in_utilities(self):
        action = "pseudonote_extended:decompiler_quality_inspector"
        self.assertGreaterEqual(PLUGIN.count(action), 2)
        self.assertIn(action, MENU)


if __name__ == "__main__":
    unittest.main()
