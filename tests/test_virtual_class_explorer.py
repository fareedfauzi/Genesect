import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "pseudonote_extended" / "virtual_class_explorer.py").read_text(encoding="utf-8")
PLUGIN = (ROOT / "pseudonote_extended" / "plugin.py").read_text(encoding="utf-8")
MENU = (ROOT / "pseudonote_extended" / "ui" / "context_menu.py").read_text(encoding="utf-8")


class VirtualClassExplorerTests(unittest.TestCase):
    def test_reuses_bounded_vtable_scanner(self):
        self.assertIn("scan_vftables", SOURCE)
        self.assertIn("recover_virtual_classes", SOURCE)

    def test_recovers_requested_class_evidence(self):
        for marker in ("recover_class_identity", "recover_rtti", "constructors", "destructors", "initializer_candidates", "bases", "methods"):
            self.assertIn(marker, SOURCE)

    def test_inferred_results_are_labeled(self):
        self.assertIn("heuristic", SOURCE)
        self.assertIn("inferred from vtable reference", SOURCE)
        self.assertIn("secondary/construction vtable", SOURCE)

    def test_has_filter_navigation_and_copy_report(self):
        for marker in ("apply_filter", "navigate_item", "Copy Class Report", "_report_text"):
            self.assertIn(marker, SOURCE)

    def test_action_is_registered_and_available_in_utilities(self):
        action = "pseudonote_extended:virtual_class_explorer"
        self.assertGreaterEqual(PLUGIN.count(action), 2)
        self.assertIn(action, MENU)


if __name__ == "__main__":
    unittest.main()
