import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "pseudonote_extended" / "structure_recovery_explorer.py").read_text(encoding="utf-8")
PLUGIN = (ROOT / "pseudonote_extended" / "plugin.py").read_text(encoding="utf-8")
MENU = (ROOT / "pseudonote_extended" / "ui" / "context_menu.py").read_text(encoding="utf-8")


class StructureRecoveryExplorerTests(unittest.TestCase):
    def test_clusters_pointer_offsets_and_access_modes(self):
        for marker in ("recover_layouts", "o_displ", "_base_register", "_access_mode", "reads", "writes"):
            self.assertIn(marker, SOURCE)

    def test_detects_nested_pointer_follow_patterns(self):
        self.assertIn("_nested_pointer_offsets", SOURCE)
        self.assertIn("nested pointer candidate", SOURCE)

    def test_compares_layout_signatures(self):
        self.assertIn('other["signature"] == layout["signature"]', SOURCE)
        self.assertIn("Compatible Layouts", SOURCE)

    def test_review_required_before_type_import(self):
        self.assertIn("Review & Import Type", SOURCE)
        self.assertIn("ask_yn", SOURCE)
        self.assertIn("idc.parse_decls", SOURCE)
        self.assertIn("No variable or operand type was changed automatically", SOURCE)
        self.assertIn("_has_overlapping_fields", SOURCE)
        self.assertIn("will not import a misleading sequential structure", SOURCE)

    def test_action_is_registered_and_in_utilities(self):
        action = "pseudonote_extended:structure_recovery_explorer"
        self.assertGreaterEqual(PLUGIN.count(action), 2)
        self.assertIn(action, MENU)


if __name__ == "__main__":
    unittest.main()
