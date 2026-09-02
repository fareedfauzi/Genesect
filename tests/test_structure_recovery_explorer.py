import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]


class StructureRecoveryExplorerRemovalTests(unittest.TestCase):
    def test_feature_implementation_is_removed(self):
        self.assertFalse((ROOT / "pseudonote_extended" / "structure_recovery_explorer.py").exists())

    def test_action_menu_icon_and_documentation_are_removed(self):
        paths = (
            ROOT / "pseudonote_extended" / "plugin.py",
            ROOT / "pseudonote_extended" / "ui" / "context_menu.py",
            ROOT / "pseudonote_extended" / "ui" / "icons.py",
            ROOT / "docs" / "features-overview.md",
            ROOT / "docs" / "utilities.md",
        )
        for path in paths:
            source = path.read_text(encoding="utf-8")
            self.assertNotIn("structure_recovery_explorer", source)
            self.assertNotIn("Structure Recovery Explorer", source)


if __name__ == "__main__":
    unittest.main()
