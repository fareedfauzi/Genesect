import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
PLUGIN = (ROOT / "pseudonote_extended" / "plugin.py").read_text(encoding="utf-8")
MENU = (ROOT / "pseudonote_extended" / "ui" / "context_menu.py").read_text(encoding="utf-8")
ICONS = (ROOT / "pseudonote_extended" / "ui" / "icons.py").read_text(encoding="utf-8")


class RemovedAutoEnumExplorerTests(unittest.TestCase):
    def test_feature_and_action_are_removed(self):
        self.assertFalse((ROOT / "pseudonote_extended" / "auto_enum_explorer.py").exists())
        for source in (PLUGIN, MENU, ICONS):
            self.assertNotIn("auto_enum_explorer", source)
            self.assertNotIn("Automatic Enum Recovery", source)


if __name__ == "__main__":
    unittest.main()
