import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]


class UIImportBoundaryTests(unittest.TestCase):
    def test_workspace_styler_is_always_imported_from_its_defining_module(self):
        invalid = []
        for path in (ROOT / "pseudonote_extended").rglob("*.py"):
            source = path.read_text(encoding="utf-8")
            if "from pseudonote_extended.ui.theme import apply_mac_workspace" in source:
                invalid.append(str(path.relative_to(ROOT)))
        self.assertEqual([], invalid)


if __name__ == "__main__":
    unittest.main()
