import importlib.util
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
PATH = ROOT / "pseudonote_extended" / "ui" / "tokens.py"
SPEC = importlib.util.spec_from_file_location("pseudonote_extended_ui_tokens", PATH)
tokens = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = tokens
SPEC.loader.exec_module(tokens)


class UITokenTests(unittest.TestCase):
    def test_palettes_have_matching_fields(self):
        self.assertEqual(set(tokens.DARK.as_dict()), set(tokens.LIGHT.as_dict()))

    def test_palette_selection(self):
        self.assertIs(tokens.palette_for_name("light"), tokens.LIGHT)
        self.assertIs(tokens.palette_for_name("dark"), tokens.DARK)

    def test_readable_text(self):
        self.assertEqual(tokens.readable_text("#FFFFFF"), "#000000")
        self.assertEqual(tokens.readable_text("#000000"), "#FFFFFF")

    def test_invalid_color_rejected(self):
        with self.assertRaises(ValueError):
            tokens.readable_text("#FFF")


if __name__ == "__main__":
    unittest.main()
