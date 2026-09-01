import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
VIEW = (ROOT / "pseudonote_extended" / "view.py").read_text(encoding="utf-8")


class ReadableCodeLabelTests(unittest.TestCase):
    def test_tabs_name_source_and_destination(self):
        self.assertIn('f"Readable Code (ASM → {self.current_lang})"', VIEW)
        self.assertIn('f"Readable Code (C → {self.current_lang})"', VIEW)
        self.assertIn('"Commented Code (Pseudocode)"', VIEW)

    def test_buttons_name_source_and_destination(self):
        self.assertIn('f"Convert ASM → {self.current_lang} (AI)"', VIEW)
        self.assertIn('f"Convert C → {self.current_lang} (AI)"', VIEW)

    def test_assembly_prompt_is_an_explicit_conversion(self):
        self.assertIn(
            'f"Convert this ASM to readable {self.current_lang} code.',
            VIEW,
        )


if __name__ == "__main__":
    unittest.main()
