import pathlib
import unittest


HEXVIEW = pathlib.Path(__file__).resolve().parents[1] / "pseudonote_extended" / "hexview.py"


class HexViewerCompatibilityTests(unittest.TestCase):
    def test_font_detection_does_not_use_unavailable_has_family(self):
        source = HEXVIEW.read_text(encoding="utf-8-sig")
        self.assertNotIn(".hasFamily(", source)
        self.assertIn(".families()", source)


if __name__ == "__main__":
    unittest.main()
