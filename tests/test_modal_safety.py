import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "pseudonote_extended" / "ui" / "modal_safety.py").read_text(encoding="utf-8")


class ModalSafetyTests(unittest.TestCase):
    def test_modal_is_moved_off_pseudocode_and_focus_is_restored(self):
        self.assertIn("idaapi.BWN_PSEUDOCODE", SOURCE)
        self.assertIn("open_disasm_window", SOURCE)
        self.assertIn("activate_widget(source, True)", SOURCE)
        self.assertIn("close_widget(safe, close_later)", SOURCE)
        self.assertIn("return dialog.exec_()", SOURCE)


if __name__ == "__main__":
    unittest.main()
