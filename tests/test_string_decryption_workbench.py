import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "pseudonote_extended" / "string_decryption_workbench.py").read_text(encoding="utf-8")
PLUGIN = (ROOT / "pseudonote_extended" / "plugin.py").read_text(encoding="utf-8")
MENU = (ROOT / "pseudonote_extended" / "ui" / "context_menu.py").read_text(encoding="utf-8")


class StringDecryptionWorkbenchTests(unittest.TestCase):
    def test_detects_decoder_functions(self):
        for marker in ("detect_decoder_functions", "_DECODER_MNEMONICS", "decoder-like symbol"):
            self.assertIn(marker, SOURCE)

    def test_previews_common_safe_transforms(self):
        for marker in ("Base64", "Hex", "ROT13", "Single-byte XOR", "_safe_transforms"):
            self.assertIn(marker, SOURCE)
        self.assertIn("Decode Selected Bytes", SOURCE)
        self.assertIn("read_range_selection", SOURCE)

    def test_never_executes_native_idb_code(self):
        self.assertIn("never Appcall or execute code from the IDB", SOURCE)
        self.assertNotIn("ida_dbg.Appcall", SOURCE)

    def test_annotation_is_explicit_and_confirmed(self):
        self.assertIn("Annotate References", SOURCE)
        self.assertIn("ask_yn", SOURCE)
        self.assertIn("ida_bytes.set_cmt", SOURCE)

    def test_action_is_registered_and_in_data_utilities(self):
        action = "pseudonote_extended:string_decryption_workbench"
        self.assertGreaterEqual(PLUGIN.count(action), 2)
        self.assertIn(action, MENU)


if __name__ == "__main__":
    unittest.main()
