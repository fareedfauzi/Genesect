import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "pseudonote_extended" / "com_explorer.py").read_text(encoding="utf-8")
PLUGIN = (ROOT / "pseudonote_extended" / "plugin.py").read_text(encoding="utf-8-sig")
MENU = (ROOT / "pseudonote_extended" / "ui" / "context_menu.py").read_text(encoding="utf-8")


class COMExplorerTests(unittest.TestCase):
    def test_explorer_is_registered_under_program_structure(self):
        self.assertIn("COM Explorer", SOURCE)
        self.assertIn("COMExplorerHandler", PLUGIN)
        self.assertIn('"pseudonote_extended:com_explorer"', MENU)

    def test_guid_tracking_uses_registry_and_real_data_references(self):
        for marker in ("guid_bytes_to_string", "HKEY_CLASSES_ROOT", "DataRefsFrom", "CLSID", "Interface"):
            self.assertIn(marker, SOURCE)
        self.assertIn("Scan Current Function", SOURCE)
        self.assertIn("Scan Entire IDB", SOURCE)

    def test_type_inference_covers_requested_com_patterns(self):
        for marker in ("cocreateinstance", "cogetcallcontext", "queryinterface", "set_final_lvar_type", "save_user_lvar_settings"):
            self.assertIn(marker, SOURCE.lower())
        self.assertIn("Infer Current Function Types", SOURCE)
        self.assertIn("ask_yn", SOURCE)

    def test_scanning_and_inference_are_not_startup_hooks(self):
        self.assertNotIn("Hexrays_Hooks", SOURCE)
        self.assertNotIn("maturity(self", SOURCE)


if __name__ == "__main__":
    unittest.main()
