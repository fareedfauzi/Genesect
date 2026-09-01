import ast
import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "pseudonote_extended" / "auto_enum_explorer.py").read_text(encoding="utf-8")
PLUGIN = (ROOT / "pseudonote_extended" / "plugin.py").read_text(encoding="utf-8")
MENU = (ROOT / "pseudonote_extended" / "ui" / "context_menu.py").read_text(encoding="utf-8")


class AutoEnumExplorerTests(unittest.TestCase):
    def test_source_is_valid_and_feature_is_registered(self):
        ast.parse(SOURCE)
        self.assertIn("from pseudonote_extended.ui.mac_workspace import apply_mac_workspace", SOURCE)
        self.assertNotIn("from pseudonote_extended.ui.theme import apply_mac_workspace", SOURCE)
        action = "pseudonote_extended:auto_enum_explorer"
        self.assertGreaterEqual(PLUGIN.count(action), 2)
        self.assertIn(action, MENU)

    def test_supports_windows_and_linux_malware_relevant_apis(self):
        for marker in ("VirtualAlloc", "VirtualProtect", "OpenProcess", "CreateFile", "CreateProcess", "socket", "mmap", "mprotect", "open", "dlopen"):
            self.assertIn('"' + marker + '"', SOURCE)

    def test_changes_are_reviewed_and_selective(self):
        for marker in ("Apply Selected", "ItemIsUserCheckable", "QMessageBox.question", "apply_proposals"):
            self.assertIn(marker, SOURCE)

    def test_virtual_memory_argument_indexes_match_real_prototypes(self):
        self.assertIn('"VirtualAlloc": ((2, "flAllocationType"', SOURCE)
        self.assertIn('(3, "flProtect", "PN_PAGE_PROTECTION")', SOURCE)
        self.assertIn('"VirtualAllocEx": ((3, "flAllocationType"', SOURCE)
        self.assertIn('(4, "flProtect", "PN_PAGE_PROTECTION")', SOURCE)

    def test_scan_validates_prototypes_and_requires_explicit_selection(self):
        self.assertIn('"apply": False', SOURCE)
        self.assertIn('"valid": valid', SOURCE)
        self.assertIn('details is not None and index < len(details)', SOURCE)
        self.assertIn('"Import Slot"', SOURCE)
        self.assertIn('"Xrefs"', SOURCE)

    def test_uses_function_prototypes_to_propagate_enum_rendering(self):
        for marker in ("func_type_data_t", "get_func_details", "create_func", "apply_tinfo", "TINFO_DEFINITE"):
            self.assertIn(marker, SOURCE)

    def test_flag_enums_support_combined_symbolic_values(self):
        self.assertIn("FLAG_ENUMS", SOURCE)
        self.assertIn("set_enum_bf", SOURCE)

    def test_has_no_runtime_dependency_on_reference_plugin(self):
        self.assertNotIn("import enumlib", SOURCE)
        self.assertIn("ENUMS =", SOURCE)
        self.assertIn("RULES =", SOURCE)


if __name__ == "__main__":
    unittest.main()
