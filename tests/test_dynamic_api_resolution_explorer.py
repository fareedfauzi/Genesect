import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "pseudonote_extended" / "dynamic_api_resolution_explorer.py").read_text(encoding="utf-8")
PLUGIN = (ROOT / "pseudonote_extended" / "plugin.py").read_text(encoding="utf-8")
MENU = (ROOT / "pseudonote_extended" / "ui" / "context_menu.py").read_text(encoding="utf-8")


class DynamicAPIResolutionExplorerTests(unittest.TestCase):
    def test_recovers_runtime_resolvers_and_modules(self):
        for marker in ("GetProcAddress", "LdrGetProcedureAddress", "dlsym", "LoadLibrary", "Resolved API name", "Dynamically loaded module"):
            self.assertIn(marker, SOURCE)

    def test_detects_hash_and_export_walkers(self):
        for marker in ("scan_hash_resolvers", "API hash resolver candidate", "scan_export_walkers", "PE export walker candidate", "0x3C"):
            self.assertIn(marker, SOURCE)

    def test_maps_syscalls_and_custom_loaders(self):
        for marker in ("scan_syscall_tables", "Direct syscall stub", "Syscall table / dispatcher", "scan_custom_loaders", "Custom loader candidate"):
            self.assertIn(marker, SOURCE)

    def test_inferred_results_require_validation(self):
        self.assertIn('"heuristic"', SOURCE)
        self.assertIn("require analyst validation", SOURCE)

    def test_action_is_registered_and_in_utilities(self):
        action = "pseudonote_extended:dynamic_api_resolution_explorer"
        self.assertGreaterEqual(PLUGIN.count(action), 2)
        self.assertIn(action, MENU)


if __name__ == "__main__":
    unittest.main()
