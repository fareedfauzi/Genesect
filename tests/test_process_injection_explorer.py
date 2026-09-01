import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "pseudonote_extended" / "process_injection_explorer.py").read_text(encoding="utf-8")
PLUGIN = (ROOT / "pseudonote_extended" / "plugin.py").read_text(encoding="utf-8")
MENU = (ROOT / "pseudonote_extended" / "ui" / "context_menu.py").read_text(encoding="utf-8")


class ProcessInjectionExplorerTests(unittest.TestCase):
    def test_maps_major_injection_primitive_families(self):
        for marker in ("VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "QueueUserAPC", "NtMapViewOfSection", "SetThreadContext", "ResumeThread"):
            self.assertIn(marker, SOURCE)

    def test_correlates_named_injection_techniques(self):
        for marker in ("Remote-thread injection", "APC injection", "Section-mapping injection", "Process hollowing", "Thread-context hijacking"):
            self.assertIn(marker, SOURCE)

    def test_does_not_overclaim_single_primitives(self):
        self.assertIn("A primitive alone is not proof of injection", SOURCE)
        self.assertIn("all(stage in stages for stage in required)", SOURCE)
        self.assertIn("_has_create_suspended", SOURCE)
        self.assertIn("CREATE_SUSPENDED flag evidence", SOURCE)

    def test_has_navigation_filter_copy_and_export(self):
        for marker in ("apply_filter", "navigate_selected", "copy_selected", "export_csv"):
            self.assertIn(marker, SOURCE)

    def test_action_is_registered_and_in_utilities(self):
        action = "pseudonote_extended:process_injection_explorer"
        self.assertGreaterEqual(PLUGIN.count(action), 2)
        self.assertIn(action, MENU)


if __name__ == "__main__":
    unittest.main()
