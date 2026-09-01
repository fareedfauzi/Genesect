import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "pseudonote_extended" / "anti_analysis_explorer.py").read_text(encoding="utf-8")
PLUGIN = (ROOT / "pseudonote_extended" / "plugin.py").read_text(encoding="utf-8")
MENU = (ROOT / "pseudonote_extended" / "ui" / "context_menu.py").read_text(encoding="utf-8")


class AntiAnalysisExplorerTests(unittest.TestCase):
    def test_detects_debugger_vm_and_environment_checks(self):
        for marker in ("IsDebuggerPresent", "CheckRemoteDebuggerPresent", "VM / sandbox artifact", "Environment fingerprint", "cpuid"):
            self.assertIn(marker, SOURCE)

    def test_correlates_timing_checks(self):
        for marker in ("scan_correlated_timing_checks", "multiple timestamps plus delta arithmetic and comparison", "rdtsc"):
            self.assertIn(marker, SOURCE)

    def test_detects_control_flow_candidates(self):
        for marker in ("scan_opaque_predicates", "Push/return control transfer", "Indirect control-flow cluster"):
            self.assertIn(marker, SOURCE)

    def test_heuristics_are_not_overclaimed(self):
        self.assertIn('"low"', SOURCE)
        self.assertIn('row["score"] >= 60', SOURCE)
        self.assertIn("can describe legitimate runtime behavior", SOURCE)

    def test_generic_string_terms_do_not_trigger_artifact_detection(self):
        pattern_section = SOURCE[SOURCE.index("_VM_STRING"):SOURCE.index("_CONDITIONAL_BRANCHES")]
        self.assertNotIn("processorname|string|", pattern_section)
        self.assertNotIn("idaq?", pattern_section)
        self.assertIn(r"\bida", pattern_section)

    def test_dual_use_signals_are_weak_without_corroboration(self):
        self.assertIn('("Delay / sleep", _DELAY_API', SOURCE)
        self.assertIn('"single host-information API"', SOURCE)
        self.assertIn('"timestamp source without a complete local timing-check chain"', SOURCE)
        self.assertIn('row["score"] >= 60', SOURCE)

    def test_debug_information_classes_are_argument_correlated(self):
        self.assertIn("def _has_nearby_immediate", SOURCE)
        self.assertIn("{7, 0x1E, 0x1F}", SOURCE)
        self.assertIn("{0x11}", SOURCE)

    def test_cpuid_requires_hypervisor_bit_check_for_visible_result(self):
        self.assertIn("hypervisor_test", SOURCE)
        self.assertIn("0x80000000", SOURCE)

    def test_weak_signal_toggle_is_off_by_default(self):
        self.assertIn('ToggleSwitch("Weak signals")', SOURCE)
        self.assertIn('self.settings.value("show_weak", "false")', SOURCE)
        self.assertIn("include_weak=self.show_weak.isChecked()", SOURCE)

    def test_action_is_registered_and_in_utilities(self):
        action = "pseudonote_extended:anti_analysis_explorer"
        self.assertGreaterEqual(PLUGIN.count(action), 2)
        self.assertIn(action, MENU)


if __name__ == "__main__":
    unittest.main()
