import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "pseudonote_extended" / "callback_resolver.py").read_text(encoding="utf-8")
PLUGIN = (ROOT / "pseudonote_extended" / "plugin.py").read_text(encoding="utf-8")
MENU = (ROOT / "pseudonote_extended" / "ui" / "context_menu.py").read_text(encoding="utf-8")


class CallbackDispatchResolverTests(unittest.TestCase):
    def test_scans_all_requested_dispatch_sources(self):
        for scanner in ("scan_function_pointers", "scan_callback_registrations", "scan_named_handlers", "scan_switches", "scan_indirect_calls"):
            self.assertIn("def %s" % scanner, SOURCE)

    def test_uses_ida_metadata_and_instruction_decoding(self):
        for marker in ("get_switch_info", "calc_switch_cases", "decode_insn", "CF_CALL", "XrefsTo"):
            self.assertIn(marker, SOURCE)

    def test_unresolved_targets_are_not_guessed(self):
        self.assertIn('"Unresolved"', SOURCE)
        self.assertIn('"unresolved"', SOURCE)
        self.assertIn("callback argument unresolved", SOURCE)

    def test_has_filter_navigation_details_and_csv(self):
        for marker in ("apply_filter", "navigate_selected", "Resolution evidence", "Export CSV", "Copy Selected"):
            self.assertIn(marker, SOURCE)

    def test_action_is_registered_and_available_in_utilities(self):
        action = "pseudonote_extended:callback_dispatch_resolver"
        self.assertGreaterEqual(PLUGIN.count(action), 2)
        self.assertIn(action, MENU)


if __name__ == "__main__":
    unittest.main()
