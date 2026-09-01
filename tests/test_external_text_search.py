import importlib.util
import pathlib
import unittest
import urllib.parse


ROOT = pathlib.Path(__file__).parents[1]
spec = importlib.util.spec_from_file_location("external_text_utility", ROOT / "pseudonote_extended" / "utility_state.py")
utility = importlib.util.module_from_spec(spec)
spec.loader.exec_module(utility)
HANDLERS = (ROOT / "pseudonote_extended" / "handlers.py").read_text(encoding="utf-8")


class ExternalTextSearchTests(unittest.TestCase):
    def test_normalization_collapses_controls_and_unwraps_matching_quotes(self):
        self.assertEqual(utility.normalize_external_text('  "hello\x00\x01\nworld"  '), "hello world")
        self.assertEqual(utility.normalize_external_text("'unmatched"), "'unmatched")

    def test_every_supported_mode_builds_an_https_url(self):
        for mode in utility.EXTERNAL_TEXT_LIMITS:
            self.assertTrue(utility.build_external_text_url(mode, "LoadLibraryW").startswith("https://"))

    def test_unknown_modes_and_oversized_text_are_rejected(self):
        with self.assertRaises(ValueError):
            utility.build_external_text_url("unknown", "x")
        with self.assertRaises(ValueError):
            utility.build_external_text_url("vt", "x" * 513)

    def test_cyberchef_fragment_is_url_encoded(self):
        url = utility.build_external_text_url("cyberchef", "😀")
        fragment = url.split("#input=", 1)[1]
        self.assertNotIn("+", fragment)
        self.assertEqual(urllib.parse.unquote(fragment), "8J+YgA==")

    def test_handler_reads_selection_from_invoking_widget(self):
        section = HANDLERS[HANDLERS.index("class SearchStringHandler"):HANDLERS.index("class FlossStringsHandler")]
        self.assertIn("viewer = ctx.widget or", section)
        self.assertIn("ida_lines.tag_remove", section)

    def test_handler_requires_truncation_consent_and_checks_browser_result(self):
        section = HANDLERS[HANDLERS.index("class SearchStringHandler"):HANDLERS.index("class FlossStringsHandler")]
        self.assertIn("Truncate and continue?", section)
        self.assertIn("if not QtGui.QDesktopServices.openUrl", section)


if __name__ == "__main__":
    unittest.main()
