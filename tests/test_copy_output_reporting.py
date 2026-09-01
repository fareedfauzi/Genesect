import pathlib
import unittest


SOURCE = (
    pathlib.Path(__file__).resolve().parents[1]
    / "pseudonote_extended"
    / "handlers.py"
).read_text(encoding="utf-8")


class CopyOutputReportingTests(unittest.TestCase):
    def test_advanced_copy_reports_exact_full_clipboard_output(self):
        self.assertIn("def _report_full_copied_output", SOURCE)
        self.assertGreaterEqual(SOURCE.count("_report_full_copied_output(output)"), 2)
        self.assertIn('ida_kernwin.msg("[PseudoNote] Copied:\\n")', SOURCE)
        self.assertIn("text[offset:offset + chunk_size]", SOURCE)

    def test_old_sixty_character_preview_is_removed(self):
        self.assertNotIn("preview = output.replace", SOURCE)
        self.assertNotIn("preview[:57]", SOURCE)


if __name__ == "__main__":
    unittest.main()
