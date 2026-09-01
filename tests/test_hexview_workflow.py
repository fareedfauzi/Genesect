import pathlib
import unittest


SOURCE = (pathlib.Path(__file__).parents[1] / "pseudonote_extended" / "hexview.py").read_text(encoding="utf-8")


class HexViewerWorkflowTests(unittest.TestCase):
    def test_segment_enumeration_is_deterministic(self):
        self.assertIn("for start_ea in idautils.Segments()", SOURCE)

    def test_negative_and_past_end_flat_offsets_are_rejected(self):
        self.assertIn("if flat < 0 or flat >= self.total_bytes:", SOURCE)

    def test_selection_cannot_cross_unmapped_segment_gaps(self):
        self.assertIn("def clamp_to_segment", SOURCE)
        self.assertIn("b = self._bmap.clamp_to_segment(a, b)", SOURCE)

    def test_formatted_copy_is_bounded_and_bulk_read(self):
        self.assertIn("MAX_FORMATTED_COPY_SOURCE_BYTES = 16 * 1024 * 1024", SOURCE)
        selection = SOURCE[SOURCE.index("def _sel_bytes"):SOURCE.index("# ── painting")]
        self.assertIn("ida_bytes.get_bytes(a, size)", selection)
        self.assertNotIn("for e in range", selection)

    def test_invalid_search_clears_stale_results(self):
        self.assertIn("Invalid Hex Pattern", SOURCE)
        self.assertIn("MAX_SEARCH_RESULTS = 2000", SOURCE)
        self.assertIn("MAX_SEARCH_PATTERN_BYTES = 1024 * 1024", SOURCE)

    def test_highlights_are_range_validated(self):
        self.assertGreaterEqual(SOURCE.count('QMessageBox.warning(self, "Invalid Highlight", message)'), 2)

    def test_global_form_reference_is_released(self):
        close = SOURCE[SOURCE.index("def OnClose"):SOURCE.index("# IDA HOOKS")]
        self.assertIn("_hex_view_instance = None", close)


if __name__ == "__main__":
    unittest.main()
