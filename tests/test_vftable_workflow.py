import pathlib
import unittest


SOURCE = (pathlib.Path(__file__).parents[1] / "pseudonote_extended" / "vftable.py").read_text(encoding="utf-8")


class VftableWorkflowTests(unittest.TestCase):
    def test_pointer_reads_and_slots_respect_loaded_segment_bounds(self):
        self.assertIn("ida_bytes.is_loaded(ea + ptr_size - 1)", SOURCE)
        self.assertIn("entry_ea + ptr_size > table_segment.end_ea", SOURCE)

    def test_named_candidates_exclude_executable_segments(self):
        self.assertIn("segment and not (segment.perm & ida_segment.SEGPERM_EXEC)", SOURCE)

    def test_unnamed_tables_require_real_function_entries(self):
        self.assertIn("if require_entry and func_ea != ea:", SOURCE)
        self.assertGreaterEqual(SOURCE.count("require_entry=True"), 4)

    def test_direct_callers_only_accept_call_xrefs(self):
        self.assertIn("xref.type not in (idaapi.fl_CF, idaapi.fl_CN)", SOURCE)
        self.assertIn("calls_only=True", SOURCE)

    def test_tables_are_deduplicated_by_address(self):
        self.assertIn("tables_by_ea = {}", SOURCE)
        self.assertIn("tables_by_ea.setdefault", SOURCE)

    def test_scans_are_cancellable_and_bounded(self):
        self.assertIn("_MAX_SCAN_BYTES = 512 * 1024 * 1024", SOURCE)
        self.assertIn("_MAX_ROWS = 200000", SOURCE)
        self.assertGreaterEqual(SOURCE.count("ida_kernwin.user_cancelled()"), 2)

    def test_xref_results_are_cached(self):
        self.assertIn("xref_cache = {}", SOURCE)

    def test_refresh_returns_ida_chooser_change_tuple(self):
        self.assertIn("return (ida_kernwin.Choose.ALL_CHANGED, selected)", SOURCE)

    def test_chooser_reference_is_released_and_previous_window_closed(self):
        self.assertIn("if _viewer is self:", SOURCE)
        self.assertIn("_viewer.Close()", SOURCE)


if __name__ == "__main__":
    unittest.main()
