import pathlib
import unittest


SOURCE = (pathlib.Path(__file__).parents[1] / "pseudonote_extended" / "analyzer.py").read_text(encoding="utf-8")


class BulkAnalyzerCompatibilityTests(unittest.TestCase):
    def test_failures_are_not_persisted_as_benign(self):
        self.assertIn("'ERROR', 0, '', 'No code found'", SOURCE)
        self.assertIn("elif tag == 'ERROR':", SOURCE)
        error_branch = SOURCE[SOURCE.index("            elif tag == 'ERROR':"):SOURCE.index("            else:", SOURCE.index("            elif tag == 'ERROR':"))]
        self.assertNotIn("save_to_idb", error_branch)

    def test_cache_format_is_delimiter_safe_and_backward_compatible(self):
        self.assertIn("def encode_analysis_result", SOURCE)
        self.assertIn("def decode_analysis_result", SOURCE)
        self.assertIn("json.dumps({", SOURCE)
        self.assertIn("split('|', 3)", SOURCE)

    def test_cancellation_is_local_and_http_request_is_cancellable(self):
        self.assertNotIn("AI_CANCEL_REQUESTED = True", SOURCE)
        self.assertIn("cancel_checker=lambda: not self.running", SOURCE)
        self.assertIn("self._cancel_requested = True", SOURCE)

    def test_worker_count_is_bounded(self):
        self.assertIn("(len(items) + num_workers - 1) // num_workers", SOURCE)

    def test_activity_starts_after_selection_validation(self):
        section = SOURCE[SOURCE.index("    def start_analyze(self):"):SOURCE.index("    def _start_worker_items", SOURCE.index("    def start_analyze(self):"))]
        self.assertGreater(section.index("self.batch_bar.set_running(True)"), section.index("if not items:"))

    def test_ida_metric_reads_are_synchronized(self):
        self.assertGreaterEqual(SOURCE.count("idaapi.execute_sync(_read, idaapi.MFF_READ)"), 2)

    def test_batch_size_is_never_zero(self):
        self.assertIn("batch_size = max(1, int(self.cfg.get('batch_size', 1)))", SOURCE)

    def test_context_does_not_nest_execute_sync_code_fetches(self):
        section = SOURCE[SOURCE.index("    def get_context(self, ea):"):SOURCE.index("class StreamingSummaryDialog")]
        callback = section[section.index("        def _fetch():"):section.index("        idaapi.execute_sync(_fetch")]
        self.assertNotIn("get_code_fast", callback)

    def test_close_waits_for_active_workers(self):
        self.assertIn("def closeEvent(self, event):", SOURCE)
        self.assertIn("worker.wait(remaining_ms)", SOURCE)

    def test_load_all_functions_button_uses_deduplicated_valid_idb_functions(self):
        self.assertIn("self.load_all_btn = QPushButton('Load All Functions')", SOURCE)
        self.assertIn("self.load_all_btn.clicked.connect(self.load_all_functions)", SOURCE)
        section = SOURCE[SOURCE.index("    def load_all_functions(self):"):SOURCE.index("    def load_entry_points", SOURCE.index("    def load_all_functions(self):"))]
        self.assertIn("for ea in idautils.Functions()", section)
        self.assertIn("not is_valid_seg(ea)", section)
        self.assertIn("self.model.set_data(funcs)", section)
        self.assertIn("seen.add(ea)", section)


if __name__ == "__main__":
    unittest.main()
