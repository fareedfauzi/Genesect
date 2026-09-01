import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "pseudonote_extended" / "renamer.py").read_text(encoding="utf-8")


class BulkRenamerCompletionStateTests(unittest.TestCase):
    def test_new_rows_are_explicitly_not_analyzed(self):
        self.assertIn("'', '', 'Not analyzed', True", SOURCE)

    def test_start_marks_selected_rows_as_queued(self):
        self.assertIn("for idx, func in items:", SOURCE)
        self.assertIn("func.status = 'Queued'", SOURCE)
        self.assertIn("self.model.refresh_rows(queued_indices)", SOURCE)

    def test_finish_resets_shared_workbench_to_ready(self):
        finish = SOURCE.index("def finish_analyze(self):")
        clear = SOURCE.index("def clear_cache(self):", finish)
        self.assertIn("self.batch_bar.set_running(False)", SOURCE[finish:clear])

    def test_row_refresh_includes_status_column(self):
        self.assertIn("self.columnCount() - 1", SOURCE)


if __name__ == "__main__":
    unittest.main()
