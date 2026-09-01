import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "pseudonote_extended" / "thread_sync_explorer.py").read_text(encoding="utf-8")
PLUGIN = (ROOT / "pseudonote_extended" / "plugin.py").read_text(encoding="utf-8")
MENU = (ROOT / "pseudonote_extended" / "ui" / "context_menu.py").read_text(encoding="utf-8")


class ThreadSynchronizationExplorerTests(unittest.TestCase):
    def test_recovers_thread_entries_sync_queues_and_shared_state(self):
        for marker in ("scan_thread_entries", "scan_sync_and_queues", "analyze_shared_state", "_THREAD_API", "_SYNC_API", "_QUEUE_API"):
            self.assertIn(marker, SOURCE)

    def test_builds_bounded_thread_reachable_call_graphs(self):
        for marker in ("reachable_functions", "_direct_internal_callees", "_MAX_GRAPH_FUNCTIONS", "_MAX_GRAPH_DEPTH"):
            self.assertIn(marker, SOURCE)

    def test_reports_lock_cycles_and_race_candidates_as_heuristics(self):
        for marker in ("analyze_lock_order", "Possible deadlock", "possible race", "static candidates", "path feasibility"):
            self.assertIn(marker, SOURCE)

    def test_has_filter_navigation_details_copy_and_csv(self):
        for marker in ("apply_filter", "navigate_selected", "Concurrency evidence", "Copy Selected", "Export CSV"):
            self.assertIn(marker, SOURCE)

    def test_action_is_registered_and_available_in_utilities(self):
        action = "pseudonote_extended:thread_sync_explorer"
        self.assertGreaterEqual(PLUGIN.count(action), 2)
        self.assertIn(action, MENU)


if __name__ == "__main__":
    unittest.main()
