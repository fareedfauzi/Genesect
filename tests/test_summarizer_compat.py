import pathlib
import unittest


SOURCE = (pathlib.Path(__file__).parents[1] / "pseudonote_extended" / "summarizer.py").read_text(encoding="utf-8")


class SummarizerCompatibilityTests(unittest.TestCase):
    def test_uses_request_scoped_cancellation(self):
        self.assertIn("cancel_request(self._active_request_id)", SOURCE)
        self.assertNotIn("AI_CANCEL_REQUESTED = True", SOURCE)

    def test_does_not_mutate_global_graph_configuration(self):
        self.assertNotIn("CONFIG.max_graph_depth =", SOURCE)
        self.assertNotIn("CONFIG.max_graph_nodes =", SOURCE)

    def test_context_is_size_bounded(self):
        self.assertIn("split_context_blocks(code_blocks", SOURCE)
        self.assertIn("build_context_snapshot(", SOURCE)

    def test_supports_non_streaming_provider_results(self):
        self.assertIn("final_response.append(response or \"\")", SOURCE)
        self.assertIn("synthesis_final.append(response or \"\")", SOURCE)

    def test_worker_completion_restores_controls(self):
        self.assertIn("self.worker.finished.connect(self.on_worker_done)", SOURCE)
        self.assertIn("self.entry_change_btn.setEnabled(True)", SOURCE)


if __name__ == "__main__":
    unittest.main()
