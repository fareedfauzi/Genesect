import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "pseudonote_extended" / "summarizer.py").read_text(encoding="utf-8")


class SummarizerActivityFeedbackTests(unittest.TestCase):
    def test_waiting_state_is_visible_and_animated(self):
        self.assertIn("self.activity_timer = QtCore.QTimer(self)", SOURCE)
        self.assertIn("self.activity_timer.setInterval(450)", SOURCE)
        self.assertIn("AI is working{dots}", SOURCE)
        self.assertIn("self.progress_bar.setRange(0, 0)", SOURCE)

    def test_provider_waiting_status_reaches_the_ui(self):
        self.assertIn("provider_status_signal = Signal(str)", SOURCE)
        self.assertIn("self.worker.provider_status_signal.connect(self.on_provider_status)", SOURCE)
        self.assertIn('message or "Waiting for AI response…"', SOURCE)

    def test_streaming_reports_live_character_count(self):
        self.assertIn("self.received_chars += len(t)", SOURCE)
        self.assertIn("self.char_count_signal.emit(self.received_chars, len(t))", SOURCE)
        self.assertIn("Receiving response{dots}  •  {self._received_chars:,} characters", SOURCE)

    def test_preview_worker_exists_before_initial_target_load(self):
        init = SOURCE.index("class SummarizerDialog")
        setup = SOURCE.index("self.setup_ui()", init)
        self.assertIn("self.preview_worker = None", SOURCE[init:setup])


if __name__ == "__main__":
    unittest.main()
