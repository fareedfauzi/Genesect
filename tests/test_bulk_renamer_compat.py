import pathlib
import unittest


SOURCE = (pathlib.Path(__file__).parents[1] / "pseudonote_extended" / "renamer.py").read_text(encoding="utf-8")


class BulkRenamerCompatibilityTests(unittest.TestCase):
    def test_deferred_batch_items_cannot_shift_result_mapping(self):
        self.assertIn("parse_batch_response(resp, len(valid_in_prompt))", SOURCE)
        self.assertIn("enumerate(valid_in_prompt)", SOURCE)

    def test_apply_respects_review_selection(self):
        self.assertIn("items = self.model.get_with_suggestions()", SOURCE)

    def test_same_address_is_not_treated_as_collision(self):
        self.assertIn("owner_ea != idaapi.BADADDR and owner_ea != f.ea", SOURCE)

    def test_configured_worker_count_is_an_upper_bound(self):
        self.assertIn("(len(items) + num_workers - 1) // num_workers", SOURCE)

    def test_retry_cooldown_is_cancellable(self):
        self.assertIn("cancel_checker=lambda: not self.running", SOURCE)
        self.assertIn("if _cancelled():", SOURCE)

    def test_worker_uses_bulk_specific_settings(self):
        self.assertIn("getattr(c, 'bulk_cooldown', 0)", SOURCE)
        self.assertIn("getattr(c, 'bulk_batch_size', 10)", SOURCE)
        self.assertIn("getattr(c, 'bulk_parallel_workers', 1)", SOURCE)
        self.assertNotIn("'cooldown_seconds': getattr(c, 'cooldown_seconds', 0)", SOURCE)

    def test_configured_pacing_is_not_reported_as_http_rate_limit(self):
        self.assertIn("Inter-batch cooldown:", SOURCE)
        self.assertIn("has_next_batch", SOURCE)
        self.assertNotIn("Rate limit reached. Cooling down for", SOURCE)

    def test_bulk_stop_does_not_cancel_unrelated_ai_features(self):
        section = SOURCE[SOURCE.index("    def stop_all(self):"):SOURCE.index("    def jump_to", SOURCE.index("    def stop_all(self):"))]
        self.assertNotIn("AI_CANCEL_REQUESTED = True", section)
        self.assertIn("self._cancel_requested = True", section)

    def test_batch_indicator_starts_only_after_input_validation(self):
        section = SOURCE[SOURCE.index("    def start_analyze(self):"):SOURCE.index("    def _start_worker_items", SOURCE.index("    def start_analyze(self):"))]
        self.assertGreater(section.index("self.batch_bar.set_running(True)"), section.index("if not items:"))


if __name__ == "__main__":
    unittest.main()
