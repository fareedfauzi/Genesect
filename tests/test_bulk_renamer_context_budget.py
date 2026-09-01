import pathlib
import unittest


SOURCE = (
    pathlib.Path(__file__).resolve().parents[1]
    / "pseudonote_extended"
    / "renamer.py"
).read_text(encoding="utf-8")


class BulkRenamerContextBudgetTests(unittest.TestCase):
    def test_local_model_budget_covers_entire_request(self):
        self.assertIn("LOCAL_RENAME_REQUEST_CHARS = 9000", SOURCE)
        self.assertIn("rename_request_char_budget(self.cfg) - len(self.sys_prompt)", SOURCE)
        self.assertNotIn("40000 // len(valid)", SOURCE)

    def test_long_code_retains_head_and_behavioral_tail(self):
        section = SOURCE[
            SOURCE.index("def bounded_rename_text"):
            SOURCE.index("def fit_rename_user_prompt")
        ]
        self.assertIn("value[:head]", section)
        self.assertIn("value[-(available - head):]", section)

    def test_single_and_batch_requests_have_small_completion_budgets(self):
        self.assertIn("max_tokens=160", SOURCE)
        self.assertIn("min(512, len(valid_in_prompt) * 48)", SOURCE)

    def test_empty_deferred_batch_does_not_send_a_request(self):
        self.assertIn("if not valid_in_prompt:", SOURCE)
        self.assertIn("functions require bounded single-function analysis", SOURCE)


if __name__ == "__main__":
    unittest.main()
