import pathlib
import unittest


SOURCE = (pathlib.Path(__file__).parents[1] / "pseudonote_extended" / "handlers.py").read_text(encoding="utf-8")


class SingleRenameCompatibilityTests(unittest.TestCase):
    def test_single_function_name_does_not_use_bulk_cleaner(self):
        section = SOURCE[SOURCE.index("def _review_function_rename"):SOURCE.index("# Conversation history")]
        self.assertNotIn("clean_name(", section)
        self.assertIn("_finalize_single_function_name", section)

    def test_prefix_is_applied_deterministically(self):
        self.assertIn('prefix = CONFIG.function_prefix.strip() if CONFIG.use_rename_prefix else ""', SOURCE)
        self.assertIn('candidate = f"{prefix}{result.value}"', SOURCE)
        self.assertNotIn("prefix it with '{prefix}'", SOURCE)

    def test_function_rename_is_a_durable_user_name(self):
        self.assertIn("ida_name.SN_NOWARN | ida_name.SN_FORCE", SOURCE)

    def test_function_name_collisions_are_resolved_before_review(self):
        self.assertIn("owner not in (idaapi.BADADDR, func_ea)", SOURCE)
        self.assertIn("for suffix in range(1, 100)", SOURCE)

    def test_plain_text_and_json_name_responses_are_supported(self):
        self.assertIn("def _extract_suggested_function_name", SOURCE)
        self.assertIn('(\"suggested_name\", \"function_name\", \"name\")', SOURCE)

    def test_variable_context_is_bounded_and_local_only(self):
        self.assertIn("if len(code) > 60000:", SOURCE)
        self.assertIn("Suggest local variables and parameters only", SOURCE)

    def test_comments_use_only_successful_variable_renames(self):
        callback = SOURCE[SOURCE.index("def _pn_rename_callback"):SOURCE.index("class RenameVariablesHandler")]
        self.assertIn('outcome.get("success")', callback)
        self.assertIn('outcome.get("final_name")', callback)
        self.assertIn("idc.get_func_cmt(func.start_ea", callback)

    def test_request_start_failures_clear_progress(self):
        self.assertGreaterEqual(SOURCE.count("request failed: {exc}"), 3)


if __name__ == "__main__":
    unittest.main()
