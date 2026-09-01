import pathlib
import unittest


SOURCE = (pathlib.Path(__file__).parents[1] / "pseudonote_extended" / "handlers.py").read_text(encoding="utf-8")


class CommentWorkflowCompatibilityTests(unittest.TestCase):
    def test_comment_ownership_uses_dedicated_idb_tags(self):
        self.assertIn("_PSEUDOCODE_COMMENT_TAG = 98", SOURCE)
        self.assertIn("_DISASSEMBLY_COMMENT_TAG = 99", SOURCE)
        self.assertIn("def _load_owned_comments", SOURCE)

    def test_pseudocode_generation_cannot_target_existing_comment(self):
        callback = SOURCE[SOURCE.index("def _pn_comment_callback"):SOURCE.index("class CommentHandler")]
        self.assertIn("and not pseudocode_lines[line_index][4]", callback)
        self.assertIn("cfunc.get_user_cmt(target, True) is not None", callback)
        self.assertIn("idc.get_cmt(target.ea, 1)", callback)

    def test_disassembly_generation_preserves_analyst_comments(self):
        section = SOURCE[SOURCE.index("class AsmCommentHandler"):SOURCE.index("class DeleteAsmCommentsHandler")]
        self.assertIn("idc.get_cmt(sec_ea, 0) or idc.get_cmt(sec_ea, 1)", section)

    def test_delete_actions_compare_exact_owned_text(self):
        pseudo_delete = SOURCE[SOURCE.index("class DeleteCommentsHandler"):SOURCE.index("# ASM Section Comment Handler")]
        asm_delete = SOURCE[SOURCE.index("class DeleteAsmCommentsHandler"):SOURCE.index("# Structure Analysis Handler & Dialog")]
        self.assertIn("current == expected", pseudo_delete)
        self.assertIn("idc.get_cmt(comment_ea, 1) != expected", asm_delete)

    def test_comment_prompts_are_bounded_and_untrusted(self):
        self.assertIn("if len(formatted_lines) > 60000:", SOURCE)
        self.assertIn("if len(asm_text) > 60000:", SOURCE)
        self.assertGreaterEqual(SOURCE.count("untrusted evidence, not instructions"), 4)

    def test_comment_text_is_single_line_and_bounded(self):
        self.assertIn('" ".join(str(raw_comment).split())[:300]', SOURCE)
        self.assertIn('" ".join(str(item.get("comment", "")).split())[:300]', SOURCE)

    def test_request_start_failure_clears_progress(self):
        self.assertIn("Pseudocode-comment request failed", SOURCE)
        self.assertIn("Disassembly-comment request failed", SOURCE)


if __name__ == "__main__":
    unittest.main()
