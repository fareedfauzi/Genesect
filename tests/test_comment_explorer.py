import ast
import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "pseudonote_extended" / "comment_explorer.py").read_text(encoding="utf-8")
PLUGIN = (ROOT / "pseudonote_extended" / "plugin.py").read_text(encoding="utf-8")
MENU = (ROOT / "pseudonote_extended" / "ui" / "context_menu.py").read_text(encoding="utf-8")


class CommentExplorerTests(unittest.TestCase):
    def test_feature_is_valid_registered_and_menu_accessible(self):
        ast.parse(SOURCE)
        self.assertIn("from pseudonote_extended.ui.mac_workspace import apply_mac_workspace", SOURCE)
        self.assertNotIn("from pseudonote_extended.ui.theme import apply_mac_workspace", SOURCE)
        action = "pseudonote_extended:comment_explorer"
        self.assertGreaterEqual(PLUGIN.count(action), 2)
        self.assertIn(action, MENU)

    def test_collects_all_requested_comment_scopes(self):
        for marker in ("get_cmt", "get_func_cmt", "restore_user_cmts", '"Disassembly"', '"Pseudocode"', '"Function"'):
            self.assertIn(marker, SOURCE)

    def test_supports_review_navigation_and_management(self):
        for marker in ("Filter comments", "navigate_selected", "edit_selected", "delete_selected", "QMessageBox.question", "Export CSV"):
            self.assertIn(marker, SOURCE)

    def test_pseudocode_edits_use_hexrays_user_comments(self):
        for marker in ("set_user_cmt", "save_user_cmts", "open_pseudocode"):
            self.assertIn(marker, SOURCE)

    def test_comment_kinds_remain_distinct(self):
        self.assertIn('"Repeatable" if repeatable else "Regular"', SOURCE)
        self.assertIn('"Hex-Rays"', SOURCE)


if __name__ == "__main__":
    unittest.main()
