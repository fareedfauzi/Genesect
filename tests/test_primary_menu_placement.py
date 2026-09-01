import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
CONFIG = (ROOT / "pseudonote_extended" / "config.py").read_text(encoding="utf-8")
PLUGIN = (ROOT / "pseudonote_extended" / "plugin.py").read_text(encoding="utf-8")
CONTEXT = (ROOT / "pseudonote_extended" / "ui" / "context_menu.py").read_text(encoding="utf-8")


class PrimaryMenuPlacementTests(unittest.TestCase):
    def test_indent_marks_are_enabled_by_default(self):
        self.assertIn("self.indent_guides_enabled = True", CONFIG)
        self.assertIn('"INDENT_GUIDES_ENABLED", fallback=True', CONFIG)

    def test_edit_plugins_menu_is_not_used(self):
        self.assertNotIn("attach_action_to_menu", PLUGIN)
        self.assertNotIn("Edit/Plugins/PseudoNote", PLUGIN)
        self.assertIn("idaapi.PLUGIN_FIX | idaapi.PLUGIN_HIDE", PLUGIN)
        self.assertIn("right-click in Disassembly/Pseudocode", PLUGIN)

    def test_view_and_history_actions_are_in_context_menu(self):
        for action_id in (
            "pseudonote_extended:toggle_highlight",
            "pseudonote_extended:toggle_disasm_highlight",
            "pseudonote_extended:toggle_indent_guides",
            "pseudonote_extended:hex_viewer",
            "pseudonote_extended:change_history_explorer",
        ):
            self.assertIn(action_id, CONTEXT)


if __name__ == "__main__":
    unittest.main()
