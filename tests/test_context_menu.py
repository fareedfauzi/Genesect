import importlib.util
import pathlib
import unittest

PATH = pathlib.Path(__file__).resolve().parents[1] / "pseudonote_extended" / "ui" / "context_menu.py"
SPEC = importlib.util.spec_from_file_location("pseudonote_extended_context_menu", PATH)
menu = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(menu)


class ContextMenuTests(unittest.TestCase):
    def test_groups_are_task_oriented(self):
        names = [name for name, _ in menu.menu_groups(True)]
        top_levels = []
        for name in names:
            top = name.split("/", 1)[0]
            if top not in top_levels:
                top_levels.append(top)
        self.assertEqual(top_levels, ["", "AI Assistant", "Utilities", "Bookmarks"])
        self.assertNotIn("Workspace", top_levels)
        self.assertEqual(dict(menu.menu_groups(True))[""], ["pseudonote_extended:settings"])
        self.assertIn("AI Assistant/Rename && Comments (Current Function)", names)
        self.assertIn("AI Assistant/Analyst Notes", names)
        self.assertIn("Utilities/Program Structure", names)
        self.assertIn("Utilities/Navigation && Views", names)
        self.assertIn("Utilities/IDB Maintenance", names)

    def test_actions_are_unique_per_rendered_menu(self):
        for pseudocode in (False, True):
            for _, rows in menu.menu_groups(pseudocode):
                actions = [action for action in rows if action != "-"]
                self.assertEqual(len(actions), len(set(actions)))

    def test_bookmarks_are_configurable_and_view_specific(self):
        for pseudocode in (False, True):
            requested = ["pseudonote_extended:ask_chat", "pseudonote_extended:shellcode_analyst"]
            bookmarks = dict(menu.menu_groups(pseudocode, requested))["Bookmarks"]
            self.assertIn("pseudonote_extended:ask_chat", bookmarks)
            self.assertEqual(
                "pseudonote_extended:shellcode_analyst" in bookmarks,
                not pseudocode,
            )

    def test_empty_bookmarks_keep_the_submenu_visible(self):
        bookmarks = dict(menu.menu_groups(True, []))["Bookmarks"]
        self.assertEqual(bookmarks, ["pseudonote_extended:bookmarks_empty"])

    def test_bookmark_candidates_exclude_settings_and_placeholder(self):
        actions = [action for _category, action in menu.bookmark_candidates()]
        self.assertNotIn("pseudonote_extended:settings", actions)
        self.assertNotIn("pseudonote_extended:bookmarks_empty", actions)
        self.assertEqual(len(actions), len(set(actions)))

    def test_view_specific_actions(self):
        pseudo = [a for _, rows in menu.menu_groups(True) for a in rows]
        disasm = [a for _, rows in menu.menu_groups(False) for a in rows]
        self.assertIn("pseudonote_extended:suggest_function_prototype", pseudo)
        self.assertNotIn("pseudonote_extended:suggest_function_prototype", disasm)
        self.assertIn("pseudonote_extended:copy_yara_rule", disasm)
        self.assertNotIn("pseudonote_extended:shellcode_analyst", pseudo)
        self.assertIn("pseudonote_extended:shellcode_analyst", disasm)

    def test_view_controls_are_always_visible_in_both_contexts(self):
        required = {
            "pseudonote_extended:hex_viewer",
            "pseudonote_extended:toggle_highlight",
            "pseudonote_extended:toggle_disasm_highlight",
            "pseudonote_extended:toggle_indent_guides",
        }
        for pseudocode in (False, True):
            groups = dict(menu.menu_groups(pseudocode))
            self.assertTrue(required.issubset(set(groups["Utilities/Navigation && Views"])))

    def test_requested_group_order(self):
        expected = [
            "",
            "AI Assistant/Analyst Notes",
            "AI Assistant/Chat, Summarizer, && Agentic",
            "AI Assistant/Bulk Analysis && Workflow",
            "AI Assistant/Rename && Comments (Current Function)",
            "Utilities/Navigation && Views", "Utilities/Program Structure",
            "Utilities/Malware Analysis", "Utilities/Search && Data",
            "Utilities/IDB Maintenance",
        ]
        for pseudocode in (False, True):
            names = [name for name, _ in menu.menu_groups(pseudocode)]
            self.assertEqual(names[:len(expected)], expected)
            self.assertEqual(names[-3:], [
                "Utilities/Copy && Export",
                "Utilities/External Pivot Search",
                "Bookmarks",
            ])

    def test_separator_order_for_ai_workflows(self):
        groups = dict(menu.menu_groups(False))
        self.assertEqual(
            groups["AI Assistant/Chat, Summarizer, && Agentic"].count("-"), 2
        )
        self.assertEqual(
            groups["AI Assistant/Bulk Analysis && Workflow"].count("-"), 1
        )
