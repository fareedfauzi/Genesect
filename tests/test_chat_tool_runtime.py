import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
CHAT = (ROOT / "pseudonote_extended" / "chat.py").read_text(encoding="utf-8")
RUNTIME = (ROOT / "pseudonote_extended" / "chat_tool_runtime.py").read_text(encoding="utf-8")


class ChatToolRuntimeTests(unittest.TestCase):
    def test_chat_has_live_idb_read_tools(self):
        for tool in (
            "decompile", "disassemble", "get_xrefs", "function_evidence",
            "basic_blocks", "stack_layout", "read_memory", "search_strings",
        ):
            self.assertIn(f'"{tool}"', RUNTIME)

    def test_chat_has_reviewed_ida_change_tools(self):
        for tool in ("rename_func", "rename_vars", "add_comment", "set_func_type", "create_apply_struct"):
            self.assertIn(f'"{tool}"', RUNTIME)
        self.assertIn("AgentPolicy(allow_mutations=True", RUNTIME)
        self.assertIn("_confirm_chat_tool", CHAT)
        self.assertIn("Review IDA Change", CHAT)

    def test_dangerous_escape_hatches_are_not_exposed(self):
        catalog = RUNTIME.split("CHAT_TOOL_CATALOG = {", 1)[1].split("}\n\n", 1)[0]
        self.assertNotIn("execute_idapython", catalog)
        self.assertNotIn("patch_bytes", catalog)

    def test_prompt_forbids_false_no_access_claims(self):
        self.assertIn("Never claim that you lack access", RUNTIME)
        self.assertIn("show the assembly", RUNTIME)
        self.assertIn('{"action":"tools"', RUNTIME)

    def test_ui_exposes_live_idb_shortcuts_and_centered_send_icon(self):
        self.assertIn('("Inspect Live IDB"', CHAT)
        self.assertIn('("Show pseudocode"', CHAT)
        self.assertIn('("Show assembly"', CHAT)
        self.assertIn("text-align: center", CHAT)
        self.assertIn("font-family: 'Segoe UI Symbol'", CHAT)


if __name__ == "__main__":
    unittest.main()
