import pathlib
import importlib.util
import sys
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
CHAT = (ROOT / "pseudonote_extended" / "chat.py").read_text(encoding="utf-8")
RUNTIME = (ROOT / "pseudonote_extended" / "chat_tool_runtime.py").read_text(encoding="utf-8")


def _load_runtime():
    # Stub the two dependency-free imports under the package names expected by
    # chat_tool_runtime so its intent router can be tested without IDA.
    for name in ("pseudonote_extended.agent_policy", "pseudonote_extended.agent_runtime"):
        path = ROOT / (name.replace(".", "/") + ".py")
        spec = importlib.util.spec_from_file_location(name, path)
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
    path = ROOT / "pseudonote_extended" / "chat_tool_runtime.py"
    spec = importlib.util.spec_from_file_location("pseudonote_extended.chat_tool_runtime_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ChatDecisionControllerTests(unittest.TestCase):
    def test_explicit_live_idb_reads_bypass_model_planning(self):
        self.assertIn("if self._try_direct_read_request(text):", CHAT)
        self.assertIn("return direct_read_tool(text)", CHAT)
        runtime = _load_runtime()
        self.assertEqual(runtime.direct_read_tool("Show pseudocode"), "decompile")
        self.assertEqual(runtime.direct_read_tool("Show assembly"), "disassemble")
        self.assertEqual(runtime.direct_read_tool("Show callers and callees"), "get_xrefs")
        self.assertEqual(runtime.direct_read_tool("Show variables and stack"), "stack_layout")
        self.assertEqual(runtime.direct_read_tool("Show basic blocks"), "basic_blocks")

    def test_direct_results_are_rendered_in_full_code_blocks(self):
        self.assertIn('"decompile": ("Hex-Rays pseudocode", "c")', CHAT)
        self.assertIn('"disassemble": ("IDA disassembly", "asm")', CHAT)
        self.assertIn('return f"### {title}', CHAT)

    def test_duplicate_model_decisions_are_reported_back_for_finalization(self):
        self.assertIn("self._successful_tool_results = []", CHAT)
        self.assertIn("Skipped: Identical tool call already attempted", CHAT)
        self.assertNotIn("if duplicate_call:", CHAT)
        self.assertIn("self._request_chat_tool_followup(token)", CHAT)

    def test_prompt_forbids_repeating_successful_reads(self):
        self.assertIn("Never request an identical", RUNTIME)
        self.assertIn("never retry a tool that returned a complete result", RUNTIME)

    def test_disassembly_request_is_not_overridden_by_pseudocode_context(self):
        runtime = _load_runtime()
        prompt = (
            "Show the actual IDA disassembly for this function. Use the disassemble tool; "
            "do not infer assembly from pseudocode."
        )
        self.assertEqual(runtime.direct_read_tool(prompt), "disassemble")
        self.assertEqual(runtime.direct_read_tool("Show the actual Hex-Rays pseudocode"), "decompile")


if __name__ == "__main__":
    unittest.main()
