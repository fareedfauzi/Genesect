import pathlib
import types
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]


class ChatToolExecutionTypeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # chat.py is an IDA UI module, so execute only its pure classifier.
        source = (ROOT / "pseudonote_extended" / "chat.py").read_text(encoding="utf-8")
        start = source.index("AI_WORKFLOW_ACTIONS =")
        end = source.index("\ndef get_ida_colors", start)
        def direct_read_tool(text):
            lowered = str(text).lower()
            return "direct" if "show" in lowered and ("pseudocode" in lowered or "assembly" in lowered) else None
        namespace = {"direct_read_tool": direct_read_tool, "frozenset": frozenset}
        exec(source[start:end], namespace)
        runtime = types.SimpleNamespace()
        runtime.classify = namespace["chat_tool_execution_type"]
        cls.runtime = runtime

    def test_direct_live_idb_prompts_are_tools(self):
        self.assertEqual(self.runtime.classify("prompt", "Show the actual Hex-Rays pseudocode"), "Tool")
        self.assertEqual(self.runtime.classify("prompt", "Show assembly"), "Tool")

    def test_reasoning_prompts_are_ai(self):
        self.assertEqual(self.runtime.classify("prompt", "Explain this function step by step"), "AI")

    def test_model_backed_actions_are_ai(self):
        self.assertEqual(self.runtime.classify("action", "pseudonote_extended:rename_variables"), "AI")

    def test_local_navigation_actions_are_tools(self):
        self.assertEqual(self.runtime.classify("action", "pseudonote_extended:readable_code"), "Tool")


if __name__ == "__main__":
    unittest.main()
