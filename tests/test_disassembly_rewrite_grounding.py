import ast
import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
VIEW_PATH = ROOT / "pseudonote_extended" / "view.py"
SOURCE = VIEW_PATH.read_text(encoding="utf-8")


def _load_validator():
    tree = ast.parse(SOURCE)
    node = next(item for item in tree.body if isinstance(item, ast.FunctionDef) and item.name == "validate_disassembly_rewrite")
    module = ast.Module(body=[node], type_ignores=[])
    namespace = {"re": __import__("re")}
    exec(compile(module, str(VIEW_PATH), "exec"), namespace)
    return namespace["validate_disassembly_rewrite"]


class DisassemblyRewriteGroundingTests(unittest.TestCase):
    def test_collection_does_not_inline_remote_tail_chunks(self):
        self.assertIn("def collect_function_disassembly", SOURCE)
        self.assertIn("idautils.Chunks(func.start_ea)", SOURCE)
        self.assertIn("REFERENCED TAIL CHUNK NOT EXPANDED", SOURCE)
        self.assertIn("if chunk_start != func.start_ea", SOURCE)
        self.assertIn("continue", SOURCE)

    def test_hallucinated_identity_constants_and_calls_are_rejected(self):
        validate = _load_validator()
        assembly = "; TARGET FUNCTION: start\n0x1400013F4: mov rax, cs:flag\n0x140001401: call sub_1400011B0\n0x140001406: nop\n0x14000140C: retn"
        code = "int sub_14000AEB0(void) { if (value > 0x20474343) return 1; }"
        problems = validate(code, assembly, "start")
        self.assertTrue(any("target function name" in item for item in problems))
        self.assertTrue(any("unsupported hexadecimal constants" in item for item in problems))
        self.assertTrue(any("omitted direct call" in item for item in problems))

    def test_grounded_rewrite_passes(self):
        validate = _load_validator()
        assembly = "; TARGET FUNCTION: start\n0x401000: call initialize_runtime\n0x401005: retn"
        code = "int start(void) { initialize_runtime(); return 0; }"
        self.assertEqual(validate(code, assembly, "start"), [])

    def test_prompt_forbids_invention_and_completion_is_bounded(self):
        self.assertIn("Never invent constants, fields, loops, cases, APIs, or conditions", SOURCE)
        self.assertIn("Convert this ASM to readable", SOURCE)
        self.assertIn("Do not declare one variable per register or instruction", SOURCE)
        self.assertIn('additional_options={"max_completion_tokens": 4096}', SOURCE)


if __name__ == "__main__":
    unittest.main()
