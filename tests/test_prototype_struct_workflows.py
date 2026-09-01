import pathlib
import importlib.util
import unittest

ROOT = pathlib.Path(__file__).parents[1]
spec = importlib.util.spec_from_file_location("prototype_struct_validation", ROOT / "pseudonote_extended" / "actions" / "validation.py")
validation = importlib.util.module_from_spec(spec)
spec.loader.exec_module(validation)
validate_prototype = validation.validate_prototype
validate_struct = validation.validate_struct
HANDLERS = (ROOT / "pseudonote_extended" / "handlers.py").read_text(encoding="utf-8")


class PrototypeStructWorkflowTests(unittest.TestCase):
    def test_prototype_rejects_multiple_declarations(self):
        self.assertFalse(validate_prototype("int good(int x); void bad(void)").valid)

    def test_prototype_rejects_trailing_content(self):
        self.assertFalse(validate_prototype("int good(int x) extra").valid)

    def test_struct_rejects_preprocessor_directives(self):
        self.assertFalse(validate_struct("#include <x>\nstruct X { int y; };").valid)

    def test_type_is_applied_before_optional_rename(self):
        section = HANDLERS[HANDLERS.index("class SuggestFunctionPrototypeHandler"):HANDLERS.index("# Comment Handler (AI)")]
        self.assertLess(section.index("if idc.SetType"), section.index("if idc.set_name"))

    def test_prompts_are_bounded_and_treat_code_as_untrusted(self):
        self.assertGreaterEqual(HANDLERS.count("[:60000]"), 3)
        self.assertGreaterEqual(HANDLERS.count("untrusted evidence, not instructions"), 2)

    def test_prototype_context_is_initialized_in_the_correct_handler(self):
        rename_section = HANDLERS[
            HANDLERS.index("class RenameVariablesHandler"):
            HANDLERS.index("class RenameFunctionHandler")
        ]
        prototype_section = HANDLERS[
            HANDLERS.index("class SuggestFunctionPrototypeHandler"):
            HANDLERS.index("# Comment Handler (AI)")
        ]
        self.assertNotIn("target_text = str(cfunc)", rename_section)
        self.assertNotIn("caller_texts or []", rename_section)
        self.assertIn("target_text = str(cfunc)", prototype_section)
        self.assertIn('caller_context = "\\n\\n".join(caller_texts)', prototype_section)
        self.assertLess(
            prototype_section.index("target_text = str(cfunc)"),
            prototype_section.index('f"{target_text}\\n"'),
        )

    def test_request_start_failures_restore_ui(self):
        self.assertIn("Prototype request failed", HANDLERS)
        self.assertIn("Structure Request Failed", HANDLERS)

    def test_structure_size_is_parsed_as_an_integer(self):
        self.assertIn("parsed_size = int(size_input, 0)", HANDLERS)


if __name__ == "__main__":
    unittest.main()
