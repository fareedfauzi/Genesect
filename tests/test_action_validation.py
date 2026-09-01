import importlib.util
import pathlib
import sys
import unittest

PATH = pathlib.Path(__file__).resolve().parents[1] / "pseudonote_extended" / "actions" / "validation.py"
SPEC = importlib.util.spec_from_file_location("pseudonote_extended_action_validation", PATH)
validation = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = validation
SPEC.loader.exec_module(validation)

parse_json_object = validation.parse_json_object
strip_code_fence = validation.strip_code_fence
validate_identifier = validation.validate_identifier
validate_prototype = validation.validate_prototype
validate_rename_mapping = validation.validate_rename_mapping
validate_struct = validation.validate_struct


class ActionValidationTests(unittest.TestCase):
    def test_strips_markdown_fence(self):
        self.assertEqual(strip_code_fence("```json\n{\"x\": 1}\n```"), '{"x": 1}')

    def test_extracts_json_object_from_explanation(self):
        result = parse_json_object('result: {"old": "new"} done')
        self.assertTrue(result.valid)
        self.assertEqual(result.value, {"old": "new"})

    def test_identifier_rejects_invalid_name(self):
        self.assertFalse(validate_identifier("bad name").valid)
        self.assertTrue(validate_identifier("packet_count").valid)

    def test_rename_mapping_discards_invalid_and_unchanged_rows(self):
        result = validate_rename_mapping({"v1": "packet_count", "same": "same", "bad key": "ok"})
        self.assertTrue(result.valid)
        self.assertEqual(result.value, {"v1": "packet_count"})

    def test_usercall_annotations_cannot_be_dropped(self):
        original = "int __usercall fn@<eax>(int value@<ecx>)"
        self.assertFalse(validate_prototype("int fn(int value)", original).valid)

    def test_valid_struct(self):
        self.assertTrue(validate_struct("struct Packet { int size; char data[16]; };").valid)

    def test_struct_rejects_expression_array_size(self):
        self.assertFalse(validate_struct("struct Packet { char data[4 + 4]; };").valid)


if __name__ == "__main__":
    unittest.main()
