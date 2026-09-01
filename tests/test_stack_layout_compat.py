import pathlib
import unittest


SOURCE = (pathlib.Path(__file__).parents[1] / "pseudonote_extended" / "agentic_analyzer.py").read_text(encoding="utf-8")


class StackLayoutCompatibilityTests(unittest.TestCase):
    def test_hexrays_members_support_properties_and_methods(self):
        start = SOURCE.index("def tool_stack_layout")
        end = SOURCE.index("def tool_function_evidence", start)
        section = SOURCE[start:end]
        self.assertIn("if callable(value):", section)
        self.assertIn('member_value(variable, "is_arg_var", False)', section)
        self.assertIn('member_value(variable, "is_result_var", False)', section)
        self.assertNotIn("variable.is_arg_var()", section)
        self.assertNotIn("variable.is_result_var()", section)

    def test_location_falls_back_to_vloc(self):
        start = SOURCE.index("def tool_stack_layout")
        end = SOURCE.index("def tool_function_evidence", start)
        section = SOURCE[start:end]
        self.assertIn('member_value(variable, "location", None)', section)
        self.assertIn('member_value(variable, "vloc", "")', section)


if __name__ == "__main__":
    unittest.main()
