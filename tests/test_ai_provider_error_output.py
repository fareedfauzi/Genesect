import pathlib
import unittest


ROOT = pathlib.Path(__file__).parents[1]
SOURCE = (ROOT / "pseudonote_extended" / "ai_client.py").read_text(encoding="utf-8")


class AIProviderErrorOutputTests(unittest.TestCase):
    def test_context_overflow_is_identified_as_model_error(self):
        self.assertIn('category = "MODEL CONTEXT ERROR" if context_limit', SOURCE)
        self.assertIn("This is not a PseudoNote plugin failure.", SOURCE)
        self.assertIn('"trying to keep the first"', SOURCE)

    def test_provider_failure_is_printed_to_ida_output(self):
        self.assertIn("output_message = _format_provider_error(", SOURCE)
        self.assertIn("safe_execute(lambda text=output_message: print(text))", SOURCE)
        self.assertIn('f"  Provider: {provider}\\n"', SOURCE)
        self.assertIn('f"  Model: {model or \'<not configured>\'}\\n"', SOURCE)
        self.assertIn('f"  Provider details: {detail}\\n"', SOURCE)


if __name__ == "__main__":
    unittest.main()
