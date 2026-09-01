import ast
import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "pseudonote_extended" / "handlers.py").read_text(encoding="utf-8")


def _load_budget(config):
    tree = ast.parse(SOURCE)
    function = next(
        node for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "_fit_function_name_request"
    )
    module = ast.Module(body=[function], type_ignores=[])
    namespace = {"CONFIG": config}
    exec(compile(module, "handlers.py", "exec"), namespace)
    return namespace["_fit_function_name_request"]


class _Config:
    active_provider = "LMStudio"
    request_context_window_tokens = 4096


class FunctionNameContextBudgetTests(unittest.TestCase):
    def test_large_local_request_fits_four_k_context(self):
        fit = _load_budget(_Config())
        prompt, options, compacted = fit("A" * 30000 + "FINAL_INSTRUCTIONS")
        self.assertTrue(compacted)
        self.assertLessEqual(len(prompt), (4096 - 128 - 256) * 2)
        self.assertTrue(prompt.endswith("FINAL_INSTRUCTIONS"))
        self.assertEqual(options, {"max_completion_tokens": 128})

    def test_small_request_is_unchanged(self):
        fit = _load_budget(_Config())
        prompt, options, compacted = fit("short pseudocode")
        self.assertEqual(prompt, "short pseudocode")
        self.assertFalse(compacted)
        self.assertEqual(options["max_completion_tokens"], 128)

    def test_both_function_name_handlers_use_budget(self):
        self.assertEqual(SOURCE.count("= _fit_function_name_request(prompt)"), 2)
        self.assertGreaterEqual(SOURCE.count("additional_options=request_options"), 2)


if __name__ == "__main__":
    unittest.main()
