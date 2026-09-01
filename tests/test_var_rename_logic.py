import ast
import unittest
from pathlib import Path


SOURCE = (Path(__file__).resolve().parents[1] / "pseudonote_extended" / "var_renamer.py").read_text(encoding="utf-8")
TREE = ast.parse(SOURCE)


def load_functions(*names):
    selected = [
        node for node in TREE.body
        if isinstance(node, ast.FunctionDef) and node.name in names
    ]
    namespace = {}
    exec(compile(ast.Module(body=selected, type_ignores=[]), "var_renamer_helpers", "exec"), namespace)
    return namespace


HELPERS = load_functions(
    "normalize_var_suggestions", "pending_var_suggestions",
    "rename_result_counts", "merge_rename_results", "filter_suggestions_for_lvars",
)


class VariableRenameLogicTests(unittest.TestCase):
    def test_common_ai_wrapper_is_unwrapped(self):
        normalize = HELPERS["normalize_var_suggestions"]
        self.assertEqual({"v1": "buffer"}, normalize({"renames": {"v1": "buffer"}}))

    def test_non_scalar_and_noop_proposals_are_rejected(self):
        normalize = HELPERS["normalize_var_suggestions"]
        self.assertEqual(
            {"v2": "count"},
            normalize({"v1": {"name": "buffer"}, "v2": "count", "v3": "v3"}),
        )

    def test_result_count_uses_verified_results_not_suggestion_count(self):
        counts = HELPERS["rename_result_counts"]
        self.assertEqual((1, 2), counts({
            "v1": {"success": True},
            "v2": {"success": False},
            "v3": {"success": False},
        }))

    def test_retry_result_replaces_old_failure_without_losing_other_successes(self):
        merge = HELPERS["merge_rename_results"]
        merged = merge(
            {"v1": {"success": True}, "v2": {"success": False}},
            {"v2": {"success": True}},
        )
        self.assertTrue(merged["v1"]["success"])
        self.assertTrue(merged["v2"]["success"])

    def test_only_real_lvars_survive_and_case_is_canonicalized(self):
        filter_lvars = HELPERS["filter_suggestions_for_lvars"]
        self.assertEqual(
            {"Buffer": "output_buffer", "v2": "count"},
            filter_lvars(
                {"buffer": "output_buffer", "v2": "count", "dword_404000": "flags"},
                ["Buffer", "v2"],
            ),
        )


if __name__ == "__main__":
    unittest.main()
