import ast
import pathlib
import unittest


PATH = pathlib.Path(__file__).parents[1] / "pseudonote_extended" / "deep_analyzer.py"
SOURCE = PATH.read_text(encoding="utf-8")


class DeepAnalyzerCompatibilityTests(unittest.TestCase):
    def test_final_tree_refresh_updates_inside_graph_loop(self):
        tree = ast.parse(SOURCE)
        cls = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "DeepAnalyzerDialog")
        method = next(n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == "sync_tree_from_graph")
        loop = next(n for n in ast.walk(method) if isinstance(n, ast.For) and isinstance(n.target, ast.Tuple))
        calls = [n for n in ast.walk(loop) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "setText"]
        self.assertGreaterEqual(len(calls), 4)

    def test_stage_mutation_helpers_are_not_nested_in_execute_sync(self):
        self.assertNotIn("idaapi.execute_sync(_sr, idaapi.MFF_WRITE)", SOURCE)
        self.assertNotIn("idaapi.execute_sync(_sv, idaapi.MFF_WRITE)", SOURCE)
        self.assertNotIn("idaapi.execute_sync(_sc, idaapi.MFF_WRITE)", SOURCE)
        self.assertNotIn("_consolidated_sync_update", SOURCE)

    def test_failed_rename_does_not_write_success_marker(self):
        self.assertGreaterEqual(SOURCE.count("if confidence > 0 and final_name != old_name_before:"), 2)

    def test_incomplete_batch_response_cannot_rename_to_unresolved(self):
        self.assertIn("Batch response omitted a valid name", SOURCE)
        self.assertNotIn('raw_name = "unresolved"', SOURCE)
        self.assertIn("confidence = max(0, min(100", SOURCE)

    def test_valid_entry_is_persisted(self):
        self.assertIn("if self.entry_ea is not None and self.entry_ea != idaapi.BADADDR:", SOURCE)

    def test_worker_configuration_is_bounded(self):
        self.assertIn("max_workers = max(1, min(max_workers, 32, len(wave_tasks) or 1))", SOURCE)
        self.assertIn("batch_funcs=max(1, min(5", SOURCE)

    def test_close_waits_for_workers(self):
        self.assertIn("for name in (\"rename_worker\", \"analysis_worker\", \"graph_worker\")", SOURCE)
        self.assertIn("worker.wait(remaining_ms)", SOURCE)

    def test_graph_persistence_reads_binary_path_on_main_thread(self):
        self.assertIn("def _main_thread_input_path", SOURCE)
        section = SOURCE[SOURCE.index("def save_graph_to_disk"):SOURCE.index("def load_graph_from_disk")]
        self.assertIn("_main_thread_input_path()", section)
        self.assertNotIn("ida_nalt.get_input_file_path()", section)

    def test_variable_rename_does_not_nest_synchronized_transactions(self):
        section = SOURCE[
            SOURCE.index("def apply_variable_renames_in_ida"):
            SOURCE.index("def apply_function_rename_from_analysis")
        ]
        call_pos = section.index("apply_var_renames(res_box")
        resolver_end = section.index("idaapi.execute_sync(_resolve_target")
        self.assertGreater(call_pos, resolver_end)
        callback = section[section.index("    def _resolve_target"):resolver_end]
        self.assertNotIn("apply_var_renames", callback)

    def test_comment_target_is_inspected_on_main_thread(self):
        section = SOURCE[
            SOURCE.index("def apply_function_comment"):
            SOURCE.index("def validate_analysis_response")
        ]
        callback = section[
            section.index("    def _inspect_target"):
            section.index("    idaapi.execute_sync(_inspect_target")
        ]
        self.assertIn("idc.get_func_name(ea)", callback)
        self.assertNotIn("is_valid_seg(ea)", section)

    def test_malformed_analysis_is_not_counted_as_success(self):
        section = SOURCE[
            SOURCE.index("def analyze_single_function"):
            SOURCE.index("def analyze_batch_functions")
        ]
        self.assertIn("parse_succeeded", section)
        self.assertIn("return None, analysis_code", section)
        self.assertIn('node.status = "error"', section)
        self.assertIn('"error")', SOURCE[SOURCE.index("_UNRESOLVED ="):])

    def test_cancelled_response_is_discarded_before_persistence(self):
        section = SOURCE[
            SOURCE.index("def analyze_single_function"):
            SOURCE.index("def analyze_batch_functions")
        ]
        cancel_pos = section.index("if _ai_mod.AI_CANCEL_REQUESTED:")
        persistence_pos = section.index("# Persistence")
        self.assertLess(cancel_pos, persistence_pos)


if __name__ == "__main__":
    unittest.main()
