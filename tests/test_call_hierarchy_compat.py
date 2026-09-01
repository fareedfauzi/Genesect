import pathlib
import unittest


SOURCE = (pathlib.Path(__file__).parents[1] / "pseudonote_extended" / "xrefs.py").read_text(encoding="utf-8")


class CallHierarchyCompatibilityTests(unittest.TestCase):
    def test_cycles_are_detected_and_rendered_as_leaves(self):
        self.assertIn("def _is_ancestor_target", SOURCE)
        self.assertIn(' + " (cycle)"', SOURCE)

    def test_api_toggle_filters_library_and_thunk_functions(self):
        self.assertGreaterEqual(SOURCE.count("is_api and not self.show_api_cb.isChecked()"), 2)

    def test_node_fanout_is_bounded(self):
        self.assertIn("MAX_CHILDREN_PER_NODE = 2000", SOURCE)
        self.assertIn("Results limited to", SOURCE)

    def test_cross_architecture_call_detection(self):
        self.assertIn("def _is_call_or_tail_jump", SOURCE)
        for mnemonic in ('"callq"', '"blx"', '"jalr"', '"bctrl"'):
            self.assertIn(mnemonic, SOURCE)

    def test_results_are_deduplicated_and_sorted(self):
        self.assertIn("key=lambda ref: (ref.frm, ref.to, ref.type)", SOURCE)
        self.assertIn("key=lambda ref: (ref.to, ref.type)", SOURCE)
        self.assertIn("visited = set()", SOURCE)

    def test_window_reference_is_released_on_close(self):
        close = SOURCE[SOURCE.index("def closeEvent"):SOURCE.index("def sync_to_current")]
        self.assertIn("_xrefs_win = None", close)

    def test_only_typed_calls_and_cross_function_tail_jumps_are_calls(self):
        self.assertIn("def _is_real_call_edge", SOURCE)
        self.assertIn("xref_type in _CALL_XREF_TYPES", SOURCE)
        self.assertIn("source_func.start_ea != target_func.start_ea", SOURCE)
        self.assertNotIn("set(idautils.CodeRefsFrom(ea, 0)) | set(idautils.DataRefsFrom(ea))", SOURCE)

    def test_data_references_are_separate_indirect_evidence(self):
        self.assertIn("ref.type in _DATA_XREF_TYPES", SOURCE)
        self.assertIn('edge_kind="address"', SOURCE)
        self.assertIn("Address-taken / callback reference", SOURCE)

    def test_local_branches_are_not_unresolved_calls(self):
        self.assertIn("def _is_unresolved_indirect_instruction", SOURCE)
        section = SOURCE[
            SOURCE.index("def _is_unresolved_indirect_instruction"):
            SOURCE.index("def _is_real_call_edge")
        ]
        self.assertNotIn('"b"', section)

    def test_large_function_instruction_scan_is_bounded(self):
        self.assertIn("MAX_INSTRUCTIONS_PER_EXPANSION = 100000", SOURCE)
        self.assertIn("if instruction_index >= MAX_INSTRUCTIONS_PER_EXPANSION", SOURCE)

    def test_context_menu_exposes_target_and_reference_navigation(self):
        self.assertIn("def on_context_menu", SOURCE)
        self.assertIn('menu.addAction("Go to function")', SOURCE)
        self.assertIn('menu.addAction("Go to reference site")', SOURCE)

    def test_filter_loads_immediate_lazy_relationships(self):
        section = SOURCE[SOURCE.index("def on_filter_changed"):SOURCE.index("def _apply_filter")]
        self.assertIn("if not root.loaded", section)
        self.assertIn("self.on_expand(root)", section)


if __name__ == "__main__":
    unittest.main()
