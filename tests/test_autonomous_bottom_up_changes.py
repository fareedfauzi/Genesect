import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
ANALYZER = (ROOT / "pseudonote_extended" / "agentic_analyzer.py").read_text(encoding="utf-8-sig")
RUNTIME = (ROOT / "pseudonote_extended" / "agent_runtime.py").read_text(encoding="utf-8-sig")
POLICY = (ROOT / "pseudonote_extended" / "agent_policy.py").read_text(encoding="utf-8-sig")


class AutonomousBottomUpChangesTests(unittest.TestCase):
    def test_durable_function_memory_is_checkpointed(self):
        self.assertIn("function_memory: dict", RUNTIME)
        self.assertIn("def remember_function", RUNTIME)
        self.assertIn("payload = asdict(self)", RUNTIME)
        self.assertIn('"recent_function_memory": dict(memory_items[-40:])', RUNTIME)

    def test_structured_completion_contract_is_host_validated(self):
        self.assertIn('"record_function_analysis"', ANALYZER)
        self.assertIn('tool_name == "record_function_analysis"', ANALYZER)
        self.assertIn("evidence_supported_for_ea(ea, evidence)", ANALYZER)
        self.assertIn("_short_function_summary", ANALYZER)
        self.assertIn("clean_name(requested_name", ANALYZER)

    def test_low_confidence_results_are_rescanned(self):
        self.assertIn("confidence <= 50 and attempts < 3", ANALYZER)
        self.assertIn('"retry_low_confidence"', ANALYZER)
        self.assertIn("reanalyze this function individually", ANALYZER)

    def test_rename_and_managed_comment_are_atomic_and_recoverable(self):
        self.assertIn("def _apply_function_name_and_comment", ANALYZER)
        self.assertIn('_MANAGED_COMMENT_PREFIX = "[PseudoNote] "', ANALYZER)
        self.assertIn("_replace_managed_comment", ANALYZER)
        self.assertIn("ida_name.set_name(ea, original_name", ANALYZER)
        self.assertIn("idc.set_func_cmt(ea, original_comment", ANALYZER)
        self.assertIn('"apply_function_metadata": WRITE_IDB', POLICY)

    def test_changes_are_only_applied_after_explicit_toggle(self):
        self.assertIn("if self.policy.allow_mutations:", ANALYZER)
        self.assertIn("Apply validated bottom-up function names", ANALYZER)

    def test_manual_changes_are_not_silently_overwritten(self):
        self.assertIn("conflict with manual IDA edits", ANALYZER)
        self.assertIn("they were not overwritten", ANALYZER)

    def test_large_call_graph_and_stale_callers_are_handled_safely(self):
        self.assertIn("Iterative Kosaraju", ANALYZER)
        self.assertNotIn("def strongconnect", ANALYZER)
        self.assertIn("A callee changed and caller context must be refreshed", ANALYZER)
        self.assertIn("self.session.invalidate_function_cache(ea)", ANALYZER)

    def test_normal_ui_suppresses_raw_autonomous_tool_spam(self):
        self.assertIn('self._task_profile != "autonomous_full" or result_status(result) == "error"', ANALYZER)
        self.assertIn("Coverage complete:", ANALYZER)
        self.assertIn("names retained", ANALYZER)

    def test_progress_and_short_function_explanations_are_visible(self):
        self.assertIn("self.analysis_progress = QtWidgets.QProgressBar()", ANALYZER)
        self.assertIn('self.analysis_progress_label.setText(f"{processed:,} / {total:,} processed")', ANALYZER)
        self.assertIn("What it does: {summary}", ANALYZER)
        self.assertIn("self._refresh_agent_dashboard()", ANALYZER)


if __name__ == "__main__":
    unittest.main()
