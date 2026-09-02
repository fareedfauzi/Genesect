import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "pseudonote_extended" / "agentic_analyzer.py").read_text(encoding="utf-8-sig")


class AutonomousFullCoverageTests(unittest.TestCase):
    def test_autopilot_uses_host_enumerated_entire_idb_queue(self):
        self.assertIn("def _collect_all_functions():", SOURCE)
        self.assertIn('self._task_profile = "autonomous_full"', SOURCE)
        self.assertIn("self._task_targets = _collect_all_functions()", SOURCE)
        self.assertIn("complete A-to-Z autonomous investigation", SOURCE)

    def test_budget_scales_with_binary_function_count(self):
        self.assertIn("max_steps=max(128, target_count * 10 + 64)", SOURCE)
        self.assertIn("max_seconds=max(1800, target_count * 30)", SOURCE)
        self.assertIn("(target_count * 9 + 3) // 4 + 32", SOURCE)

    def test_coverage_requires_metadata_and_code_for_every_function(self):
        self.assertIn("self.session.function_memory.get(ea, {})", SOURCE)
        runtime = (ROOT / "pseudonote_extended" / "agent_runtime.py").read_text(encoding="utf-8-sig")
        self.assertIn("function_coverage: dict", runtime)
        self.assertIn('tool in ("function_evidence", "decompile", "disassemble")', runtime)
        self.assertIn("CURRENT FUNCTION TRANSACTION", SOURCE)

    def test_final_report_is_rejected_while_any_function_is_pending(self):
        self.assertIn('if self._task_profile == "autonomous_full":', SOURCE)
        self.assertIn("functions remain pending", SOURCE)
        self.assertIn('self._task_profile == "autonomous_full" or not self._must_finalize', SOURCE)
        self.assertIn("No premature summary was accepted", SOURCE)
        self.assertIn('all_calls_repeated and self._task_profile != "autonomous_full"', SOURCE)

    def test_scheduler_is_bottom_up_and_cycle_aware(self):
        for marker in ("Iterative Kosaraju", "components.append", "dependencies =", "ordered_components", 'f"cycle-{order + 1}"'):
            self.assertIn(marker, SOURCE)

    def test_callee_memory_is_propagated_to_caller_batches(self):
        self.assertIn('"known_callees"', SOURCE)
        self.assertIn('memory.get("summary")', SOURCE)
        self.assertIn("callee-first", SOURCE)

    def test_host_completes_one_function_before_advancing(self):
        self.assertIn("def _ready_coverage_targets(self, limit=1)", SOURCE)
        self.assertIn("def _coverage_batch_text(self, batch_size=1)", SOURCE)
        self.assertIn("Do not inspect another function until record_function_analysis succeeds", SOURCE)


if __name__ == "__main__":
    unittest.main()
