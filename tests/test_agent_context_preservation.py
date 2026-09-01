import pathlib
import unittest


ROOT = pathlib.Path(__file__).parents[1]
ANALYZER = (ROOT / "pseudonote_extended" / "agentic_analyzer.py").read_text(encoding="utf-8")
RUNTIME = (ROOT / "pseudonote_extended" / "agent_runtime.py").read_text(encoding="utf-8")


class AgentContextPreservationTests(unittest.TestCase):
    def test_compaction_reinjects_host_owned_ledger(self):
        self.assertIn("Earlier conversation was compacted", ANALYZER)
        self.assertIn("self.session.snapshot(max_chars=40000)", ANALYZER)
        self.assertNotIn("del self.history[1:3]", ANALYZER)

    def test_snapshot_prioritizes_bounded_observations(self):
        self.assertIn("compact_observations", RUNTIME)
        self.assertIn('"observations": compact_observations', RUNTIME)
        self.assertIn('[:1200]', RUNTIME)

    def test_function_evidence_does_not_stop_at_early_aggregate_limit(self):
        start = ANALYZER.index("def tool_function_evidence")
        end = ANALYZER.index("def tool_int_convert", start)
        section = ANALYZER[start:end]
        self.assertNotIn("len(strings) + len(data)", section)
        self.assertIn("len(strings) < limit", section)
        self.assertIn("len(constants) < limit", section)


if __name__ == "__main__":
    unittest.main()
