import importlib.util
import pathlib
import sys
import unittest


ROOT = pathlib.Path(__file__).parents[1]
PATH = ROOT / "pseudonote_extended" / "agent_runtime.py"
SPEC = importlib.util.spec_from_file_location("pseudonote_extended_agent_ledger", PATH)
runtime = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = runtime
SPEC.loader.exec_module(runtime)
ANALYZER = (ROOT / "pseudonote_extended" / "agentic_analyzer.py").read_text(encoding="utf-8")


class AgentEvidenceLedgerTests(unittest.TestCase):
    def test_observations_persist_in_session_snapshot(self):
        session = runtime.AgentSession(0x401000, "entry")
        session.record_observation("decompile", {"ea": "0x401000"}, "0x401020 calls InternetOpenW")
        restored = runtime.AgentSession.from_json(session.to_json())
        self.assertIn("InternetOpenW", restored.snapshot())

    def test_findings_require_a_marker_from_host_evidence(self):
        session = runtime.AgentSession(0x401000, "entry")
        session.record_observation("decompile", {"ea": "0x401000"}, "0x401020 calls InternetOpenW")
        self.assertTrue(session.evidence_supported(["0x401020 calls InternetOpenW"]))
        self.assertFalse(session.evidence_supported(["0x499999 injects a remote process"]))

    def test_semantically_repeated_findings_are_merged(self):
        session = runtime.AgentSession(0x401000, "entry")
        session.add_finding("Uses InternetOpenW", "medium", ["0x401020 InternetOpenW"])
        session.add_finding("Function calls InternetOpenW", "high", ["0x401020 calls InternetOpenW"])
        self.assertEqual(len(session.findings), 1)
        self.assertEqual(session.findings[0].confidence, "high")

    def test_controller_rejects_unsupported_findings_and_coverage(self):
        self.assertIn("self.session.evidence_supported", ANALYZER)
        self.assertIn("Finding rejected", ANALYZER)
        self.assertIn("has_evidence_for_ea", ANALYZER)

    def test_support_count_tracks_independent_observations(self):
        session = runtime.AgentSession(0x401000, "entry")
        session.record_observation("decompile", {"ea": "0x401000"}, "0x401020 calls InternetOpenW")
        self.assertEqual(session.evidence_support_count(["0x401020 InternetOpenW"]), 1)

    def test_final_report_rejects_markers_absent_from_host_evidence(self):
        session = runtime.AgentSession(0x401000, "entry")
        session.record_observation("decompile", {"ea": "0x401000"}, "0x401020 uses http://known.test/a")
        self.assertEqual(session.unsupported_report_markers("See 0x401020 and http://known.test/a"), [])
        self.assertIn("0x499999", session.unsupported_report_markers("See 0x499999"))


if __name__ == "__main__":
    unittest.main()
