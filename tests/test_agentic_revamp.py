import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "pseudonote_extended" / "agentic_analyzer.py").read_text(encoding="utf-8")
POLICY = (ROOT / "pseudonote_extended" / "agent_policy.py").read_text(encoding="utf-8")


class AgenticRevampTests(unittest.TestCase):
    def test_primary_start_path_runs_mission_agent_not_bulk_renamer(self):
        start = SOURCE[SOURCE.index("def on_start_autopilot"):SOURCE.index("def _legacy_bulk_autopilot")]
        self.assertIn("AgentSession(self.address, self.function_name)", start)
        self.assertIn("self.run_loop()", start)
        self.assertNotIn("idautils.Functions()", start)

    def test_agent_uses_strict_envelopes_and_evidence_state(self):
        self.assertIn("parse_agent_response(response)", SOURCE)
        self.assertIn('tool_name == "record_finding"', SOURCE)
        self.assertIn('tool_name == "mark_examined"', SOURCE)
        self.assertIn("CURRENT INVESTIGATION STATE", SOURCE)
        self.assertIn("Repeated identical call blocked", SOURCE)

    def test_requests_are_bounded_and_cancellable(self):
        self.assertIn("self._active_request_id = AI_CLIENT.query_model_async", SOURCE)
        self.assertIn("AI_CLIENT.cancel_request(request_id)", SOURCE)
        self.assertIn('additional_options={"max_completion_tokens": 8192}', SOURCE)

    def test_read_tools_are_bounded_and_threat_intel_is_not_fabricated(self):
        self.assertIn("min(int(size or 32), 4096)", SOURCE)
        self.assertIn("min(int(count or 10), 256)", SOURCE)
        self.assertIn("does not fabricate threat-intelligence results", SOURCE)
        self.assertNotIn("0 detections (clean)", SOURCE)

    def test_new_session_tools_are_policy_classified(self):
        for tool in ("function_info", "disassemble", "record_finding", "mark_examined"):
            self.assertIn(f'"{tool}"', POLICY)


if __name__ == "__main__":
    unittest.main()
