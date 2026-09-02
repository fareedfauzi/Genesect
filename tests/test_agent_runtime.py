import importlib.util
import pathlib
import sys
import unittest


PATH = pathlib.Path(__file__).resolve().parents[1] / "pseudonote_extended" / "agent_runtime.py"
SPEC = importlib.util.spec_from_file_location("pseudonote_extended_agent_runtime", PATH)
runtime = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = runtime
SPEC.loader.exec_module(runtime)


class AgentRuntimeTests(unittest.TestCase):
    def test_strict_multi_tool_envelope(self):
        parsed, error = runtime.parse_agent_response(
            '{"action":"tools","calls":[{"tool":"decompile","args":{"ea":"0x401000"}}]}'
        )
        self.assertFalse(error)
        self.assertEqual(parsed["calls"][0]["tool"], "decompile")

    def test_prose_wrapped_tool_call_is_rejected(self):
        parsed, error = runtime.parse_agent_response(
            'I will inspect it {"action":"tools","calls":[{"tool":"decompile","args":{}}]}'
        )
        self.assertIsNone(parsed)
        self.assertIn("invalid JSON", error)

    def test_echoed_tool_data_tail_before_envelope_is_recovered(self):
        response = (
            '"name": "start"}]\n--- END DATA ---\n\n```json\n'
            '{"action":"tools","calls":[{"tool":"decompile","args":{"ea":"0x401000"}}]}\n```'
        )
        parsed, error = runtime.parse_agent_response(response)
        self.assertFalse(error)
        self.assertEqual(parsed["calls"][0]["tool"], "decompile")

    def test_call_batch_is_bounded(self):
        calls = [{"tool": "decompile", "args": {}}] * 5
        parsed, error = runtime.parse_agent_response("{\"action\":\"tools\",\"calls\":" + __import__('json').dumps(calls) + "}")
        self.assertIsNone(parsed)
        self.assertIn("at most", error)

    def test_findings_are_deduplicated_and_session_round_trips(self):
        session = runtime.AgentSession(0x401000, "entry")
        first = session.add_finding("Downloads payload", "high", ["0x401050 calls URLDownloadToFileW"])
        second = session.add_finding("Downloads payload", "high", ["0x401050 calls URLDownloadToFileW"])
        self.assertEqual(first.finding_id, second.finding_id)
        self.assertEqual(len(session.findings), 1)
        restored = runtime.AgentSession.from_json(session.to_json())
        self.assertEqual(restored.root_ea, 0x401000)
        self.assertEqual(restored.findings[0].confidence, "high")

    def test_repeated_call_is_detected(self):
        session = runtime.AgentSession(0x401000, "entry")
        self.assertEqual(session.record_call("decompile", {"ea": "0x401000"}), 1)
        self.assertEqual(session.record_call("decompile", {"ea": "0x401000"}), 2)

    def test_markdown_wrapped_network_iocs_are_supported_by_host_evidence(self):
        session = runtime.AgentSession(0x401080, "_main")
        session.record_observation(
            "decompile",
            {"ea": "0x401080"},
            'InternetOpenUrlW(hInternet, L"http://huskyhacks.dev", 0, 0, 0, 0);',
        )
        report = "Observed network indicator `http://huskyhacks.dev`, at `0x401080`."
        self.assertEqual([], session.unsupported_report_markers(report))

    def test_truly_unseen_network_ioc_remains_unsupported(self):
        session = runtime.AgentSession(0x401080, "_main")
        session.record_observation("decompile", {"ea": "0x401080"}, "return 0;")
        self.assertEqual(
            ["http://unseen.example"],
            session.unsupported_report_markers("IOC: `http://unseen.example`."),
        )

    def test_repeated_call_count_survives_recent_window_and_checkpoint(self):
        session = runtime.AgentSession(0x401000, "entry")
        args = {"ea": "0x401000"}
        session.record_call("decompile", args)
        for index in range(20):
            session.record_call("read_memory", {"ea": hex(0x402000 + index), "size": 4})
        restored = runtime.AgentSession.from_json(session.to_json())
        self.assertEqual(restored.record_call("decompile", args), 2)

    def test_function_completion_evidence_is_address_scoped(self):
        session = runtime.AgentSession(0x401000, "entry")
        session.record_observation("decompile", {"ea": "0x401000"}, "calls CreateFileW")
        session.record_observation("decompile", {"ea": "0x402000"}, "calls InternetOpenUrlW")
        self.assertTrue(session.evidence_supported_for_ea("0x401000", ["CreateFileW"]))
        self.assertFalse(session.evidence_supported_for_ea("0x401000", ["InternetOpenUrlW"]))

    def test_stale_function_cache_is_fully_invalidated(self):
        session = runtime.AgentSession(0x401000, "entry")
        args = {"ea": "0x401000"}
        session.record_call("decompile", args)
        session.record_observation("decompile", args, "return 1;")
        session.record_result("decompile", args, "return 1;")
        session.mark_examined(0x401000, "analyzed")
        session.invalidate_function_cache("0x401000")
        self.assertFalse(session.cached_result("decompile", args))
        self.assertFalse(session.has_success("decompile", "0x401000"))
        self.assertNotIn("0x401000", session.function_coverage)
        self.assertEqual(session.record_call("decompile", args), 1)

    def test_prompt_translates_plain_language_change_requests_to_tools(self):
        prompt = runtime.build_system_prompt(0x401000, "entry", {"rename_func": "Rename function"})
        self.assertIn("Rename the function", prompt)
        self.assertIn("matching tool call", prompt)
        self.assertIn("per-operation review", prompt)

    def test_prompt_requires_narrow_questions_to_finish_quickly(self):
        prompt = runtime.build_system_prompt(0x401000, "entry", {"search_strings": "Search strings"})
        self.assertIn("narrow analyst question", prompt)
        self.assertIn("answer immediately", prompt)

    def test_prompt_prioritizes_decompiler_and_avoids_redundant_disassembly(self):
        prompt = runtime.build_system_prompt(0x401000, "entry", {"decompile": "Pseudocode"})
        self.assertIn("decompilation as the primary source", prompt)
        self.assertIn("Begin function analysis with decompile", prompt)
        self.assertIn("Do not routinely request decompile and disassemble", prompt)

    def test_prompt_stops_when_request_is_answered(self):
        prompt = runtime.build_system_prompt(0x401000, "entry", {"decompile": "Pseudocode"})
        self.assertIn("Stop investigating as soon as", prompt)
        self.assertIn("specific remaining uncertainty", prompt)
