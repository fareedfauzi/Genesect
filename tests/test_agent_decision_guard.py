import importlib.util
import pathlib
import sys
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
PATH = ROOT / "pseudonote_extended" / "agent_runtime.py"
SPEC = importlib.util.spec_from_file_location("pseudonote_extended_agent_decisions", PATH)
runtime = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = runtime
SPEC.loader.exec_module(runtime)
ANALYZER = (ROOT / "pseudonote_extended" / "agentic_analyzer.py").read_text(encoding="utf-8")


class AgentDecisionGuardTests(unittest.TestCase):
    def test_unknown_tools_and_bad_arguments_are_rejected(self):
        catalog = {"decompile": "read", "rename_vars": "write"}
        call, error = runtime.normalize_tool_call("shell", {}, 0x401000, catalog)
        self.assertIsNone(call)
        self.assertIn("Unknown", error)
        call, error = runtime.normalize_tool_call("rename_vars", {"renames": []}, 0x401000, catalog)
        self.assertIsNone(call)
        self.assertIn("renames", error)

    def test_addresses_and_bounds_are_canonicalized(self):
        catalog = {"disassemble": "read"}
        call, error = runtime.normalize_tool_call(
            "disassemble", {"ea": 0x401000, "max_instructions": 999999}, 0, catalog,
        )
        self.assertFalse(error)
        self.assertEqual(call["args"]["ea"], "0x401000")
        self.assertEqual(call["args"]["max_instructions"], 2000)

    def test_no_progress_forces_a_bounded_finish(self):
        session = runtime.AgentSession(0x401000, "entry")
        session.begin_round()
        self.assertFalse(session.record_result("decompile", {"ea": "0x401000"}, "Error: failed"))
        session.finish_round()
        self.assertFalse(session.should_finalize())
        session.begin_round()
        self.assertFalse(session.record_result("decompile", {"ea": "0x401000"}, "Skipped: duplicate"))
        session.finish_round()
        self.assertTrue(session.should_finalize())
        session.begin_round()
        self.assertTrue(session.record_result("disassemble", {"ea": "0x401000"}, "0x401000: ret"))
        session.finish_round()
        self.assertFalse(session.should_finalize())

    def test_successful_results_can_be_replayed_from_host_cache(self):
        session = runtime.AgentSession(0x401000, "entry")
        args = {"ea": "0x401000"}
        session.record_observation("decompile", args, "int main(void) { return 0; }")
        self.assertIn("int main", session.cached_result("decompile", args))

    def test_successful_capabilities_survive_checkpoints(self):
        session = runtime.AgentSession(0x401000, "entry")
        session.record_result("decompile", {"ea": "0x401000"}, "int f(){return 0;}")
        restored = runtime.AgentSession.from_json(session.to_json())
        self.assertTrue(restored.has_success("decompile", "0x401000"))

    def test_controller_validates_every_agent_call_and_gives_recovery(self):
        self.assertIn("normalize_tool_call(", ANALYZER)
        self.assertIn("recovery_guidance(tool_name, result)", ANALYZER)
        self.assertIn("self.session.should_finalize()", ANALYZER)
        self.assertIn("Pseudocode already succeeded", ANALYZER)

    def test_multifunction_rename_has_host_owned_targets_and_report_guards(self):
        self.assertIn('"rename_descendants"', ANALYZER)
        self.assertIn("_collect_descendant_functions(self.address)", ANALYZER)
        self.assertIn("Candidate targets:", ANALYZER)
        self.assertIn("apply evidence-backed proposals", ANALYZER)
        self.assertIn("_final_report_contradictions", ANALYZER)
        self.assertIn("decompilation succeeded, so it was not blocked", ANALYZER)

    def test_prefix_rename_is_host_enumerated_and_completion_is_verified(self):
        self.assertIn("def _requested_rename_prefix", ANALYZER)
        self.assertIn("def _collect_prefixed_functions", ANALYZER)
        self.assertIn('"rename_prefix"', ANALYZER)
        self.assertIn("no functions with the prefix", ANALYZER)
        self.assertIn("targets lack function-level analysis", ANALYZER)
        self.assertIn("the report cites list_functions()", ANALYZER)
        self.assertIn("PREMATURE FINAL REPORT", ANALYZER)
        self.assertIn("Return action=tools", ANALYZER)

    def test_ida_changes_control_is_a_visible_toggle_switch(self):
        self.assertIn("StatusBadge, ToggleSwitch", ANALYZER)
        self.assertIn('ToggleSwitch("Enable IDA changes")', ANALYZER)
        active_ui = ANALYZER[ANALYZER.index("def _setup_professional_ui"):ANALYZER.index("def _apply_agentic_visual_style")]
        self.assertNotIn('QCheckBox("Enable IDA changes")', active_ui)

    def test_all_safe_specialized_tools_are_visible_to_planning(self):
        for tool in ("get_vtable_ptrs", "create_apply_struct"):
            self.assertIn(f'"{tool}":', ANALYZER)
        catalog = ANALYZER[ANALYZER.index("AGENT_TOOL_CATALOG ="):ANALYZER.index("FUNCTION_SCOPED_AGENT_TOOLS")]
        self.assertNotIn('"query_threat_intel"', catalog)

    def test_prompt_requires_purpose_and_failure_fallback(self):
        prompt = runtime.build_system_prompt(0x401000, "entry", {"decompile": "read"})
        self.assertIn("named information gap", prompt)
        self.assertIn("Never retry a failed tool unchanged", prompt)
        self.assertIn("disassemble plus basic_blocks", prompt)


if __name__ == "__main__":
    unittest.main()
