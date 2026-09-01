import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "pseudonote_extended" / "var_renamer.py").read_text(encoding="utf-8")


class VariableRenameApplyContractTests(unittest.TestCase):
    def test_bulk_apply_uses_persistent_hexrays_local_variable_api(self):
        self.assertIn("locate_lvar(locator, fe, old_name)", SOURCE)
        self.assertIn("modify_user_lvar_info(", SOURCE)
        self.assertIn("ida_hexrays.MLI_NAME", SOURCE)
        self.assertIn("info.ll = locator", SOURCE)
        self.assertIn("info.name = new_name", SOURCE)

    def test_public_rename_api_is_attempted_before_low_level_fallback(self):
        persistent = SOURCE.index("modify_user_lvar_info(")
        public_api = SOURCE.index("ida_hexrays.rename_lvar(")
        self.assertLess(public_api, persistent)

    def test_successes_are_verified_in_a_fresh_decompilation(self):
        self.assertIn("ida_hexrays.mark_cfunc_dirty(fe, False)", SOURCE)
        self.assertIn("Rename was not present after fresh decompilation", SOURCE)

    def test_apply_failure_exposes_the_hexrays_reason(self):
        self.assertIn("def var_rename_error_summary", SOURCE)
        self.assertIn('Apply failed: {var_rename_error_summary(', SOURCE)
        self.assertIn("last_error", SOURCE)

    def test_collisions_are_resolved_before_writing(self):
        self.assertIn("used_names = set(name_to_lvar)", SOURCE)
        self.assertIn("name not in used_names", SOURCE)

    def test_ui_distinguishes_applied_from_pending_counts(self):
        self.assertIn("Renames (Applied / Pending)", SOURCE)
        self.assertIn("rename_result_counts(f.applied_renames)", SOURCE)

    def test_ai_wrappers_and_non_scalar_values_are_normalized(self):
        self.assertIn("def normalize_var_suggestions", SOURCE)
        self.assertIn('(\"renames\", \"variable_renames\", \"var_renames\", \"suggestions\")', SOURCE)
        self.assertIn("not isinstance(new_name, str)", SOURCE)

    def test_function_resolution_occurs_on_ida_main_thread(self):
        section = SOURCE[
            SOURCE.index("def apply_var_renames"):
            SOURCE.index("def parse_var_response")
        ]
        callback = section[
            section.index("    def _resolve_function"):
            section.index("        idaapi.execute_sync(_resolve_function")
        ]
        self.assertIn("idaapi.get_func(ea)", callback)
        prefix = section[:section.index("    def _resolve_function")]
        self.assertNotIn("idaapi.get_func(ea)", prefix)


if __name__ == "__main__":
    unittest.main()
