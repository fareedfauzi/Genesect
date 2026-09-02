import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "pseudonote_extended" / "argument_hints.py").read_text(encoding="utf-8-sig")
PLUGIN = (ROOT / "pseudonote_extended" / "plugin.py").read_text(encoding="utf-8-sig")
CONFIG = (ROOT / "pseudonote_extended" / "config.py").read_text(encoding="utf-8-sig")
MENU = (ROOT / "pseudonote_extended" / "ui" / "context_menu.py").read_text(encoding="utf-8-sig")


class ArgumentHintTests(unittest.TestCase):
    def test_action_has_requested_name_and_pseudocode_menu_entry(self):
        self.assertIn('"Display function argument names"', PLUGIN)
        self.assertIn('"pseudonote_extended:argument_name_hints"', MENU)
        self.assertIn('"Utilities/Navigation && Views"', MENU)

    def test_hexrays_hook_uses_type_information_and_colored_inlays(self):
        self.assertIn("class ArgumentNameHintHooks(ida_hexrays.Hexrays_Hooks)", SOURCE)
        self.assertIn("def func_printed(self, cfunc):", SOURCE)
        self.assertIn("get_func_details", SOURCE)
        self.assertIn("idaapi.COLSTR", SOURCE)
        self.assertIn("idaapi.SCOLOR_AUTOCMT", SOURCE)

    def test_windows_api_fallback_is_lazy_and_module_scoped(self):
        self.assertIn('"API", "Windows"', SOURCE)
        self.assertIn("ET.parse(path)", SOURCE)
        self.assertIn('api.get("BothCharset")', SOURCE)
        self.assertIn('api.findall("Param")', SOURCE)
        self.assertIn("get_import_module_qty", SOURCE)
        self.assertNotIn("os.walk", SOURCE)

    def test_setting_is_opt_in_persistent_and_checkable(self):
        self.assertIn("self.argument_name_hints_enabled = False", CONFIG)
        self.assertIn('"ARGUMENT_NAME_HINTS_ENABLED"', CONFIG)
        self.assertIn("fallback=False", CONFIG)
        self.assertIn("ADF_CHECKABLE", PLUGIN)

    def test_hook_lifecycle_and_refresh_do_not_assume_named_views(self):
        self.assertIn("create_argument_name_hint_hooks()", PLUGIN)
        self.assertIn("destroy_argument_name_hint_hooks()", PLUGIN)
        self.assertIn("get_widget_qty", SOURCE)
        self.assertIn("getn_widget", SOURCE)
        self.assertNotIn('"Pseudocode-A"', SOURCE)

    def test_repeated_rendering_does_not_duplicate_same_tagged_hint(self):
        self.assertIn("if tagged_hint in simple_line.line:", SOURCE)


if __name__ == "__main__":
    unittest.main()
