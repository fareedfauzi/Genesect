import pathlib
import unittest


SOURCE = (pathlib.Path(__file__).parents[1] / "pseudonote_extended" / "handlers.py").read_text(encoding="utf-8")
SECTION = SOURCE[SOURCE.index("# Function Copy Mapper / Copy Function Tree"):SOURCE.index("class CopyGlobalXrefTreeHandler")]


class CopyTreeWorkflowTests(unittest.TestCase):
    def test_both_tree_walks_enforce_a_node_limit(self):
        self.assertIn("MAX_COPY_TREE_NODES = 5000", SECTION)
        self.assertGreaterEqual(SECTION.count("self.rendered_nodes >= MAX_COPY_TREE_NODES"), 3)

    def test_filter_preserves_ancestors_of_matching_rows(self):
        self.assertIn("descendant_match = apply(item.child(index)) or descendant_match", SECTION)

    def test_double_click_navigates_to_function(self):
        self.assertIn("itemDoubleClicked.connect(self.on_item_double_clicked)", SECTION)
        self.assertIn("ida_kernwin.jumpto(int(ea))", SECTION)

    def test_mapping_failures_are_reported(self):
        self.assertIn("Function tree mapping failed", SECTION)
        self.assertIn("Global xref tree mapping failed", SECTION)

    def test_invalid_targets_show_user_facing_warning_dialogs(self):
        self.assertIn("Place the cursor inside a function before opening Copy Function Tree.", SOURCE)
        self.assertIn("Could not determine a global variable address.", SOURCE)
        self.assertGreaterEqual(SOURCE.count("ida_kernwin.warning("), 2)

    def test_dialog_releases_retained_reference(self):
        self.assertIn("_copy_tree_dialogs.remove(self)", SECTION)

    def test_tree_dialogs_are_standalone_taskbar_windows(self):
        self.assertIn("super(FunctionTreeDialog, self).__init__(parent)", SOURCE)
        self.assertNotIn("parent or QtWidgets.QApplication.activeWindow()", SOURCE)
        self.assertIn("| QtCore.Qt.Window", SECTION)
        self.assertIn("| QtCore.Qt.WindowMinimizeButtonHint", SECTION)
        self.assertIn("dlg = FunctionTreeDialog(f.start_ea, parent=None)", SOURCE)
        self.assertIn("dlg = GlobalXrefTreeDialog(obj_ea, parent=None)", SOURCE)

    def test_tree_handlers_do_not_use_dock_wrappers(self):
        function_handler = SOURCE[
            SOURCE.index("class CopyFunctionTreeHandler"):
            SOURCE.index("class GlobalXrefTreeDialog")
        ]
        global_handler = SOURCE[SOURCE.index("class CopyGlobalXrefTreeHandler"):]
        self.assertIn("dlg.show()", function_handler)
        self.assertIn("dlg.show()", global_handler)
        self.assertNotIn("PluginFormWrapper", function_handler)
        self.assertNotIn("PluginFormWrapper", global_handler)

    def test_decompile_error_is_preserved_in_clipboard_output(self):
        self.assertIn('code = f"[Decompilation failed: {exc}]"', SECTION)

    def test_clipboard_output_is_bounded(self):
        self.assertIn("MAX_COPY_TREE_CLIPBOARD_CHARS = 10_000_000", SECTION)
        self.assertIn("Output truncated at the 10,000,000-character safety limit", SECTION)


if __name__ == "__main__":
    unittest.main()
