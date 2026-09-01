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

    def test_dialog_releases_retained_reference(self):
        self.assertIn("_copy_tree_dialogs.remove(self)", SECTION)

    def test_decompile_error_is_preserved_in_clipboard_output(self):
        self.assertIn('code = f"[Decompilation failed: {exc}]"', SECTION)

    def test_clipboard_output_is_bounded(self):
        self.assertIn("MAX_COPY_TREE_CLIPBOARD_CHARS = 10_000_000", SECTION)
        self.assertIn("Output truncated at the 10,000,000-character safety limit", SECTION)


if __name__ == "__main__":
    unittest.main()
