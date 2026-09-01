import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SELECTOR = (ROOT / "pseudonote_extended" / "ui" / "function_selector.py").read_text(encoding="utf-8-sig")
CHAIN = (ROOT / "pseudonote_extended" / "chat_chain.py").read_text(encoding="utf-8-sig")
SUMMARIZER = (ROOT / "pseudonote_extended" / "summarizer.py").read_text(encoding="utf-8-sig")
DEEP = (ROOT / "pseudonote_extended" / "deep_analyzer.py").read_text(encoding="utf-8-sig")


class SharedFunctionSelectorTests(unittest.TestCase):
    def test_shared_selector_lists_and_searches_all_functions(self):
        self.assertIn("class SearchableFunctionSelector", SELECTOR)
        self.assertIn("for ea in idautils.Functions():", SELECTOR)
        self.assertIn("Search function name or address...", SELECTOR)
        self.assertIn("MatchContains", SELECTOR)
        self.assertIn("idc.get_name_ea_simple", SELECTOR)
        self.assertIn("int(token, 16)", SELECTOR)

    def test_summarizer_and_deep_analyzer_use_shared_selector(self):
        for source in (SUMMARIZER, DEEP):
            self.assertIn("SearchableFunctionSelector", source)
            self.assertIn("functionSelected.connect(self.on_entry_function_selected)", source)
            self.assertIn("self.entry_selector.set_function(self.entry_ea)", source)
            self.assertNotIn("self.entry_edit = QLineEdit()", source)

    def test_chain_chat_also_exposes_searchable_all_function_dropdown(self):
        self.assertIn("self.entry_combo = QtWidgets.QComboBox()", CHAIN)
        self.assertIn("for ea in idautils.Functions():", CHAIN)
        self.assertIn("Search function name or address...", CHAIN)

    def test_current_function_shortcuts_remain_available(self):
        self.assertIn('QPushButton("Current Func")', CHAIN)
        self.assertIn('QPushButton("Load Current Function")', SUMMARIZER)
        self.assertIn('QPushButton("Load Current Function")', DEEP)


if __name__ == "__main__":
    unittest.main()
