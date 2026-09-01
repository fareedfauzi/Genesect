import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "pseudonote_extended" / "chat_chain.py").read_text(encoding="utf-8-sig")


class ChatChainFunctionSelectorTests(unittest.TestCase):
    def test_entry_is_an_editable_searchable_dropdown(self):
        self.assertIn("self.entry_combo = QtWidgets.QComboBox()", SOURCE)
        self.assertIn("self.entry_combo.setEditable(True)", SOURCE)
        self.assertIn("Search function name or address...", SOURCE)
        self.assertIn("completer.setCaseSensitivity(QtCore.Qt.CaseInsensitive)", SOURCE)
        self.assertIn("completer.setFilterMode(match_contains)", SOURCE)

    def test_qt_compat_flattens_combo_and_completer_enums(self):
        compat = (ROOT / "pseudonote_extended" / "qt_compat.py").read_text(encoding="utf-8-sig")
        self.assertIn('(QtWidgets.QComboBox, ("InsertPolicy", "SizeAdjustPolicy"))', compat)
        self.assertIn('(QtWidgets.QCompleter, ("CompletionMode", "ModelSorting"))', compat)

    def test_selector_contains_all_idb_functions_with_addresses(self):
        self.assertIn("for ea in idautils.Functions():", SOURCE)
        self.assertIn('self.entry_combo.addItem(f"0x{ea:X}  -  {name}", ea)', SOURCE)

    def test_selection_switches_root_and_resets_old_graph_context(self):
        self.assertIn("def _switch_entry_function(self, ea):", SOURCE)
        self.assertIn("self.graph = {}", SOURCE)
        self.assertIn("self._context_signature = ()", SOURCE)
        self.assertIn("self.func_table.setRowCount(0)", SOURCE)
        self.assertIn("self._clear_chat_widgets()", SOURCE)

    def test_current_function_shortcut_uses_same_switch_path(self):
        self.assertIn("self._switch_entry_function(f.start_ea)", SOURCE)


if __name__ == "__main__":
    unittest.main()
