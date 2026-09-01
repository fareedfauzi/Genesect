import pathlib
import unittest


ROOT = pathlib.Path(__file__).parents[1]
HANDLERS = (ROOT / "pseudonote_extended" / "handlers.py").read_text(encoding="utf-8")
MAC_STYLE = (ROOT / "pseudonote_extended" / "ui" / "mac_workspace.py").read_text(encoding="utf-8")


class CallerSelectionUiTests(unittest.TestCase):
    def test_mac_checkbox_has_visible_checked_and_unchecked_states(self):
        self.assertIn("QCheckBox::indicator:checked", MAC_STYLE)
        self.assertIn("background: {t.accent}", MAC_STYLE)
        self.assertIn("border: 1px solid {t.border_strong}", MAC_STYLE)

    def test_caller_dialog_has_bulk_selection_and_count(self):
        start = HANDLERS.index("class CallerSelectionDialog")
        end = HANDLERS.index("def _get_caller_context_texts", start)
        section = HANDLERS[start:end]
        self.assertIn('QPushButton("Select All")', section)
        self.assertIn('QPushButton("Clear")', section)
        self.assertIn("def _set_all_checked", section)
        self.assertIn("def _update_selection_count", section)

    def test_caller_dialog_avoids_glitchy_workspace_skin_and_routes_buttons_directly(self):
        start = HANDLERS.index("class CallerSelectionDialog")
        end = HANDLERS.index("def _get_caller_context_texts", start)
        section = HANDLERS[start:end]
        self.assertNotIn("apply_mac_workspace(self)", section)
        self.assertIn("super(CallerSelectionDialog, self).__init__(None)", section)
        self.assertIn("self.ok_button.clicked.connect(self.accept)", section)
        self.assertIn("self.cancel_button.clicked.connect(self.reject)", section)
        self.assertIn("self.ok_button.setDefault(True)", section)

    def test_caller_modal_moves_off_hexrays_native_viewport(self):
        self.assertIn("from pseudonote_extended.ui.modal_safety import exec_modal", HANDLERS)
        self.assertIn('exec_modal(dialog, "PseudoNote Caller Context Host", target_func_ea)', HANDLERS)


if __name__ == "__main__":
    unittest.main()
