import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "pseudonote_extended" / "ui" / "proposals.py").read_text(encoding="utf-8")


class ProposalReviewDialogTests(unittest.TestCase):
    def test_apply_selected_is_direct_and_selection_aware(self):
        self.assertIn("self.apply_button.clicked.connect(self.accept)", SOURCE)
        self.assertIn("self.table.itemChanged.connect(self._update_apply_enabled)", SOURCE)
        self.assertIn("self.apply_button.setEnabled(bool(self.selected_mapping()))", SOURCE)

    def test_qt5_and_qt6_accept_values_are_lazy_and_safe(self):
        self.assertIn('accepted = getattr(QtWidgets.QDialog, "Accepted", None)', SOURCE)
        self.assertIn('dialog_code = getattr(QtWidgets.QDialog, "DialogCode", None)', SOURCE)
        self.assertNotIn('getattr(QtWidgets.QDialog, "Accepted", QtWidgets.QDialog.DialogCode.Accepted)', SOURCE)

    def test_pseudocode_reviews_use_a_safe_surface(self):
        self.assertIn("def _open_safe_review_surface", SOURCE)
        self.assertIn('open_disasm_window("PseudoNote Review Host")', SOURCE)
        self.assertIn("_restore_review_surface(source, safe)", SOURCE)


if __name__ == "__main__":
    unittest.main()
