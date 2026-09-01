"""Reusable review dialogs for AI-generated proposals."""

from pseudonote_extended.qt_compat import QtCore, QtWidgets
from pseudonote_extended.ui.components import PageHeader, ProfessionalTable
from pseudonote_extended.ui.theme import ThemeManager


def _accepted_value():
    accepted = getattr(QtWidgets.QDialog, "Accepted", None)
    if accepted is not None:
        return accepted
    dialog_code = getattr(QtWidgets.QDialog, "DialogCode", None)
    return getattr(dialog_code, "Accepted", 1)


def _open_safe_review_surface():
    """Move modal review dialogs off Hex-Rays' native viewport."""
    try:
        import idaapi
        import ida_kernwin
        source = ida_kernwin.get_current_widget()
        if source and idaapi.get_widget_type(source) == idaapi.BWN_PSEUDOCODE:
            safe = ida_kernwin.open_disasm_window("PseudoNote Review Host")
            if safe:
                ida_kernwin.activate_widget(safe, True)
                return source, safe
    except Exception:
        pass
    return None, None


def _restore_review_surface(source, safe):
    try:
        import ida_kernwin
        if source:
            ida_kernwin.activate_widget(source, True)
        if safe:
            close_later = getattr(ida_kernwin, "WCLS_CLOSE_LATER", 0)
            ida_kernwin.close_widget(safe, close_later)
    except Exception:
        pass


class ChangeReviewDialog(QtWidgets.QDialog):
    def __init__(self, title, original, proposed, apply_label="Apply", parent=None):
        super().__init__(None)
        self.setWindowTitle(title)
        self.resize(820, 480)
        layout = QtWidgets.QVBoxLayout(self)
        layout.setContentsMargins(20, 18, 20, 18)
        layout.addWidget(PageHeader(title, "Review the AI proposal before modifying the IDB."))
        split = QtWidgets.QSplitter(QtCore.Qt.Horizontal)
        split.addWidget(self._panel("Current", original))
        split.addWidget(self._panel("Proposed", proposed))
        layout.addWidget(split, 1)
        buttons = QtWidgets.QDialogButtonBox()
        apply_button = buttons.addButton(apply_label, QtWidgets.QDialogButtonBox.AcceptRole)
        apply_button.setProperty("pnVariant", "primary")
        buttons.addButton(QtWidgets.QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        self.theme = ThemeManager(self, "system")

    def _panel(self, title, text):
        box = QtWidgets.QGroupBox(title)
        layout = QtWidgets.QVBoxLayout(box)
        editor = QtWidgets.QPlainTextEdit()
        editor.setReadOnly(True)
        editor.setPlainText(str(text or ""))
        layout.addWidget(editor)
        return box


class MappingReviewDialog(QtWidgets.QDialog):
    def __init__(self, title, mapping, source_label="Current", proposal_label="Proposed", parent=None):
        super().__init__(None)
        self.mapping = dict(mapping)
        self.setWindowTitle(title)
        self.resize(760, 520)
        layout = QtWidgets.QVBoxLayout(self)
        layout.setContentsMargins(20, 18, 20, 18)
        layout.addWidget(PageHeader(title, "Select the proposals to apply. Unchecked rows leave IDA unchanged."))
        self.table = ProfessionalTable(len(self.mapping), 3)
        self.table.setSortingEnabled(False)
        self.table.setHorizontalHeaderLabels(["Apply", source_label, proposal_label])
        for row, (source, proposal) in enumerate(self.mapping.items()):
            checked = QtWidgets.QTableWidgetItem()
            checked.setFlags(checked.flags() | QtCore.Qt.ItemIsUserCheckable)
            checked.setCheckState(QtCore.Qt.Checked)
            self.table.setItem(row, 0, checked)
            self.table.setItem(row, 1, QtWidgets.QTableWidgetItem(str(source)))
            self.table.setItem(row, 2, QtWidgets.QTableWidgetItem(str(proposal)))
        self.table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.table, 1)
        buttons = QtWidgets.QDialogButtonBox()
        self.apply_button = buttons.addButton("Apply Selected", QtWidgets.QDialogButtonBox.AcceptRole)
        self.apply_button.setProperty("pnVariant", "primary")
        buttons.addButton(QtWidgets.QDialogButtonBox.Cancel)
        self.apply_button.clicked.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        self.table.itemChanged.connect(self._update_apply_enabled)
        self._update_apply_enabled()
        self.theme = ThemeManager(self, "system")

    def _update_apply_enabled(self, *_args):
        self.apply_button.setEnabled(bool(self.selected_mapping()))

    def selected_mapping(self):
        selected = {}
        for row in range(self.table.rowCount()):
            if self.table.item(row, 0).checkState() == QtCore.Qt.Checked:
                selected[self.table.item(row, 1).text()] = self.table.item(row, 2).text()
        return selected


def confirm_change(title, original, proposed, apply_label="Apply", parent=None):
    source, safe = _open_safe_review_surface()
    try:
        dialog = ChangeReviewDialog(title, original, proposed, apply_label, parent)
        return dialog.exec_() == _accepted_value()
    finally:
        _restore_review_surface(source, safe)


def select_mapping(title, mapping, source_label="Current", proposal_label="Proposed", parent=None):
    source, safe = _open_safe_review_surface()
    try:
        dialog = MappingReviewDialog(title, mapping, source_label, proposal_label, parent)
        if dialog.exec_() != _accepted_value():
            return None
        return dialog.selected_mapping()
    finally:
        _restore_review_surface(source, safe)
