"""Reusable searchable selector for choosing an IDB function."""

import idaapi
import ida_funcs
import idautils
import idc

from pseudonote_extended.qt_compat import QtCore, QtWidgets, Signal


class SearchableFunctionSelector(QtWidgets.QComboBox):
    functionSelected = Signal(object)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setEditable(True)
        self.setInsertPolicy(QtWidgets.QComboBox.NoInsert)
        self.setMaxVisibleItems(24)
        self.setToolTip("Select or search for a function by name or address")
        self.lineEdit().setPlaceholderText("Search function name or address...")
        self.refresh_functions()
        completer = self.completer()
        if completer:
            completer.setCaseSensitivity(QtCore.Qt.CaseInsensitive)
            mode = getattr(QtCore.Qt, "MatchContains", None)
            if mode is None and hasattr(QtCore.Qt, "MatchFlag"):
                mode = QtCore.Qt.MatchFlag.MatchContains
            if mode is not None and hasattr(completer, "setFilterMode"):
                completer.setFilterMode(mode)
            completer.setCompletionMode(QtWidgets.QCompleter.PopupCompletion)
        self.activated.connect(self._on_index_activated)
        self.lineEdit().returnPressed.connect(self._on_text_submitted)

    def refresh_functions(self):
        current_ea = self.current_function_ea()
        functions = []
        for ea in idautils.Functions():
            name = idc.get_func_name(ea) or f"sub_{ea:X}"
            functions.append((int(ea), str(name)))
        functions.sort(key=lambda item: (item[1].lower(), item[0]))
        self.blockSignals(True)
        self.clear()
        for ea, name in functions:
            self.addItem(f"0x{ea:X}  -  {name}", ea)
        self.blockSignals(False)
        if current_ea not in (None, idaapi.BADADDR):
            self.set_function(current_ea)

    def current_function_ea(self):
        try:
            data = self.currentData()
            return int(data) if data is not None else None
        except (TypeError, ValueError):
            return None

    def set_function(self, ea):
        func = ida_funcs.get_func(int(ea))
        if not func:
            return False
        index = self.findData(int(func.start_ea))
        if index < 0:
            name = idc.get_func_name(func.start_ea) or f"sub_{func.start_ea:X}"
            self.addItem(f"0x{func.start_ea:X}  -  {name}", int(func.start_ea))
            index = self.count() - 1
        self.blockSignals(True)
        self.setCurrentIndex(index)
        self.blockSignals(False)
        return True

    def _emit_ea(self, ea):
        func = ida_funcs.get_func(int(ea))
        if not func:
            return False
        self.set_function(func.start_ea)
        self.functionSelected.emit(int(func.start_ea))
        return True

    def _on_index_activated(self, index):
        ea = self.itemData(int(index))
        if ea is not None:
            self._emit_ea(int(ea))

    def _on_text_submitted(self):
        text = self.currentText().strip()
        index = self.findText(text, getattr(QtCore.Qt, "MatchFixedString", 0))
        if index >= 0:
            self._on_index_activated(index)
            return
        token = text.split("-", 1)[0].strip()
        try:
            ea = int(token, 16) if token.lower().startswith("0x") else idc.get_name_ea_simple(text)
        except Exception:
            ea = idaapi.BADADDR
        if ea not in (None, idaapi.BADADDR):
            self._emit_ea(int(ea))
