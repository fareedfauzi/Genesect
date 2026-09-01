# -*- coding: utf-8 -*-
"""Recover dynamic imports, hashed resolution, export walking, syscalls, and custom loaders."""
import csv
import io
import os
import re

import idaapi
import ida_funcs
import ida_kernwin
import ida_ua
import idautils
import idc

from pseudonote_extended.qt_compat import QtCore, QtWidgets
from pseudonote_extended.ui.components import PageHeader, Card
from pseudonote_extended.ui.mac_workspace import apply_mac_workspace


_explorer = None
_MAX_RESULTS = 200000
_RESOLVER_API = re.compile(r"^(?:__imp_)?(?:GetProcAddress|LdrGetProcedureAddress|LdrGetProcedureAddressEx|dlsym|dlvsym|NSLookupSymbolInImage|CFBundleGetFunctionPointerForName)$", re.I)
_LOADER_API = re.compile(r"^(?:__imp_)?(?:LoadLibrary[AW]?|LoadLibraryEx[AW]?|LdrLoadDll|dlopen|NSCreateObjectFileImageFromMemory|CFBundleCreate)$", re.I)
_MEMORY_API = re.compile(r"^(?:__imp_)?(?:VirtualAlloc|VirtualProtect|NtAllocateVirtualMemory|NtProtectVirtualMemory|mmap|mprotect)$", re.I)
_API_NAME = re.compile(r"^(?:[A-Z][A-Za-z0-9_]{2,}|Nt[A-Z]\w+|Zw[A-Z]\w+|[a-z][a-z0-9_]{2,})$")
_DLL_NAME = re.compile(r"(?:\.dll|\.so(?:\.\d+)*|\.dylib)$", re.I)
_SYSCALL_MNEMONICS = {"syscall", "sysenter", "svc", "swi", "ecall"}
_HASH_MNEMONICS = {"rol", "ror", "xor", "imul", "mul", "add", "sub", "shl", "shr"}


def _hex(value):
    return "0x%X" % int(value)


def _func_start(ea):
    func = ida_funcs.get_func(ea)
    return int(func.start_ea) if func else idaapi.BADADDR


def _func_name(ea):
    start = _func_start(ea)
    return idc.get_func_name(start) or ("sub_%X" % start if start != idaapi.BADADDR else "")


def _row(category, ea, value="", confidence="high", evidence="", detail=""):
    return {
        "category": category, "ea": int(ea), "function": _func_name(ea),
        "value": str(value), "confidence": confidence, "evidence": evidence, "detail": detail,
    }


def _api_calls(pattern):
    for api_ea, api_name in idautils.Names():
        if not pattern.search(api_name or ""):
            continue
        for xref in idautils.XrefsTo(api_ea, 0):
            if xref.type in (getattr(idaapi, "fl_CF", 16), getattr(idaapi, "fl_CN", 17)) and _func_start(xref.frm) != idaapi.BADADDR:
                yield int(xref.frm), api_name


def _strings_by_function():
    result = {}
    for item in idautils.Strings():
        text = str(item).strip()
        for xref in idautils.XrefsTo(int(item.ea), 0):
            owner = _func_start(xref.frm)
            if owner != idaapi.BADADDR:
                result.setdefault(owner, []).append((int(xref.frm), int(item.ea), text))
    return result


def scan_direct_resolvers(strings_by_function):
    rows, resolver_functions = [], set()
    for call, api_name in _api_calls(_RESOLVER_API):
        owner = _func_start(call)
        resolver_functions.add(owner)
        rows.append(_row("Resolver API", call, api_name, "high", "direct call to runtime symbol resolver", idc.generate_disasm_line(call, 0) or ""))
        for site, string_ea, text in strings_by_function.get(owner, []):
            if _API_NAME.fullmatch(text) and not _DLL_NAME.search(text):
                rows.append(_row("Resolved API name", site, text, "high", "API-like string referenced by function calling runtime resolver", "string at %s; resolver call at %s" % (_hex(string_ea), _hex(call))))
    return rows, resolver_functions


def scan_dynamic_libraries(strings_by_function):
    rows, loader_functions = [], set()
    for call, api_name in _api_calls(_LOADER_API):
        owner = _func_start(call)
        loader_functions.add(owner)
        rows.append(_row("Dynamic library loader", call, api_name, "high", "direct runtime module-loading call", idc.generate_disasm_line(call, 0) or ""))
        for site, string_ea, text in strings_by_function.get(owner, []):
            if _DLL_NAME.search(text):
                rows.append(_row("Dynamically loaded module", site, text, "high", "library string referenced by runtime loader function", "string at %s; loader call at %s" % (_hex(string_ea), _hex(call))))
    return rows, loader_functions


def _function_features(func_ea):
    immediates, mnemonics, indirect, comparisons = set(), [], [], []
    for ea in idautils.FuncItems(func_ea):
        mnemonic = (idc.print_insn_mnem(ea) or "").lower()
        mnemonics.append((ea, mnemonic))
        if mnemonic in ("cmp", "test", "cmn"):
            comparisons.append(ea)
        if mnemonic in ("call", "jmp", "br", "blr") and idc.get_operand_type(ea, 0) in (getattr(ida_ua, "o_reg", 1), getattr(ida_ua, "o_phrase", 3), getattr(ida_ua, "o_displ", 4)):
            indirect.append(ea)
        for operand in range(3):
            if idc.get_operand_type(ea, operand) == getattr(ida_ua, "o_imm", 5):
                immediates.add(int(idc.get_operand_value(ea, operand)) & 0xFFFFFFFFFFFFFFFF)
    return immediates, mnemonics, indirect, comparisons


def scan_hash_resolvers(resolver_functions):
    rows = []
    for func_ea in idautils.Functions():
        immediates, mnemonics, indirect, comparisons = _function_features(func_ea)
        transforms = [(ea, mnemonic) for ea, mnemonic in mnemonics if mnemonic in _HASH_MNEMONICS]
        large_constants = sorted(value for value in immediates if 0x10000 <= value <= 0xFFFFFFFF and value not in (0xFFFFFFFF,))
        anchored = func_ea in resolver_functions
        if not comparisons or len(transforms) < 3 or not large_constants:
            continue
        confidence = "medium" if anchored else "heuristic"
        detail = "Transforms: %s\nCompared constants: %s" % (
            ", ".join("%s@%s" % (mnemonic, _hex(ea)) for ea, mnemonic in transforms[:24]),
            ", ".join(_hex(value) for value in large_constants[:32]))
        rows.append(_row("API hash resolver candidate", func_ea, "%d hash-like constants" % len(large_constants), confidence, "transform loop and constant comparisons%s" % (" in resolver function" if anchored else ""), detail))
    return rows


def scan_export_walkers():
    rows, functions = [], set()
    for func_ea in idautils.Functions():
        immediates, mnemonics, indirect, comparisons = _function_features(func_ea)
        # DOS e_lfanew + PE export-directory offsets (PE32 0x78 / PE32+ 0x88).
        has_pe_offsets = 0x3C in immediates and (0x78 in immediates or 0x88 in immediates)
        loops = sum(1 for _ea, mnemonic in mnemonics if mnemonic in ("loop", "jmp", "jnz", "jne", "b", "cbnz"))
        if not has_pe_offsets or not comparisons or loops < 1:
            continue
        functions.add(func_ea)
        confidence = "medium" if indirect else "heuristic"
        detail = "PE offsets: %s; comparisons: %d; indirect transfers: %d" % (", ".join(_hex(value) for value in sorted(immediates & {0x3C, 0x78, 0x88})), len(comparisons), len(indirect))
        rows.append(_row("PE export walker candidate", func_ea, "manual export traversal", confidence, "e_lfanew and export-directory offsets with loop/comparison behavior", detail))
    return rows, functions


def _syscall_number(ea, func_ea):
    cursor = int(ea)
    for _index in range(12):
        cursor = idc.prev_head(cursor)
        if cursor == idaapi.BADADDR or _func_start(cursor) != func_ea:
            break
        mnemonic = (idc.print_insn_mnem(cursor) or "").lower()
        destination = (idc.print_operand(cursor, 0) or "").lower()
        if mnemonic in ("mov", "movz", "li") and destination in ("eax", "rax", "w8", "x8", "a7", "r7") and idc.get_operand_type(cursor, 1) == getattr(ida_ua, "o_imm", 5):
            return int(idc.get_operand_value(cursor, 1)), cursor
    return None, idaapi.BADADDR


def scan_syscall_tables():
    rows = []
    by_function = {}
    for func_ea in idautils.Functions():
        for ea in idautils.FuncItems(func_ea):
            mnemonic = (idc.print_insn_mnem(ea) or "").lower()
            if mnemonic not in _SYSCALL_MNEMONICS:
                continue
            number, setup = _syscall_number(ea, func_ea)
            rows.append(_row("Direct syscall stub", ea, _hex(number) if number is not None else "number unresolved", "high" if number is not None else "medium", "direct %s instruction%s" % (mnemonic, " with nearby service number" if number is not None else ""), "number setup at %s" % _hex(setup) if setup != idaapi.BADADDR else idc.generate_disasm_line(ea, 0) or ""))
            by_function.setdefault(func_ea, []).append(number)
    for func_ea, numbers in by_function.items():
        resolved = sorted(set(number for number in numbers if number is not None))
        if len(resolved) >= 2:
            rows.append(_row("Syscall table / dispatcher", func_ea, ", ".join(_hex(number) for number in resolved), "medium", "multiple direct service numbers in one function", "%d syscall sites" % len(numbers)))
    return rows


def scan_custom_loaders(loader_functions, export_functions):
    rows = []
    memory_functions = set(_func_start(site) for site, _name in _api_calls(_MEMORY_API))
    for func_ea in sorted(memory_functions | loader_functions | export_functions):
        immediates, mnemonics, indirect, comparisons = _function_features(func_ea)
        pe_offsets = bool(0x3C in immediates and (0x78 in immediates or 0x88 in immediates))
        anchored = func_ea in memory_functions and (func_ea in export_functions or pe_offsets)
        if not anchored or not indirect:
            continue
        rows.append(_row("Custom loader candidate", func_ea, "%d indirect execution transition(s)" % len(indirect), "medium", "memory allocation/protection plus PE traversal and indirect execution", "transitions: %s" % ", ".join(_hex(ea) for ea in indirect[:24])))
    return rows


def explore_dynamic_api_resolution():
    strings = _strings_by_function()
    resolver_rows, resolver_functions = scan_direct_resolvers(strings)
    loader_rows, loader_functions = scan_dynamic_libraries(strings)
    export_rows, export_functions = scan_export_walkers()
    rows = resolver_rows + loader_rows + scan_hash_resolvers(resolver_functions | export_functions) + export_rows + scan_syscall_tables() + scan_custom_loaders(loader_functions, export_functions)
    unique = {}
    for row in rows[:_MAX_RESULTS]:
        unique[(row["category"], row["ea"], row["value"], row["evidence"])] = row
    return sorted(unique.values(), key=lambda row: (row["category"], row["function"], row["ea"]))


class DynamicAPIResolutionExplorer(ida_kernwin.PluginForm):
    def __init__(self):
        super().__init__()
        self.rows = []

    def OnCreate(self, form):
        self.parent = self.FormToPyQtWidget(form)
        apply_mac_workspace(self.parent)
        root = QtWidgets.QVBoxLayout(self.parent)
        root.setContentsMargins(16, 14, 16, 14)
        root.setSpacing(10)
        header = PageHeader("Dynamic API Resolution Explorer", "Runtime resolvers, API hashes, export walking, syscall tables, and custom loaders")
        refresh = QtWidgets.QPushButton("Refresh")
        refresh.setProperty("pnVariant", "primary")
        refresh.clicked.connect(self.refresh)
        header.add_action(refresh)
        copy = QtWidgets.QPushButton("Copy Selected")
        copy.clicked.connect(self.copy_selected)
        header.add_action(copy)
        export = QtWidgets.QPushButton("Export CSV")
        export.clicked.connect(self.export_csv)
        header.add_action(export)
        root.addWidget(header)
        self.filter_edit = QtWidgets.QLineEdit()
        self.filter_edit.setPlaceholderText("Filter resolver, API/module name, hash, syscall, loader, confidence, or evidence...")
        self.filter_edit.setClearButtonEnabled(True)
        self.filter_edit.textChanged.connect(self.apply_filter)
        root.addWidget(self.filter_edit)
        splitter = QtWidgets.QSplitter(QtCore.Qt.Horizontal)
        table_card = Card()
        self.table = QtWidgets.QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(["Category", "Address", "Function", "Value", "Confidence", "Evidence"])
        self.table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QtWidgets.QAbstractItemView.SingleSelection)
        self.table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.itemSelectionChanged.connect(self.show_details)
        self.table.itemDoubleClicked.connect(self.navigate_selected)
        table_card.add_widget(self.table)
        splitter.addWidget(table_card)
        detail_card = Card("Resolution evidence")
        self.details = QtWidgets.QTextBrowser()
        detail_card.add_widget(self.details)
        splitter.addWidget(detail_card)
        splitter.setSizes([990, 440])
        root.addWidget(splitter, 1)
        self.status = QtWidgets.QLabel("Ready")
        self.status.setProperty("pnMuted", True)
        root.addWidget(self.status)
        QtCore.QTimer.singleShot(0, self.refresh)

    def refresh(self):
        ida_kernwin.show_wait_box("Recovering dynamic API resolution...\nPress Cancel to stop safely.")
        try:
            self.rows = explore_dynamic_api_resolution()
        except Exception as exc:
            self.rows = []
            ida_kernwin.warning("Dynamic API Resolution Explorer failed:\n%s" % exc)
        finally:
            ida_kernwin.hide_wait_box()
        self.populate()

    def populate(self):
        self.table.setSortingEnabled(False)
        self.table.setRowCount(len(self.rows))
        for row_index, row in enumerate(self.rows):
            for column, value in enumerate([row["category"], _hex(row["ea"]), row["function"], row["value"], row["confidence"], row["evidence"]]):
                item = QtWidgets.QTableWidgetItem(value)
                item.setData(QtCore.Qt.UserRole, row_index)
                self.table.setItem(row_index, column, item)
        self.table.resizeColumnsToContents()
        self.table.setColumnWidth(5, max(420, self.table.columnWidth(5)))
        self.table.setSortingEnabled(True)
        self.apply_filter(self.filter_edit.text())
        self.status.setText("%d resolution records | hash and loader candidates require analyst validation" % len(self.rows))

    def selected_row(self):
        selected = self.table.selectionModel().selectedRows() if self.table.selectionModel() else []
        if not selected:
            return None
        item = self.table.item(selected[0].row(), 0)
        index = item.data(QtCore.Qt.UserRole) if item else None
        return self.rows[int(index)] if index is not None and 0 <= int(index) < len(self.rows) else None

    def apply_filter(self, text):
        needle = str(text or "").strip().lower()
        for row_index in range(self.table.rowCount()):
            row = self.rows[int(self.table.item(row_index, 0).data(QtCore.Qt.UserRole))]
            self.table.setRowHidden(row_index, bool(needle and needle not in " ".join(str(value) for value in row.values()).lower()))

    def show_details(self):
        row = self.selected_row()
        if not row:
            self.details.setPlainText("Select a resolution record to inspect its evidence.")
            return
        self.details.setPlainText("Category: %s\nAddress: %s\nFunction: %s\nValue: %s\nConfidence: %s\n\nEvidence: %s\n\nDetails:\n%s\n\nHash, export-walker, syscall-table, and custom-loader candidates require analyst validation." % (row["category"], _hex(row["ea"]), row["function"], row["value"], row["confidence"], row["evidence"], row["detail"]))

    def navigate_selected(self, *_args):
        row = self.selected_row()
        if row:
            ida_kernwin.jumpto(row["ea"])

    def _csv_text(self, rows):
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["Category", "Address", "Function", "Value", "Confidence", "Evidence", "Details"])
        for row in rows:
            writer.writerow([row["category"], _hex(row["ea"]), row["function"], row["value"], row["confidence"], row["evidence"], row["detail"]])
        return output.getvalue()

    def copy_selected(self):
        row = self.selected_row()
        if row:
            QtWidgets.QApplication.clipboard().setText(self._csv_text([row]))
            self.status.setText("Copied selected resolution record")

    def export_csv(self):
        path, _selected = QtWidgets.QFileDialog.getSaveFileName(self.parent, "Export Dynamic API Resolution", "dynamic_api_resolution.csv", "CSV files (*.csv)")
        if path:
            with open(path, "w", encoding="utf-8-sig", newline="") as handle:
                handle.write(self._csv_text(self.rows))
            self.status.setText("Exported %d records to %s" % (len(self.rows), os.path.basename(path)))

    def OnClose(self, form):
        global _explorer
        if _explorer is self:
            _explorer = None


def show_dynamic_api_resolution_explorer():
    global _explorer
    if _explorer is None:
        _explorer = DynamicAPIResolutionExplorer()
    _explorer.Show("PseudoNote - Dynamic API Resolution Explorer", options=ida_kernwin.PluginForm.WOPN_PERSIST)


class DynamicAPIResolutionExplorerHandler(idaapi.action_handler_t):
    def activate(self, ctx):
        show_dynamic_api_resolution_explorer()
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS
