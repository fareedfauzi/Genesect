# -*- coding: utf-8 -*-
"""Inspect decompiler failures, typing gaps, stack warnings, casts, and unresolved calls."""
import csv
import io
import os
import re

import idaapi
import ida_funcs
import ida_hexrays
import ida_kernwin
import ida_ua
import idautils
import idc

from pseudonote_extended.qt_compat import QtCore, QtWidgets
from pseudonote_extended.ui.components import PageHeader, Card
from pseudonote_extended.ui.mac_workspace import apply_mac_workspace


_inspector = None
_STACK_WARNING = re.compile(r"(?:positive sp value|sp-analysis failed|stack pointer|bad stack|failed to trace the value of sp|inconsistent sp)", re.I)
_CAST = re.compile(r"\([^\n()]{1,80}(?:\*|__cdecl|__stdcall|__fastcall|__thiscall|int|long|char|short|void)[^\n()]{0,80}\)")
_DEFAULT_NAME = re.compile(r"^(?:sub|nullsub|loc|unk)_[0-9A-F]+$", re.I)
_MAX_RESULTS = 200000


def _hex(value):
    return "0x%X" % int(value)


def _func_start(ea):
    func = ida_funcs.get_func(ea)
    return int(func.start_ea) if func else idaapi.BADADDR


def _func_name(ea):
    start = _func_start(ea)
    return idc.get_func_name(start) or ("sub_%X" % start if start != idaapi.BADADDR else "")


def _row(issue, ea, severity="medium", evidence="", recommendation="", detail=""):
    return {
        "issue": issue, "ea": int(ea), "function": _func_name(ea), "severity": severity,
        "evidence": evidence, "recommendation": recommendation, "detail": detail,
    }


def _decompile(func_ea):
    try:
        cfunc = ida_hexrays.decompile(func_ea)
        return cfunc, ""
    except Exception as exc:
        return None, str(exc)


def inspect_prototype(func_ea):
    rows = []
    prototype = idc.get_type(func_ea) or ""
    name = _func_name(func_ea)
    if not prototype:
        rows.append(_row("Missing function prototype", func_ea, "medium", "IDA has no function type declaration", "Infer or define the calling convention, return type, and parameters."))
    elif "..." in prototype:
        rows.append(_row("Variadic / incomplete prototype", func_ea, "medium", prototype, "Verify fixed parameters and calling convention from call sites."))
    elif _DEFAULT_NAME.match(name) and re.search(r"\b(?:int|__int64|void)\s+(?:__cdecl|__fastcall|__stdcall|__thiscall)?", prototype):
        rows.append(_row("Generic inferred prototype", func_ea, "low", prototype, "Review argument and return types using callers and callees."))
    return rows


def inspect_stack_consistency(func_ea):
    rows = []
    func = ida_funcs.get_func(func_ea)
    flags = int(getattr(func, "flags", 0)) if func else 0
    sp_ready = getattr(ida_funcs, "FUNC_SP_READY", getattr(idaapi, "FUNC_SP_READY", 0))
    if sp_ready and not flags & sp_ready:
        rows.append(_row("Stack analysis incomplete", func_ea, "high", "IDA FUNC_SP_READY flag is not set", "Repair stack deltas, calling conventions, and function boundaries before trusting pseudocode."))
    for ea in idautils.FuncItems(func_ea):
        line = idc.generate_disasm_line(ea, 0) or ""
        comment = "%s %s" % (idc.get_cmt(ea, False) or "", idc.get_cmt(ea, True) or "")
        match = _STACK_WARNING.search(line + " " + comment)
        if match:
            rows.append(_row("Stack inconsistency warning", ea, "high", match.group(0), "Inspect SP changes, purged bytes, frame size, and function boundaries.", line))
    return rows


def inspect_calls(func_ea):
    rows = []
    for ea in idautils.FuncItems(func_ea):
        mnemonic = (idc.print_insn_mnem(ea) or "").lower()
        if mnemonic not in ("call", "bl", "blr", "jal", "jalr"):
            continue
        operand_type = idc.get_operand_type(ea, 0)
        text = idc.print_operand(ea, 0) or ""
        if operand_type in (getattr(ida_ua, "o_reg", 1), getattr(ida_ua, "o_phrase", 3), getattr(ida_ua, "o_displ", 4)):
            rows.append(_row("Unresolved indirect call", ea, "medium", text, "Recover the function-pointer type, vtable, callback registration, or dispatch target.", idc.generate_disasm_line(ea, 0) or ""))
            continue
        targets = list(idautils.CodeRefsFrom(ea, False))
        if not targets:
            rows.append(_row("Call target unresolved", ea, "high", text, "Define the target as code or repair the operand/reference.", idc.generate_disasm_line(ea, 0) or ""))
            continue
        target = int(targets[0])
        if not idc.get_name(target) and _func_start(target) == idaapi.BADADDR:
            rows.append(_row("Undefined direct-call target", ea, "high", _hex(target), "Create or repair the target function and its prototype.", idc.generate_disasm_line(ea, 0) or ""))
    return rows


def inspect_pseudocode(func_ea, cfunc):
    rows = []
    code = str(cfunc)
    casts = list(_CAST.finditer(code))
    line_count = max(1, code.count("\n") + 1)
    if len(casts) >= 5 and len(casts) / float(line_count) >= 0.08:
        snippets = [match.group(0) for match in casts[:20]]
        rows.append(_row("Cast-heavy pseudocode", func_ea, "medium", "%d casts across %d lines" % (len(casts), line_count), "Repair prototypes, pointer types, structures, and local-variable types.", "\n".join(snippets)))
    try:
        lvars = list(cfunc.get_lvars())
    except Exception:
        lvars = []
    for lvar in lvars:
        try:
            tif = lvar.type()
            type_text = str(tif or "").strip()
            unknown = bool(getattr(tif, "is_unknown", lambda: False)()) if tif else True
            void_type = bool(getattr(tif, "is_void", lambda: False)()) if tif else False
        except Exception:
            type_text, unknown, void_type = "", True, False
        name = str(getattr(lvar, "name", "") or "variable")
        if unknown or not type_text or type_text in ("_UNKNOWN", "unknown"):
            rows.append(_row("Variable needs a type", func_ea, "medium", "%s: %s" % (name, type_text or "unknown"), "Infer the variable type from assignments, dereferences, arguments, and callees."))
        elif void_type and "*" not in type_text:
            rows.append(_row("Suspicious void variable", func_ea, "medium", "%s: %s" % (name, type_text), "Review the local-variable type and its uses."))
    return rows


def inspect_function(func_ea):
    rows = inspect_prototype(func_ea) + inspect_stack_consistency(func_ea) + inspect_calls(func_ea)
    cfunc, error = _decompile(func_ea)
    if cfunc is None:
        rows.append(_row("Decompilation failed", func_ea, "high", error or "Hex-Rays returned no cfunc", "Repair function boundaries, stack analysis, instruction decoding, and calling conventions."))
    else:
        rows.extend(inspect_pseudocode(func_ea, cfunc))
    return rows


def inspect_decompiler_quality(functions):
    rows = []
    for func_ea in functions:
        rows.extend(inspect_function(int(func_ea)))
        if ida_kernwin.user_cancelled() or len(rows) >= _MAX_RESULTS:
            break
    unique = {}
    for row in rows[:_MAX_RESULTS]:
        unique[(row["issue"], row["ea"], row["evidence"])] = row
    return sorted(unique.values(), key=lambda row: (row["function"], row["ea"], row["issue"]))


class DecompilerQualityInspector(ida_kernwin.PluginForm):
    def __init__(self):
        super().__init__()
        self.rows = []

    def OnCreate(self, form):
        self.parent = self.FormToPyQtWidget(form)
        apply_mac_workspace(self.parent)
        root = QtWidgets.QVBoxLayout(self.parent)
        root.setContentsMargins(16, 14, 16, 14)
        root.setSpacing(10)
        header = PageHeader("Decompiler Quality Inspector", "Failed decompilations, prototype and stack issues, suspicious casts, unresolved calls, and missing variable types")
        current = QtWidgets.QPushButton("Inspect Current Function")
        current.setProperty("pnVariant", "primary")
        current.clicked.connect(self.scan_current)
        header.add_action(current)
        all_functions = QtWidgets.QPushButton("Inspect Entire IDB")
        all_functions.clicked.connect(self.scan_all)
        header.add_action(all_functions)
        export = QtWidgets.QPushButton("Export CSV")
        export.clicked.connect(self.export_csv)
        header.add_action(export)
        root.addWidget(header)
        self.filter_edit = QtWidgets.QLineEdit()
        self.filter_edit.setPlaceholderText("Filter issue, function, severity, evidence, or recommendation...")
        self.filter_edit.setClearButtonEnabled(True)
        self.filter_edit.textChanged.connect(self.apply_filter)
        root.addWidget(self.filter_edit)
        splitter = QtWidgets.QSplitter(QtCore.Qt.Horizontal)
        table_card = Card()
        self.table = QtWidgets.QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(["Issue", "Address", "Function", "Severity", "Evidence", "Recommendation"])
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
        detail_card = Card("Quality evidence")
        self.details = QtWidgets.QTextBrowser()
        detail_card.add_widget(self.details)
        splitter.addWidget(detail_card)
        splitter.setSizes([990, 440])
        root.addWidget(splitter, 1)
        self.status = QtWidgets.QLabel("Ready")
        self.status.setProperty("pnMuted", True)
        root.addWidget(self.status)
        QtCore.QTimer.singleShot(0, self.scan_current)

    def _scan(self, functions, label):
        ida_kernwin.show_wait_box("%s...\nPress Cancel to stop safely." % label)
        try:
            self.rows = inspect_decompiler_quality(functions)
        except Exception as exc:
            self.rows = []
            ida_kernwin.warning("Decompiler Quality Inspector failed:\n%s" % exc)
        finally:
            ida_kernwin.hide_wait_box()
        self.populate()

    def scan_current(self):
        ea = idaapi.get_screen_ea()
        func_ea = _func_start(ea)
        if func_ea == idaapi.BADADDR:
            ida_kernwin.warning("Place the cursor inside a function first.")
            return
        self._scan([func_ea], "Inspecting current function")

    def scan_all(self):
        self._scan(list(idautils.Functions()), "Inspecting all functions")

    def populate(self):
        self.table.setSortingEnabled(False)
        self.table.setRowCount(len(self.rows))
        for row_index, row in enumerate(self.rows):
            for column, value in enumerate([row["issue"], _hex(row["ea"]), row["function"], row["severity"], row["evidence"], row["recommendation"]]):
                item = QtWidgets.QTableWidgetItem(value)
                item.setData(QtCore.Qt.UserRole, row_index)
                self.table.setItem(row_index, column, item)
        self.table.resizeColumnsToContents()
        self.table.setColumnWidth(4, min(460, max(260, self.table.columnWidth(4))))
        self.table.setColumnWidth(5, max(440, self.table.columnWidth(5)))
        self.table.setSortingEnabled(True)
        self.apply_filter(self.filter_edit.text())
        high = sum(1 for row in self.rows if row["severity"] == "high")
        self.status.setText("%d quality findings | %d high severity | no IDB changes made" % (len(self.rows), high))

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
            self.details.setPlainText("Select a quality finding to inspect its evidence.")
            return
        self.details.setPlainText("Issue: %s\nAddress: %s\nFunction: %s\nSeverity: %s\n\nEvidence: %s\n\nRecommendation: %s\n\nDetails:\n%s\n\nMedium and low findings are review candidates, not proof that Hex-Rays is wrong." % (row["issue"], _hex(row["ea"]), row["function"], row["severity"], row["evidence"], row["recommendation"], row["detail"]))

    def navigate_selected(self, *_args):
        row = self.selected_row()
        if row:
            ida_kernwin.jumpto(row["ea"])

    def _csv_text(self):
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["Issue", "Address", "Function", "Severity", "Evidence", "Recommendation", "Details"])
        for row in self.rows:
            writer.writerow([row["issue"], _hex(row["ea"]), row["function"], row["severity"], row["evidence"], row["recommendation"], row["detail"]])
        return output.getvalue()

    def export_csv(self):
        path, _selected = QtWidgets.QFileDialog.getSaveFileName(self.parent, "Export Decompiler Quality Findings", "decompiler_quality.csv", "CSV files (*.csv)")
        if path:
            with open(path, "w", encoding="utf-8-sig", newline="") as handle:
                handle.write(self._csv_text())
            self.status.setText("Exported %d findings to %s" % (len(self.rows), os.path.basename(path)))

    def OnClose(self, form):
        global _inspector
        if _inspector is self:
            _inspector = None


def show_decompiler_quality_inspector():
    global _inspector
    if _inspector is None:
        _inspector = DecompilerQualityInspector()
    _inspector.Show("PseudoNote - Decompiler Quality Inspector", options=ida_kernwin.PluginForm.WOPN_PERSIST)


class DecompilerQualityInspectorHandler(idaapi.action_handler_t):
    def activate(self, ctx):
        show_decompiler_quality_inspector()
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS
