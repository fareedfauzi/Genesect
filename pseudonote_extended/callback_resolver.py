# -*- coding: utf-8 -*-
"""Resolve callbacks, dispatch tables, jump tables, and indirect calls in IDA."""
import csv
import io
import os
import re

import idaapi
import ida_bytes
import ida_funcs
import ida_ida
import ida_kernwin
import ida_nalt
import ida_segment
import ida_ua
import idautils
import idc

from pseudonote_extended.qt_compat import QtCore, QtWidgets
from pseudonote_extended.ui.components import PageHeader, Card
from pseudonote_extended.ui.mac_workspace import apply_mac_workspace


_resolver = None
_MAX_DATA_SCAN = 512 * 1024 * 1024
_MAX_POINTER_ROWS = 100000
_MAX_INDIRECT_ROWS = 100000
_CALLBACK_API = re.compile(
    r"(?:setwindowshookex|registerclass|createdialog|dialogbox|enum(?:windows|childwindows|threadwindows|fonts|processes)|"
    r"settimer|queueuserapc|createthread|beginthread|signal|atexit|qsort|bsearch|register.*callback|set.*handler|"
    r"addvectoredexceptionhandler|setconsolectrlhandler|notify|subscribe)", re.I,
)
_HANDLER_NAME = re.compile(r"(?:callback|handler|dispatch|wndproc|dialogproc|dlgproc|hookproc|threadproc|signal|visitor|listener|on_[a-z])", re.I)


def _hex(ea):
    return "0x%X" % int(ea)


def _pointer_size():
    return 8 if ida_ida.inf_is_64bit() else 4


def _read_pointer(ea):
    if not ida_bytes.is_loaded(ea):
        return idaapi.BADADDR
    return ida_bytes.get_qword(ea) if _pointer_size() == 8 else ida_bytes.get_dword(ea)


def _function_start(ea):
    func = ida_funcs.get_func(ea)
    return int(func.start_ea) if func else idaapi.BADADDR


def _function_name(ea):
    start = _function_start(ea)
    return idc.get_func_name(start) or ("sub_%X" % start if start != idaapi.BADADDR else "")


def _owner(ea):
    name = _function_name(ea)
    start = _function_start(ea)
    return "%s (%s)" % (name, _hex(start)) if name else "<outside function>"


def _is_executable_function(ea):
    start = _function_start(ea)
    if start == idaapi.BADADDR:
        return False
    segment = ida_segment.getseg(start)
    return bool(segment and (segment.perm & ida_segment.SEGPERM_EXEC))


def _row(kind, site, target=idaapi.BADADDR, evidence="", confidence="high", detail=""):
    return {
        "kind": kind, "site": int(site), "target": int(target),
        "target_name": _function_name(target) if target != idaapi.BADADDR else "Unresolved",
        "owner": _owner(site), "evidence": evidence, "confidence": confidence, "detail": detail,
    }


def scan_function_pointers():
    rows, scanned = [], 0
    ptr_size = _pointer_size()
    for seg_ea in idautils.Segments():
        segment = ida_segment.getseg(seg_ea)
        if not segment or (segment.perm & ida_segment.SEGPERM_EXEC):
            continue
        ea = (int(segment.start_ea) + ptr_size - 1) & ~(ptr_size - 1)
        while ea + ptr_size <= segment.end_ea:
            if scanned >= _MAX_DATA_SCAN or len(rows) >= _MAX_POINTER_ROWS or ida_kernwin.user_cancelled():
                return rows
            scanned += ptr_size
            target = _read_pointer(ea)
            if _is_executable_function(target):
                name = idc.get_name(ea) or ""
                evidence = "named function pointer" if name else "aligned pointer in non-code segment"
                rows.append(_row("Function pointer", ea, _function_start(target), evidence, "high" if name else "medium", name))
            ea += ptr_size
    return rows


def _nearby_function_constants(call_ea, max_instructions=12):
    candidates = {}
    ea = int(call_ea)
    call_func = ida_funcs.get_func(call_ea)
    call_start = int(call_func.start_ea) if call_func else idaapi.BADADDR
    for _index in range(max_instructions):
        ea = idc.prev_head(ea)
        current_func = ida_funcs.get_func(ea)
        if ea in (idaapi.BADADDR, getattr(idc, "BADADDR", idaapi.BADADDR)) or not current_func or int(current_func.start_ea) != call_start:
            break
        for operand in range(3):
            operand_type = idc.get_operand_type(ea, operand)
            if operand_type in (getattr(ida_ua, "o_imm", 5), getattr(ida_ua, "o_mem", 2), getattr(ida_ua, "o_near", 7), getattr(ida_ua, "o_far", 6)):
                value = idc.get_operand_value(ea, operand)
                if _is_executable_function(value):
                    candidates[_function_start(value)] = ea
    return candidates


def scan_callback_registrations():
    rows = []
    for api_ea, api_name in idautils.Names():
        if not _CALLBACK_API.search(api_name or ""):
            continue
        for xref in idautils.XrefsTo(api_ea, 0):
            if xref.type not in (getattr(idaapi, "fl_CF", 16), getattr(idaapi, "fl_CN", 17)):
                continue
            candidates = _nearby_function_constants(xref.frm)
            if candidates:
                for target, setup_ea in candidates.items():
                    rows.append(_row("Callback registration", xref.frm, target, "function address prepared before %s" % api_name, "medium", "setup at %s" % _hex(setup_ea)))
            else:
                rows.append(_row("Callback registration", xref.frm, evidence="call to %s; callback argument unresolved" % api_name, confidence="low"))
    return rows


def scan_named_handlers():
    rows = []
    for ea in idautils.Functions():
        name = idc.get_func_name(ea) or ""
        if _HANDLER_NAME.search(name):
            rows.append(_row("Named handler", ea, ea, "handler/callback naming pattern", "high", name))
    return rows


def scan_switches():
    rows = []
    ptr_size = _pointer_size()
    for func_ea in idautils.Functions():
        for ea in idautils.FuncItems(func_ea):
            switch = ida_nalt.get_switch_info(ea)
            if not switch:
                continue
            jumps = int(getattr(switch, "jumps", idaapi.BADADDR))
            count = min(max(0, int(getattr(switch, "ncases", 0))), 65536)
            added = 0
            calculator = getattr(ida_nalt, "calc_switch_cases", None) or getattr(idaapi, "calc_switch_cases", None)
            if calculator:
                try:
                    case_info = calculator(ea, switch)
                    targets = list(getattr(case_info, "targets", []) or [])
                    cases = list(getattr(case_info, "cases", []) or [])
                    for index, target in enumerate(targets[:65536]):
                        case_values = list(cases[index]) if index < len(cases) else []
                        label = ", ".join(str(value) for value in case_values[:32]) or str(index)
                        rows.append(_row("Jump-table target", ea, _function_start(target) if _is_executable_function(target) else int(target), "IDA switch cases %s, table %s" % (label, _hex(jumps)), "high"))
                        added += 1
                except Exception:
                    added = 0
            if jumps != idaapi.BADADDR and count:
                for index in range(count if not added else 0):
                    entry = jumps + index * ptr_size
                    target = _read_pointer(entry)
                    if ida_bytes.is_loaded(target):
                        rows.append(_row("Jump-table target", ea, _function_start(target) if _is_executable_function(target) else target, "IDA switch metadata; case %d, table %s" % (index, _hex(jumps)), "high", "entry %s" % _hex(entry)))
                        added += 1
            if not added:
                rows.append(_row("Jump table", ea, evidence="IDA switch metadata; %d cases at %s" % (count, _hex(jumps)), confidence="high"))
        if ida_kernwin.user_cancelled():
            break
    return rows


def scan_indirect_calls():
    rows = []
    for func_ea in idautils.Functions():
        for ea in idautils.FuncItems(func_ea):
            insn = ida_ua.insn_t()
            if ida_ua.decode_insn(insn, ea) <= 0 or not (insn.get_canon_feature() & getattr(idaapi, "CF_CALL", 0x10)):
                continue
            op = insn.ops[0]
            if op.type in (getattr(ida_ua, "o_near", 7), getattr(ida_ua, "o_far", 6)):
                continue
            target = idaapi.BADADDR
            if op.type == getattr(ida_ua, "o_mem", 2):
                pointer_ea = int(op.addr)
                pointed = _read_pointer(pointer_ea)
                if _is_executable_function(pointed):
                    target = _function_start(pointed)
            detail = idc.generate_disasm_line(ea, 0) or idc.GetDisasm(ea)
            rows.append(_row("Indirect call", ea, target, "decoded call through register/memory operand", "high" if target != idaapi.BADADDR else "unresolved", detail))
            if len(rows) >= _MAX_INDIRECT_ROWS:
                return rows
        if ida_kernwin.user_cancelled():
            break
    return rows


def resolve_callbacks_and_dispatch():
    rows = []
    for scanner in (scan_callback_registrations, scan_named_handlers, scan_switches, scan_indirect_calls, scan_function_pointers):
        rows.extend(scanner())
        if ida_kernwin.user_cancelled():
            break
    unique = {}
    for item in rows:
        key = (item["kind"], item["site"], item["target"], item["evidence"])
        unique[key] = item
    return sorted(unique.values(), key=lambda item: (item["kind"], item["site"], item["target"]))


class CallbackDispatchResolver(ida_kernwin.PluginForm):
    def __init__(self):
        super().__init__()
        self.rows = []

    def OnCreate(self, form):
        self.parent = self.FormToPyQtWidget(form)
        apply_mac_workspace(self.parent)
        root = QtWidgets.QVBoxLayout(self.parent)
        root.setContentsMargins(16, 14, 16, 14)
        root.setSpacing(10)
        header = PageHeader("Callback and Dispatch Resolver", "Function pointers, registrations, handlers, jump tables, and indirect-call targets")
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
        self.filter_edit.setPlaceholderText("Filter by kind, address, target, function, evidence, or instruction…")
        self.filter_edit.setClearButtonEnabled(True)
        self.filter_edit.textChanged.connect(self.apply_filter)
        root.addWidget(self.filter_edit)
        splitter = QtWidgets.QSplitter(QtCore.Qt.Horizontal)
        table_card = Card()
        self.table = QtWidgets.QTableWidget(0, 7)
        self.table.setHorizontalHeaderLabels(["Kind", "Site", "Target", "Target name", "Containing function", "Confidence", "Evidence"])
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
        details_card = Card("Resolution evidence")
        self.details = QtWidgets.QTextBrowser()
        details_card.add_widget(self.details)
        splitter.addWidget(details_card)
        splitter.setSizes([1000, 400])
        root.addWidget(splitter, 1)
        self.status = QtWidgets.QLabel("Ready")
        self.status.setProperty("pnMuted", True)
        root.addWidget(self.status)
        QtCore.QTimer.singleShot(0, self.refresh)

    def refresh(self):
        ida_kernwin.show_wait_box("Resolving callbacks and indirect dispatch…\nPress Cancel to stop safely.")
        try:
            self.rows = resolve_callbacks_and_dispatch()
        except Exception as exc:
            self.rows = []
            ida_kernwin.warning("Callback and Dispatch Resolver failed:\n%s" % exc)
        finally:
            ida_kernwin.hide_wait_box()
        self.populate()

    def populate(self):
        self.table.setSortingEnabled(False)
        self.table.setRowCount(len(self.rows))
        for row_index, row in enumerate(self.rows):
            values = [row["kind"], _hex(row["site"]), _hex(row["target"]) if row["target"] != idaapi.BADADDR else "Unresolved", row["target_name"], row["owner"], row["confidence"], row["evidence"]]
            for column, value in enumerate(values):
                item = QtWidgets.QTableWidgetItem(value)
                item.setData(QtCore.Qt.UserRole, row_index)
                self.table.setItem(row_index, column, item)
        self.table.resizeColumnsToContents()
        self.table.setColumnWidth(6, max(340, self.table.columnWidth(6)))
        self.table.setSortingEnabled(True)
        self.apply_filter(self.filter_edit.text())
        counts = {}
        for row in self.rows:
            counts[row["kind"]] = counts.get(row["kind"], 0) + 1
        self.status.setText("%d results • %s" % (len(self.rows), " • ".join("%s: %d" % item for item in sorted(counts.items()))))

    def selected_row(self):
        selected = self.table.selectionModel().selectedRows() if self.table.selectionModel() else []
        if not selected:
            return None
        item = self.table.item(selected[0].row(), 0)
        index = item.data(QtCore.Qt.UserRole) if item else None
        return self.rows[int(index)] if index is not None and 0 <= int(index) < len(self.rows) else None

    def apply_filter(self, text):
        needle = str(text or "").strip().lower()
        for row in range(self.table.rowCount()):
            haystack = " ".join(self.table.item(row, col).text() for col in range(self.table.columnCount()) if self.table.item(row, col)).lower()
            source = self.rows[int(self.table.item(row, 0).data(QtCore.Qt.UserRole))]
            haystack += " " + source["detail"].lower()
            self.table.setRowHidden(row, bool(needle and needle not in haystack))

    def show_details(self):
        row = self.selected_row()
        if not row:
            self.details.setPlainText("Select a result to inspect its resolution evidence.")
            return
        self.details.setPlainText(
            "Kind: %s\nSite: %s\nContaining function: %s\nTarget: %s %s\nConfidence: %s\n\nEvidence: %s\n\nInstruction / detail:\n%s" % (
                row["kind"], _hex(row["site"]), row["owner"],
                _hex(row["target"]) if row["target"] != idaapi.BADADDR else "Unresolved",
                row["target_name"], row["confidence"], row["evidence"], row["detail"],
            )
        )

    def navigate_selected(self, *_args):
        row = self.selected_row()
        if row:
            ida_kernwin.jumpto(row["site"])

    def _csv_text(self, rows):
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["Kind", "Site", "Target", "Target name", "Containing function", "Confidence", "Evidence", "Detail"])
        for row in rows:
            writer.writerow([row["kind"], _hex(row["site"]), _hex(row["target"]) if row["target"] != idaapi.BADADDR else "", row["target_name"], row["owner"], row["confidence"], row["evidence"], row["detail"]])
        return output.getvalue()

    def copy_selected(self):
        row = self.selected_row()
        if row:
            QtWidgets.QApplication.clipboard().setText(self._csv_text([row]))
            self.status.setText("Copied selected resolution")

    def export_csv(self):
        path, _selected = QtWidgets.QFileDialog.getSaveFileName(self.parent, "Export Callback and Dispatch Results", "callback_dispatch.csv", "CSV files (*.csv)")
        if path:
            with open(path, "w", encoding="utf-8-sig", newline="") as handle:
                handle.write(self._csv_text(self.rows))
            self.status.setText("Exported %d results to %s" % (len(self.rows), os.path.basename(path)))

    def OnClose(self, form):
        global _resolver
        if _resolver is self:
            _resolver = None


def show_callback_dispatch_resolver():
    global _resolver
    if _resolver is None:
        _resolver = CallbackDispatchResolver()
    _resolver.Show("PseudoNote - Callback and Dispatch Resolver", options=ida_kernwin.PluginForm.WOPN_PERSIST)


class CallbackDispatchResolverHandler(idaapi.action_handler_t):
    def activate(self, ctx):
        show_callback_dispatch_resolver()
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS
