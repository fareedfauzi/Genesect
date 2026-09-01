# -*- coding: utf-8 -*-
"""Cross-format exception, SEH, landing-pad, cleanup, and unwind explorer."""
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
import idautils
import idc

from pseudonote_extended.qt_compat import QtCore, QtWidgets
from pseudonote_extended.ui.components import PageHeader, Card
from pseudonote_extended.ui.mac_workspace import apply_mac_workspace


_explorer = None
_EXCEPTION_SEGMENT = re.compile(r"(?:\.pdata|\.xdata|\.eh_frame|\.gcc_except_table|__unwind_info|__eh_frame|__gcc_except_tab|exception|unwind)", re.I)
_HANDLER_NAME = re.compile(
    r"(?:except_handler|exceptionhandler|framehandler|personality|terminate|unexpected|unwind|landing|catch|filter|"
    r"setunhandledexceptionfilter|vectoredexception|rtlunwind|raiseexception|cxxthrow|__throw)", re.I,
)
_REGISTRATION_API = re.compile(r"(?:setunhandledexceptionfilter|addvectoredexceptionhandler|removevectoredexceptionhandler|signal|set_terminate|set_unexpected)", re.I)
_THROW_UNWIND_API = re.compile(r"(?:raiseexception|rtlraiseexception|rtlunwind|_cxxthrowexception|__cxa_throw|__cxa_rethrow|_unwind_raiseexception|longjmp|throw)", re.I)
_CLEANUP_NAME = re.compile(r"(?:destructor|deleting destructor|cleanup|finally|unwind|destroy|dispose|free|release)", re.I)
_MAX_METADATA_BYTES = 256 * 1024 * 1024
_MAX_RESULTS = 200000


def _hex(ea):
    return "0x%X" % int(ea)


def _pointer_size():
    return 8 if ida_ida.inf_is_64bit() else 4


def _read_pointer(ea):
    if not ida_bytes.is_loaded(ea):
        return idaapi.BADADDR
    return ida_bytes.get_qword(ea) if _pointer_size() == 8 else ida_bytes.get_dword(ea)


def _func_start(ea):
    func = ida_funcs.get_func(ea)
    return int(func.start_ea) if func else idaapi.BADADDR


def _func_name(ea):
    start = _func_start(ea)
    return idc.get_func_name(start) or ("sub_%X" % start if start != idaapi.BADADDR else "")


def _owner(ea):
    name = _func_name(ea)
    start = _func_start(ea)
    return "%s (%s)" % (name, _hex(start)) if name else "<metadata / outside function>"


def _row(category, site, target=idaapi.BADADDR, mechanism="", evidence="", confidence="high", detail=""):
    return {
        "category": category, "site": int(site), "target": int(target),
        "target_name": _func_name(target) if target != idaapi.BADADDR else "",
        "owner": _owner(site), "mechanism": mechanism, "evidence": evidence,
        "confidence": confidence, "detail": detail,
    }


def scan_named_handlers():
    rows = []
    for ea, name in idautils.Names():
        if _HANDLER_NAME.search(name or "") and _func_start(ea) != idaapi.BADADDR:
            rows.append(_row("Handler / runtime", _func_start(ea), _func_start(ea), "named handler", "exception or unwind symbol pattern: %s" % name, "high", name))
    return rows


def scan_exception_api_calls():
    rows = []
    for api_ea, api_name in idautils.Names():
        category = "Handler registration" if _REGISTRATION_API.search(api_name or "") else "Throw / unwind" if _THROW_UNWIND_API.search(api_name or "") else ""
        if not category:
            continue
        for xref in idautils.XrefsTo(api_ea, 0):
            if xref.type not in (getattr(idaapi, "fl_CF", 16), getattr(idaapi, "fl_CN", 17)):
                continue
            rows.append(_row(category, xref.frm, api_ea, api_name, "direct call to exception runtime API", "high", idc.generate_disasm_line(xref.frm, 0) or ""))
    return rows


def scan_unwind_metadata():
    """Scan only known exception/unwind sections for pointers into executable functions."""
    rows, scanned = [], 0
    ptr_size = _pointer_size()
    for seg_ea in idautils.Segments():
        segment = ida_segment.getseg(seg_ea)
        if not segment:
            continue
        seg_name = ida_segment.get_segm_name(segment) or ""
        if not _EXCEPTION_SEGMENT.search(seg_name):
            continue
        pe_metadata = seg_name.lower() in (".pdata", ".xdata")
        stride = 4 if pe_metadata else ptr_size
        ea = (int(segment.start_ea) + stride - 1) & ~(stride - 1)
        while ea + stride <= segment.end_ea:
            if scanned >= _MAX_METADATA_BYTES or len(rows) >= _MAX_RESULTS or ida_kernwin.user_cancelled():
                return rows
            scanned += stride
            candidates = set(int(target) for target in idautils.DataRefsFrom(ea))
            raw = ida_bytes.get_dword(ea) if stride == 4 else _read_pointer(ea)
            if raw not in (0, idaapi.BADADDR):
                candidates.add(int(raw))
                if pe_metadata:
                    candidates.add(int(ida_nalt.get_imagebase()) + int(raw))
            for target in candidates:
                target_func = _func_start(target)
                if target_func != idaapi.BADADDR:
                    rows.append(_row("Landing pad / metadata target", ea, target_func, seg_name, "code target recovered from unwind metadata section", "metadata-backed", "entry %s" % _hex(ea)))
            ea += stride
    return rows


def scan_seh_chain_patterns():
    """Find x86/x64 TEB exception-list access and compiler SEH keywords in disassembly."""
    rows = []
    for func_ea in idautils.Functions():
        hits = []
        for ea in idautils.FuncItems(func_ea):
            line = idc.generate_disasm_line(ea, 0) or idc.GetDisasm(ea) or ""
            lowered = line.lower()
            if ("fs:" in lowered or "gs:" in lowered) and any(token in lowered for token in ("[0]", ":0", "exception", "seh")):
                hits.append((ea, line))
            if len(hits) >= 8:
                break
        if hits:
            rows.append(_row("SEH chain", hits[0][0], func_ea, "TEB exception-list access", "%d FS/GS exception-chain pattern(s)" % len(hits), "pattern", "\n".join("%s: %s" % (_hex(ea), line) for ea, line in hits)))
        if ida_kernwin.user_cancelled() or len(rows) >= _MAX_RESULTS:
            break
    return rows


def scan_cleanup_paths():
    rows = []
    cleanup_functions = {}
    for ea in idautils.Functions():
        name = idc.get_func_name(ea) or ""
        if _CLEANUP_NAME.search(name):
            cleanup_functions[int(ea)] = name
    for cleanup_ea, cleanup_name in cleanup_functions.items():
        for xref in idautils.XrefsTo(cleanup_ea, 0):
            if xref.type in (getattr(idaapi, "fl_CF", 16), getattr(idaapi, "fl_CN", 17)):
                rows.append(_row("Cleanup path", xref.frm, cleanup_ea, cleanup_name, "call to named cleanup/destructor routine", "symbol-backed", idc.generate_disasm_line(xref.frm, 0) or ""))
            if len(rows) >= _MAX_RESULTS:
                return rows
    return rows


def scan_function_unwind_flags():
    rows = []
    unwind_flag = getattr(ida_funcs, "FUNC_UNWIND", getattr(idaapi, "FUNC_UNWIND", 0))
    if not unwind_flag:
        return rows
    for ea in idautils.Functions():
        func = ida_funcs.get_func(ea)
        if func and (int(func.flags) & int(unwind_flag)):
            rows.append(_row("Compiler-generated unwind", ea, ea, "IDA function unwind flag", "IDA marked this function as an unwind handler", "high"))
    return rows


def explore_exceptions_and_unwind():
    rows = []
    for scanner in (scan_named_handlers, scan_exception_api_calls, scan_unwind_metadata, scan_seh_chain_patterns, scan_cleanup_paths, scan_function_unwind_flags):
        rows.extend(scanner())
        if ida_kernwin.user_cancelled() or len(rows) >= _MAX_RESULTS:
            break
    unique = {}
    for item in rows[:_MAX_RESULTS]:
        unique[(item["category"], item["site"], item["target"], item["mechanism"])] = item
    return sorted(unique.values(), key=lambda item: (item["category"], item["owner"], item["site"]))


class ExceptionUnwindExplorer(ida_kernwin.PluginForm):
    def __init__(self):
        super().__init__()
        self.rows = []

    def OnCreate(self, form):
        self.parent = self.FormToPyQtWidget(form)
        apply_mac_workspace(self.parent)
        root = QtWidgets.QVBoxLayout(self.parent)
        root.setContentsMargins(16, 14, 16, 14)
        root.setSpacing(10)
        header = PageHeader("Exception and Unwind Explorer", "Exception handlers, SEH chains, cleanup paths, landing pads, and compiler unwind behavior")
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
        self.filter_edit.setPlaceholderText("Filter handlers, SEH, landing pads, cleanup paths, runtime APIs, or functions…")
        self.filter_edit.setClearButtonEnabled(True)
        self.filter_edit.textChanged.connect(self.apply_filter)
        root.addWidget(self.filter_edit)
        splitter = QtWidgets.QSplitter(QtCore.Qt.Horizontal)
        tree_card = Card("Recovered exception model")
        self.tree = QtWidgets.QTreeWidget()
        self.tree.setHeaderLabels(["Category / function", "Site", "Target", "Confidence"])
        self.tree.setAlternatingRowColors(True)
        self.tree.itemSelectionChanged.connect(self.show_details)
        self.tree.itemDoubleClicked.connect(self.navigate_selected)
        tree_card.add_widget(self.tree)
        splitter.addWidget(tree_card)
        detail_card = Card("Exception and unwind evidence")
        self.details = QtWidgets.QTextBrowser()
        detail_card.add_widget(self.details)
        splitter.addWidget(detail_card)
        splitter.setSizes([760, 620])
        root.addWidget(splitter, 1)
        self.status = QtWidgets.QLabel("Ready")
        self.status.setProperty("pnMuted", True)
        root.addWidget(self.status)
        QtCore.QTimer.singleShot(0, self.refresh)

    def refresh(self):
        ida_kernwin.show_wait_box("Recovering exception and unwind behavior…\nPress Cancel to stop safely.")
        try:
            self.rows = explore_exceptions_and_unwind()
        except Exception as exc:
            self.rows = []
            ida_kernwin.warning("Exception and Unwind Explorer failed:\n%s" % exc)
        finally:
            ida_kernwin.hide_wait_box()
        self.populate()

    def populate(self):
        self.tree.clear()
        groups = {}
        for index, row in enumerate(self.rows):
            group = groups.get(row["category"])
            if group is None:
                group = QtWidgets.QTreeWidgetItem(self.tree, [row["category"], "", "", ""])
                groups[row["category"]] = group
            item = QtWidgets.QTreeWidgetItem(group, [row["owner"], _hex(row["site"]), _hex(row["target"]) if row["target"] != idaapi.BADADDR else "—", row["confidence"]])
            item.setData(0, QtCore.Qt.UserRole, index)
        self.tree.resizeColumnToContents(0)
        self.tree.resizeColumnToContents(1)
        self.tree.expandAll()
        self.apply_filter(self.filter_edit.text())
        self.status.setText("%d exception/unwind records • metadata and heuristic evidence are labeled separately" % len(self.rows))

    def selected_row(self):
        item = self.tree.currentItem()
        if not item:
            return None
        index = item.data(0, QtCore.Qt.UserRole)
        return self.rows[int(index)] if index is not None and 0 <= int(index) < len(self.rows) else None

    def apply_filter(self, text):
        needle = str(text or "").strip().lower()
        for group_index in range(self.tree.topLevelItemCount()):
            group = self.tree.topLevelItem(group_index)
            visible = False
            for child_index in range(group.childCount()):
                child = group.child(child_index)
                index = child.data(0, QtCore.Qt.UserRole)
                row = self.rows[int(index)]
                haystack = " ".join(str(value) for value in row.values()).lower()
                matched = not needle or needle in haystack
                child.setHidden(not matched)
                visible = visible or matched
            group.setHidden(not visible)

    def show_details(self):
        row = self.selected_row()
        if not row:
            self.details.setPlainText("Select an exception or unwind record to inspect its evidence.")
            return
        self.details.setPlainText(
            "Category: %s\nSite: %s\nOwner: %s\nTarget: %s %s\nMechanism: %s\nConfidence: %s\n\nEvidence: %s\n\nDetails:\n%s\n\nPattern-based cleanup and SEH results are candidates; metadata-backed results originate from IDA symbols, flags, or unwind sections." % (
                row["category"], _hex(row["site"]), row["owner"], _hex(row["target"]) if row["target"] != idaapi.BADADDR else "N/A",
                row["target_name"], row["mechanism"], row["confidence"], row["evidence"], row["detail"],
            )
        )

    def navigate_selected(self, *_args):
        row = self.selected_row()
        if row:
            ida_kernwin.jumpto(row["target"] if row["target"] != idaapi.BADADDR else row["site"])

    def _csv_text(self, rows):
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["Category", "Site", "Owner", "Target", "Target name", "Mechanism", "Confidence", "Evidence", "Detail"])
        for row in rows:
            writer.writerow([row["category"], _hex(row["site"]), row["owner"], _hex(row["target"]) if row["target"] != idaapi.BADADDR else "", row["target_name"], row["mechanism"], row["confidence"], row["evidence"], row["detail"]])
        return output.getvalue()

    def copy_selected(self):
        row = self.selected_row()
        if row:
            QtWidgets.QApplication.clipboard().setText(self._csv_text([row]))
            self.status.setText("Copied selected exception/unwind record")

    def export_csv(self):
        path, _selected = QtWidgets.QFileDialog.getSaveFileName(self.parent, "Export Exception and Unwind Results", "exception_unwind.csv", "CSV files (*.csv)")
        if path:
            with open(path, "w", encoding="utf-8-sig", newline="") as handle:
                handle.write(self._csv_text(self.rows))
            self.status.setText("Exported %d records to %s" % (len(self.rows), os.path.basename(path)))

    def OnClose(self, form):
        global _explorer
        if _explorer is self:
            _explorer = None


def show_exception_unwind_explorer():
    global _explorer
    if _explorer is None:
        _explorer = ExceptionUnwindExplorer()
    _explorer.Show("PseudoNote - Exception and Unwind Explorer", options=ida_kernwin.PluginForm.WOPN_PERSIST)


class ExceptionUnwindExplorerHandler(idaapi.action_handler_t):
    def activate(self, ctx):
        show_exception_unwind_explorer()
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS
