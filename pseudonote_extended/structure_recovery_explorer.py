# -*- coding: utf-8 -*-
"""Recover candidate structures from clustered pointer-offset accesses."""
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
_MAX_OFFSET = 0x10000
_MAX_FIELDS = 512
_BASE = re.compile(r"\[\s*([A-Za-z][A-Za-z0-9]*)\s*(?:[+\-]|\])")
_REGISTER = re.compile(r"^[A-Za-z][A-Za-z0-9]*$")


def _hex(value):
    return "0x%X" % int(value)


def _func_name(ea):
    return idc.get_func_name(ea) or "sub_%X" % int(ea)


def _dtype_size(dtype):
    getter = getattr(ida_ua, "get_dtype_size", None)
    if getter:
        try:
            return max(1, int(getter(dtype)))
        except Exception:
            pass
    return 0


def _base_register(operand_text):
    match = _BASE.search(operand_text or "")
    return match.group(1).lower() if match else ""


def _access_mode(ea, operand_index):
    mnemonic = (idc.print_insn_mnem(ea) or "").lower()
    read_only = {"cmp", "test", "lea", "push", "call", "jmp"}
    if operand_index == 0 and mnemonic not in read_only:
        return "write"
    return "read"


def _nested_pointer_offsets(func_ea):
    """Find load [base+field] -> later dereference [loaded_reg+child_field] patterns."""
    items = list(idautils.FuncItems(func_ea))
    nested = set()
    for index, ea in enumerate(items):
        if (idc.print_insn_mnem(ea) or "").lower() not in ("mov", "ldr", "ld", "lw"):
            continue
        destination = (idc.print_operand(ea, 0) or "").strip().lower()
        if not _REGISTER.fullmatch(destination):
            continue
        source = idc.print_operand(ea, 1) or ""
        source_base = _base_register(source)
        if not source_base or idc.get_operand_type(ea, 1) != getattr(ida_ua, "o_displ", 4):
            continue
        parent_offset = int(idc.get_operand_value(ea, 1))
        if not 0 <= parent_offset <= _MAX_OFFSET:
            continue
        for later in items[index + 1:index + 9]:
            texts = [idc.print_operand(later, operand) or "" for operand in range(3)]
            if any(_base_register(text) == destination for text in texts):
                nested.add((source_base, parent_offset))
                break
    return nested


def recover_layouts():
    layouts = []
    for func_ea in idautils.Functions():
        clusters = {}
        nested = _nested_pointer_offsets(func_ea)
        for ea in idautils.FuncItems(func_ea):
            insn = ida_ua.insn_t()
            if ida_ua.decode_insn(insn, ea) <= 0:
                continue
            for operand_index, operand in enumerate(insn.ops):
                if operand.type != getattr(ida_ua, "o_displ", 4):
                    continue
                offset = int(getattr(operand, "addr", 0))
                if not 0 <= offset <= _MAX_OFFSET:
                    continue
                text = idc.print_operand(ea, operand_index) or ""
                base = _base_register(text)
                if not base or base in ("sp", "esp", "rsp", "bp", "ebp", "rbp"):
                    continue
                width = _dtype_size(getattr(operand, "dtype", 0))
                field = clusters.setdefault(base, {}).setdefault(offset, {"widths": set(), "reads": 0, "writes": 0, "sites": [], "nested": False})
                if width:
                    field["widths"].add(width)
                field[_access_mode(ea, operand_index) + "s"] += 1
                field["sites"].append((int(ea), idc.generate_disasm_line(ea, 0) or ""))
                field["nested"] = field["nested"] or (base, offset) in nested
        for base, fields in clusters.items():
            if len(fields) < 2:
                continue
            trimmed = dict(sorted(fields.items())[:_MAX_FIELDS])
            signature = tuple((offset, max(info["widths"] or {0})) for offset, info in trimmed.items())
            layouts.append({
                "func_ea": int(func_ea), "function": _func_name(func_ea), "base": base,
                "fields": trimmed, "signature": signature, "matches": [],
            })
        if ida_kernwin.user_cancelled():
            break
    for layout in layouts:
        layout["matches"] = [other for other in layouts if other is not layout and other["signature"] == layout["signature"]]
    return layouts


def _ctype(width, nested=False):
    if nested:
        return "void *"
    return {1: "uint8_t", 2: "uint16_t", 4: "uint32_t", 8: "uint64_t"}.get(width, "uint8_t")


def _safe_name(layout):
    function = re.sub(r"\W+", "_", layout["function"]).strip("_") or "object"
    base = re.sub(r"\W+", "_", layout["base"]).strip("_") or "ptr"
    return "Recovered_%s_%s_%X" % (function[:40], base[:12], layout["func_ea"])


def _has_overlapping_fields(layout):
    cursor = 0
    pointer_size = 8 if idaapi.get_inf_structure().is_64bit() else 4
    for offset, info in sorted(layout["fields"].items()):
        if offset < cursor:
            return True
        width = pointer_size if info["nested"] else max(info["widths"] or {1})
        cursor = offset + width
    return False


def build_declaration(layout):
    lines = ["struct %s {" % _safe_name(layout)]
    cursor = 0
    padding = 0
    for offset, info in sorted(layout["fields"].items()):
        width = max(info["widths"] or {1})
        if offset > cursor:
            lines.append("    uint8_t _padding_%d[0x%X];" % (padding, offset - cursor))
            padding += 1
        field_type = _ctype(width, info["nested"])
        field_name = "nested_%X" % offset if info["nested"] else "field_%X" % offset
        lines.append("    %s %s; /* +0x%X, %d read(s), %d write(s) */" % (field_type, field_name, offset, info["reads"], info["writes"]))
        cursor = max(cursor, offset + (idaapi.get_inf_structure().is_64bit() and 8 or width) if info["nested"] else offset + width)
    lines.append("};")
    return "\n".join(lines)


def _layout_detail(layout):
    lines = []
    for offset, info in sorted(layout["fields"].items()):
        widths = "/".join(str(value) for value in sorted(info["widths"])) or "unknown"
        nested = " | nested pointer candidate" if info["nested"] else ""
        lines.append("+0x%X | width %s | reads %d | writes %d%s" % (offset, widths, info["reads"], info["writes"], nested))
        lines.extend("  %s: %s" % (_hex(ea), text) for ea, text in info["sites"][:4])
    return "\n".join(lines)


class StructureRecoveryExplorer(ida_kernwin.PluginForm):
    def __init__(self):
        super().__init__()
        self.layouts = []

    def OnCreate(self, form):
        self.parent = self.FormToPyQtWidget(form)
        apply_mac_workspace(self.parent)
        root = QtWidgets.QVBoxLayout(self.parent)
        root.setContentsMargins(16, 14, 16, 14)
        root.setSpacing(10)
        header = PageHeader("Structure Recovery Explorer", "Cluster pointer offsets, infer fields and nested layouts, compare signatures, and import reviewed types")
        refresh = QtWidgets.QPushButton("Recover Layouts")
        refresh.setProperty("pnVariant", "primary")
        refresh.clicked.connect(self.refresh)
        header.add_action(refresh)
        apply_button = QtWidgets.QPushButton("Review & Import Type")
        apply_button.setProperty("pnVariant", "success")
        apply_button.clicked.connect(self.import_selected)
        header.add_action(apply_button)
        export = QtWidgets.QPushButton("Export CSV")
        export.clicked.connect(self.export_csv)
        header.add_action(export)
        root.addWidget(header)
        self.filter_edit = QtWidgets.QLineEdit()
        self.filter_edit.setPlaceholderText("Filter function, base register, offsets, nested fields, or compatible layouts...")
        self.filter_edit.setClearButtonEnabled(True)
        self.filter_edit.textChanged.connect(self.apply_filter)
        root.addWidget(self.filter_edit)
        splitter = QtWidgets.QSplitter(QtCore.Qt.Horizontal)
        table_card = Card()
        self.table = QtWidgets.QTableWidget(0, 7)
        self.table.setHorizontalHeaderLabels(["Function", "Address", "Base", "Fields", "Nested", "Compatible Layouts", "Confidence"])
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
        detail_card = Card("Recovered layout")
        self.details = QtWidgets.QTextBrowser()
        detail_card.add_widget(self.details)
        splitter.addWidget(detail_card)
        splitter.setSizes([900, 540])
        root.addWidget(splitter, 1)
        self.status = QtWidgets.QLabel("Ready")
        self.status.setProperty("pnMuted", True)
        root.addWidget(self.status)
        QtCore.QTimer.singleShot(0, self.refresh)

    def refresh(self):
        ida_kernwin.show_wait_box("Recovering pointer-based layouts...\nPress Cancel to stop safely.")
        try:
            self.layouts = recover_layouts()
        except Exception as exc:
            self.layouts = []
            ida_kernwin.warning("Structure Recovery Explorer failed:\n%s" % exc)
        finally:
            ida_kernwin.hide_wait_box()
        self.populate()

    def populate(self):
        self.table.setSortingEnabled(False)
        self.table.setRowCount(len(self.layouts))
        for row_index, layout in enumerate(self.layouts):
            nested = sum(1 for info in layout["fields"].values() if info["nested"])
            matches = ", ".join("%s:%s" % (item["function"], item["base"]) for item in layout["matches"][:8])
            confidence = "high" if len(layout["fields"]) >= 4 or layout["matches"] else "medium"
            values = [layout["function"], _hex(layout["func_ea"]), layout["base"], str(len(layout["fields"])), str(nested), matches or "None", confidence]
            for column, value in enumerate(values):
                item = QtWidgets.QTableWidgetItem(value)
                item.setData(QtCore.Qt.UserRole, row_index)
                self.table.setItem(row_index, column, item)
        self.table.resizeColumnsToContents()
        self.table.setColumnWidth(5, max(360, self.table.columnWidth(5)))
        self.table.setSortingEnabled(True)
        self.apply_filter(self.filter_edit.text())
        self.status.setText("%d candidate layouts | review required before Local Types import" % len(self.layouts))

    def selected_layout(self):
        selected = self.table.selectionModel().selectedRows() if self.table.selectionModel() else []
        if not selected:
            return None
        item = self.table.item(selected[0].row(), 0)
        index = item.data(QtCore.Qt.UserRole) if item else None
        return self.layouts[int(index)] if index is not None and 0 <= int(index) < len(self.layouts) else None

    def apply_filter(self, text):
        needle = str(text or "").strip().lower()
        for row_index in range(self.table.rowCount()):
            layout = self.layouts[int(self.table.item(row_index, 0).data(QtCore.Qt.UserRole))]
            haystack = (layout["function"] + " " + layout["base"] + " " + _layout_detail(layout) + " " + " ".join(item["function"] for item in layout["matches"])).lower()
            self.table.setRowHidden(row_index, bool(needle and needle not in haystack))

    def show_details(self):
        layout = self.selected_layout()
        if not layout:
            self.details.setPlainText("Select a recovered layout to inspect its evidence.")
            return
        self.details.setPlainText("Function: %s (%s)\nBase register: %s\nCompatible layouts: %d\n\n%s\n\nGenerated declaration:\n%s\n\nNested fields are pointer-follow candidates and require analyst validation." % (
            layout["function"], _hex(layout["func_ea"]), layout["base"], len(layout["matches"]), _layout_detail(layout), build_declaration(layout)))

    def navigate_selected(self, *_args):
        layout = self.selected_layout()
        if layout:
            ida_kernwin.jumpto(layout["func_ea"])

    def import_selected(self):
        layout = self.selected_layout()
        if not layout:
            ida_kernwin.warning("Select a recovered layout first.")
            return
        if _has_overlapping_fields(layout):
            ida_kernwin.warning("This candidate contains overlapping field ranges. Review it manually as a union; PseudoNote will not import a misleading sequential structure.")
            return
        declaration = build_declaration(layout)
        message = "Review this inferred declaration before importing it into IDA Local Types:\n\n%s" % declaration
        if ida_kernwin.ask_yn(ida_kernwin.ASKBTN_NO, message) != ida_kernwin.ASKBTN_YES:
            return
        result = idc.parse_decls(declaration, 0)
        if result == 0:
            self.status.setText("Imported reviewed type: %s" % _safe_name(layout))
            ida_kernwin.info("Imported '%s' into IDA Local Types. No variable or operand type was changed automatically." % _safe_name(layout))
        else:
            ida_kernwin.warning("IDA could not import the generated declaration (error %s)." % result)

    def _csv_text(self):
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["Function", "Address", "Base", "Field count", "Nested count", "Compatible layouts", "Declaration", "Evidence"])
        for layout in self.layouts:
            writer.writerow([layout["function"], _hex(layout["func_ea"]), layout["base"], len(layout["fields"]), sum(1 for info in layout["fields"].values() if info["nested"]), " ".join(item["function"] for item in layout["matches"]), build_declaration(layout), _layout_detail(layout)])
        return output.getvalue()

    def export_csv(self):
        path, _selected = QtWidgets.QFileDialog.getSaveFileName(self.parent, "Export Recovered Structures", "recovered_structures.csv", "CSV files (*.csv)")
        if path:
            with open(path, "w", encoding="utf-8-sig", newline="") as handle:
                handle.write(self._csv_text())
            self.status.setText("Exported %d layouts to %s" % (len(self.layouts), os.path.basename(path)))

    def OnClose(self, form):
        global _explorer
        if _explorer is self:
            _explorer = None


def show_structure_recovery_explorer():
    global _explorer
    if _explorer is None:
        _explorer = StructureRecoveryExplorer()
    _explorer.Show("PseudoNote - Structure Recovery Explorer", options=ida_kernwin.PluginForm.WOPN_PERSIST)


class StructureRecoveryExplorerHandler(idaapi.action_handler_t):
    def activate(self, ctx):
        show_structure_recovery_explorer()
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS
