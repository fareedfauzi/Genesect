# -*- coding: utf-8 -*-
"""Safety-first string decoder discovery, preview, and reference annotation."""
import base64
import binascii
import codecs
import csv
import io
import os
import re

import idaapi
import ida_bytes
import ida_funcs
import ida_kernwin
import idautils
import idc

from pseudonote_extended.qt_compat import QtCore, QtWidgets
from pseudonote_extended.ui.components import PageHeader, Card
from pseudonote_extended.ui.mac_workspace import apply_mac_workspace


_workbench = None
_MAX_RESULTS = 100000
_DECODER_NAME = re.compile(r"(?:decrypt|decode|deobfus|unpack|string.*(?:xor|crypt)|(?:xor|rc4|aes|base64).*(?:string|buffer))", re.I)
_DECODER_MNEMONICS = {"xor", "rol", "ror", "not", "neg", "xchg", "bswap", "shl", "shr"}
_BASE64 = re.compile(r"^(?:[A-Za-z0-9+/]{4}){4,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$")
_HEX = re.compile(r"^(?:[0-9A-Fa-f]{2}){8,}$")


def _hex(value):
    return "0x%X" % int(value)


def _func_start(ea):
    func = ida_funcs.get_func(ea)
    return int(func.start_ea) if func else idaapi.BADADDR


def _func_name(ea):
    start = _func_start(ea)
    return idc.get_func_name(start) or ("sub_%X" % start if start != idaapi.BADADDR else "")


def _printable_score(data):
    if not data:
        return 0.0
    printable = sum(1 for value in data if value in (9, 10, 13) or 32 <= value < 127)
    return printable / float(len(data))


def _preview(data, limit=512):
    return data[:limit].decode("utf-8", errors="replace").replace("\x00", "\\0")


def _row(kind, ea, source="", transform="", decoded="", confidence="medium", evidence="", refs=None):
    return {
        "kind": kind, "ea": int(ea), "function": _func_name(ea), "source": str(source),
        "transform": transform, "decoded": decoded, "confidence": confidence,
        "evidence": evidence, "refs": list(refs or []),
    }


def detect_decoder_functions():
    rows = []
    for func_ea in idautils.Functions():
        name = idc.get_func_name(func_ea) or ""
        transform_sites, total = [], 0
        for ea in idautils.FuncItems(func_ea):
            total += 1
            mnemonic = (idc.print_insn_mnem(ea) or "").lower()
            if mnemonic in _DECODER_MNEMONICS:
                transform_sites.append((ea, mnemonic))
        symbol_backed = bool(_DECODER_NAME.search(name))
        ratio = len(transform_sites) / float(max(total, 1))
        if not symbol_backed and (len(transform_sites) < 3 or ratio < 0.08):
            continue
        confidence = "high" if symbol_backed else "heuristic"
        evidence = "decoder-like symbol" if symbol_backed else "%d transform instructions (%.1f%% of function)" % (len(transform_sites), ratio * 100.0)
        detail = ", ".join("%s@%s" % (mnemonic, _hex(ea)) for ea, mnemonic in transform_sites[:24])
        rows.append(_row("Decoder function", func_ea, name, "inspect / emulate", detail, confidence, evidence, []))
        if ida_kernwin.user_cancelled() or len(rows) >= _MAX_RESULTS:
            break
    return rows


def _safe_transforms(text):
    """Pure-Python transforms only: never Appcall or execute code from the IDB."""
    output = []
    compact = text.strip()
    if _BASE64.fullmatch(compact):
        try:
            data = base64.b64decode(compact, validate=True)
            if data and _printable_score(data) >= 0.65:
                output.append(("Base64", data, "high"))
        except (ValueError, binascii.Error):
            pass
    if _HEX.fullmatch(compact):
        try:
            data = bytes.fromhex(compact)
            if data and _printable_score(data) >= 0.65:
                output.append(("Hex", data, "high"))
        except ValueError:
            pass
    try:
        rot = codecs.decode(compact, "rot_13").encode("utf-8")
        if rot != compact.encode("utf-8") and re.search(rb"(?:https?://|\\|/|\.com\b|\.net\b|cmd\b|powershell\b)", rot, re.I):
            output.append(("ROT13", rot, "medium"))
    except Exception:
        pass
    raw = compact.encode("latin-1", errors="ignore")
    if 4 <= len(raw) <= 4096 and _printable_score(raw) < 0.85:
        candidates = []
        for key in range(1, 256):
            decoded = bytes(value ^ key for value in raw)
            score = _printable_score(decoded)
            common = bool(re.search(rb"(?:https?://|\.com\b|\.net\b|\\(?:windows|users)|/tmp/|cmd\.exe|powershell)", decoded, re.I))
            if score >= 0.90:
                candidates.append((common, score, key, decoded))
        for common, score, key, decoded in sorted(candidates, reverse=True)[:3]:
            output.append(("Single-byte XOR 0x%02X" % key, decoded, "medium" if common else "heuristic"))
    return output


def decode_static_candidates():
    rows = []
    for item in idautils.Strings():
        text = str(item)
        refs = [int(xref.frm) for xref in idautils.XrefsTo(int(item.ea), 0)]
        for transform, data, confidence in _safe_transforms(text):
            rows.append(_row(
                "Decoded preview", int(item.ea), text[:512], transform, _preview(data), confidence,
                "decoded by isolated built-in transform; no IDB code was executed", refs,
            ))
        if ida_kernwin.user_cancelled() or len(rows) >= _MAX_RESULTS:
            break
    return rows


def build_string_decryption_results():
    rows = detect_decoder_functions() + decode_static_candidates()
    unique = {}
    for row in rows[:_MAX_RESULTS]:
        unique[(row["kind"], row["ea"], row["transform"], row["decoded"])] = row
    return sorted(unique.values(), key=lambda row: (row["kind"], row["function"], row["ea"], row["transform"]))


class StringDecryptionWorkbench(ida_kernwin.PluginForm):
    def __init__(self):
        super().__init__()
        self.rows = []

    def OnCreate(self, form):
        self.parent = self.FormToPyQtWidget(form)
        apply_mac_workspace(self.parent)
        root = QtWidgets.QVBoxLayout(self.parent)
        root.setContentsMargins(16, 14, 16, 14)
        root.setSpacing(10)
        header = PageHeader("String Decryption Workbench", "Detect decoder routines, safely emulate common transforms, preview strings, and annotate references")
        refresh = QtWidgets.QPushButton("Scan")
        refresh.setProperty("pnVariant", "primary")
        refresh.clicked.connect(self.refresh)
        header.add_action(refresh)
        selected_bytes = QtWidgets.QPushButton("Decode Selected Bytes")
        selected_bytes.clicked.connect(self.decode_selected_bytes)
        header.add_action(selected_bytes)
        annotate = QtWidgets.QPushButton("Annotate References")
        annotate.setProperty("pnVariant", "success")
        annotate.clicked.connect(self.annotate_selected)
        header.add_action(annotate)
        export = QtWidgets.QPushButton("Export CSV")
        export.clicked.connect(self.export_csv)
        header.add_action(export)
        root.addWidget(header)
        safety = QtWidgets.QLabel("Safe mode: built-in transforms run outside the target. Native IDB functions are never executed or Appcalled.")
        safety.setProperty("pnMuted", True)
        root.addWidget(safety)
        self.filter_edit = QtWidgets.QLineEdit()
        self.filter_edit.setPlaceholderText("Filter decoder functions, transforms, source strings, previews, or evidence...")
        self.filter_edit.setClearButtonEnabled(True)
        self.filter_edit.textChanged.connect(self.apply_filter)
        root.addWidget(self.filter_edit)
        splitter = QtWidgets.QSplitter(QtCore.Qt.Horizontal)
        table_card = Card()
        self.table = QtWidgets.QTableWidget(0, 7)
        self.table.setHorizontalHeaderLabels(["Type", "Address", "Function", "Transform", "Decoded Preview", "Confidence", "Evidence"])
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
        detail_card = Card("Decode evidence")
        self.details = QtWidgets.QTextBrowser()
        detail_card.add_widget(self.details)
        splitter.addWidget(detail_card)
        splitter.setSizes([1000, 440])
        root.addWidget(splitter, 1)
        self.status = QtWidgets.QLabel("Ready")
        self.status.setProperty("pnMuted", True)
        root.addWidget(self.status)
        QtCore.QTimer.singleShot(0, self.refresh)

    def refresh(self):
        ida_kernwin.show_wait_box("Finding decoder functions and previewing safe transforms...\nPress Cancel to stop safely.")
        try:
            self.rows = build_string_decryption_results()
        except Exception as exc:
            self.rows = []
            ida_kernwin.warning("String Decryption Workbench failed:\n%s" % exc)
        finally:
            ida_kernwin.hide_wait_box()
        self.populate()

    def decode_selected_bytes(self):
        try:
            selected, start_ea, end_ea = idaapi.read_range_selection(None)
        except Exception:
            selected, start_ea, end_ea = False, idaapi.BADADDR, idaapi.BADADDR
        if not selected or start_ea == idaapi.BADADDR or end_ea <= start_ea:
            ida_kernwin.warning("Select a byte range in an IDA disassembly or hex view first.")
            return
        size = int(end_ea - start_ea)
        if size > 1024 * 1024:
            ida_kernwin.warning("The selected range is too large. Select at most 1 MiB.")
            return
        raw = ida_bytes.get_bytes(start_ea, size)
        if not raw:
            ida_kernwin.warning("IDA could not read the selected bytes.")
            return
        source = raw.decode("latin-1", errors="ignore")
        additions = []
        for transform, decoded, confidence in _safe_transforms(source):
            additions.append(_row(
                "Decoded preview", start_ea, raw.hex(), transform, _preview(decoded), confidence,
                "decoded from analyst-selected bytes by isolated built-in transform", [start_ea],
            ))
        if not additions:
            ida_kernwin.warning("No credible built-in transform preview was found for the selected bytes.")
            return
        self.rows.extend(additions)
        self.populate()
        self.status.setText("Added %d preview(s) from %d selected bytes" % (len(additions), size))

    def populate(self):
        self.table.setSortingEnabled(False)
        self.table.setRowCount(len(self.rows))
        for row_index, row in enumerate(self.rows):
            values = [row["kind"], _hex(row["ea"]), row["function"], row["transform"], row["decoded"], row["confidence"], row["evidence"]]
            for column, value in enumerate(values):
                item = QtWidgets.QTableWidgetItem(value)
                item.setData(QtCore.Qt.UserRole, row_index)
                self.table.setItem(row_index, column, item)
        self.table.resizeColumnsToContents()
        self.table.setColumnWidth(4, min(520, max(300, self.table.columnWidth(4))))
        self.table.setColumnWidth(6, max(400, self.table.columnWidth(6)))
        self.table.setSortingEnabled(True)
        self.apply_filter(self.filter_edit.text())
        previews = sum(1 for row in self.rows if row["kind"] == "Decoded preview")
        decoders = sum(1 for row in self.rows if row["kind"] == "Decoder function")
        self.status.setText("%d decoder candidates | %d decoded previews" % (decoders, previews))

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
            source = self.rows[int(self.table.item(row_index, 0).data(QtCore.Qt.UserRole))]
            haystack = " ".join(str(value) for value in source.values()).lower()
            self.table.setRowHidden(row_index, bool(needle and needle not in haystack))

    def show_details(self):
        row = self.selected_row()
        if not row:
            self.details.setPlainText("Select a decoder or decoded preview to inspect it.")
            return
        self.details.setPlainText(
            "Type: %s\nAddress: %s\nFunction: %s\nTransform: %s\nConfidence: %s\nReferences: %s\n\nSource:\n%s\n\nDecoded preview:\n%s\n\nEvidence:\n%s" % (
                row["kind"], _hex(row["ea"]), row["function"] or "N/A", row["transform"], row["confidence"],
                ", ".join(_hex(ea) for ea in row["refs"]) or "None", row["source"], row["decoded"], row["evidence"],
            )
        )

    def navigate_selected(self, *_args):
        row = self.selected_row()
        if row:
            ida_kernwin.jumpto(row["refs"][0] if row["refs"] else row["ea"])

    def annotate_selected(self):
        row = self.selected_row()
        if not row or row["kind"] != "Decoded preview" or not row["decoded"]:
            ida_kernwin.warning("Select a decoded preview before annotating references.")
            return
        targets = row["refs"] or [row["ea"]]
        answer = ida_kernwin.ask_yn(ida_kernwin.ASKBTN_NO, "Annotate %d reference(s) with this preview?\n\n%s" % (len(targets), row["decoded"][:300]))
        if answer != ida_kernwin.ASKBTN_YES:
            return
        comment = "PseudoNote decoded string [%s]: %s" % (row["transform"], row["decoded"][:1024])
        applied = sum(1 for ea in targets if ida_bytes.set_cmt(ea, comment, False))
        self.status.setText("Annotated %d of %d references" % (applied, len(targets)))

    def _csv_text(self, rows):
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["Type", "Address", "Function", "Transform", "Source", "Decoded", "Confidence", "Evidence", "References"])
        for row in rows:
            writer.writerow([row["kind"], _hex(row["ea"]), row["function"], row["transform"], row["source"], row["decoded"], row["confidence"], row["evidence"], " ".join(_hex(ea) for ea in row["refs"])])
        return output.getvalue()

    def export_csv(self):
        path, _selected = QtWidgets.QFileDialog.getSaveFileName(self.parent, "Export String Decryption Results", "string_decryption.csv", "CSV files (*.csv)")
        if path:
            with open(path, "w", encoding="utf-8-sig", newline="") as handle:
                handle.write(self._csv_text(self.rows))
            self.status.setText("Exported %d records to %s" % (len(self.rows), os.path.basename(path)))

    def OnClose(self, form):
        global _workbench
        if _workbench is self:
            _workbench = None


def show_string_decryption_workbench():
    global _workbench
    if _workbench is None:
        _workbench = StringDecryptionWorkbench()
    _workbench.Show("PseudoNote - String Decryption Workbench", options=ida_kernwin.PluginForm.WOPN_PERSIST)


class StringDecryptionWorkbenchHandler(idaapi.action_handler_t):
    def activate(self, ctx):
        show_string_decryption_workbench()
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS
