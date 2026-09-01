# -*- coding: utf-8 -*-
"""Evidence-scored crypto, hash, encoding, compression, and decoder detector."""
import base64
import csv
import io
import math
import os
import re

import idaapi
import ida_bytes
import ida_funcs
import ida_kernwin
import ida_segment
import ida_ua
import idautils
import idc

from pseudonote_extended.qt_compat import QtCore, QtWidgets
from pseudonote_extended.ui.components import PageHeader, Card
from pseudonote_extended.ui.mac_workspace import apply_mac_workspace


_explorer = None
_MAX_RESULTS = 200000
_MAX_DATA_SCAN = 512 * 1024 * 1024
_CRYPTO_API = re.compile(
    r"(?:crypt|bcrypt|ncrypt|openssl|evp_|aes|des|rc4|chacha|salsa|sha\d*|md5|hmac|pbkdf|argon|scrypt|"
    r"base64|encode|decode|inflate|deflate|zlib|gzip|lzma|lzo|zstd|brotli|compress|uncompress)", re.I,
)
_BASE64_TEXT = re.compile(r"^[A-Za-z0-9+/]{16,}={0,2}$")
_KNOWN_CONSTANTS = {
    0x9E3779B9: ("TEA/XTEA", "delta constant"), 0xC6EF3720: ("TEA/XTEA", "32-round sum"),
    0x67452301: ("MD5/SHA-1", "initial state"), 0xEFCDAB89: ("MD5/SHA-1", "initial state"),
    0x98BADCFE: ("MD5", "initial state"), 0x10325476: ("MD5", "initial state"),
    0x6A09E667: ("SHA-256", "initial state"), 0xBB67AE85: ("SHA-256", "initial state"),
    0x3C6EF372: ("SHA-256", "initial state"), 0xA54FF53A: ("SHA-256", "initial state"),
    0xEDB88320: ("CRC-32", "reflected polynomial"), 0x04C11DB7: ("CRC-32", "polynomial"),
    0x811C9DC5: ("FNV-1a", "offset basis"), 0x01000193: ("FNV-1a", "prime"),
    0x5BD1E995: ("MurmurHash", "mix constant"), 0xCC9E2D51: ("MurmurHash3", "mix constant"),
    0x1B873593: ("MurmurHash3", "mix constant"), 0x9E3779B1: ("xxHash", "prime"),
}
_ALGORITHM_MIN_HITS = {"TEA/XTEA": 1, "MD5/SHA-1": 2, "MD5": 2, "SHA-256": 2, "CRC-32": 1, "FNV-1a": 2, "MurmurHash": 1, "MurmurHash3": 1, "xxHash": 1}
_SIGNATURES = (
    ("AES", bytes.fromhex("63 7C 77 7B F2 6B 6F C5 30 01 67 2B FE D7 AB 76"), "AES S-box prefix"),
    ("Base64", b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", "standard alphabet"),
    ("ChaCha/Salsa", b"expand 32-byte k", "sigma constant"),
)


def _hex(ea):
    return "0x%X" % int(ea)


def _func_start(ea):
    func = ida_funcs.get_func(ea)
    return int(func.start_ea) if func else idaapi.BADADDR


def _func_name(ea):
    start = _func_start(ea)
    return idc.get_func_name(start) or ("sub_%X" % start if start != idaapi.BADADDR else "")


def _row(category, algorithm, ea, evidence, confidence="medium", function="", detail=""):
    return {
        "category": category, "algorithm": algorithm, "ea": int(ea),
        "function": function or _func_name(ea), "evidence": evidence,
        "confidence": confidence, "detail": detail,
    }


def _entropy(data):
    if not data:
        return 0.0
    counts = {}
    for value in data:
        counts[value] = counts.get(value, 0) + 1
    size = float(len(data))
    return -sum((count / size) * math.log(count / size, 2) for count in counts.values())


def scan_crypto_apis():
    rows = []
    for api_ea, api_name in idautils.Names():
        if not _CRYPTO_API.search(api_name or ""):
            continue
        for xref in idautils.XrefsTo(api_ea, 0):
            if xref.type not in (getattr(idaapi, "fl_CF", 16), getattr(idaapi, "fl_CN", 17)):
                continue
            lowered = api_name.lower()
            category = "Compression" if re.search(r"inflate|deflate|zlib|gzip|lzma|lzo|zstd|brotli|compress", lowered) else "Encoding" if "base64" in lowered or "encode" in lowered or "decode" in lowered else "Cryptographic API"
            rows.append(_row(category, api_name, xref.frm, "direct call to recognized crypto/encoding/compression API", "high", detail=idc.generate_disasm_line(xref.frm, 0) or ""))
    return rows


def analyze_function_patterns():
    rows = []
    for func_ea in idautils.Functions():
        counts = {"xor": 0, "rotate": 0, "shift": 0, "addsub": 0, "loop": 0, "table": 0}
        constants = {}
        first_xor = idaapi.BADADDR
        for ea in idautils.FuncItems(func_ea):
            mnemonic = (idc.print_insn_mnem(ea) or "").lower()
            if mnemonic.startswith("xor") or mnemonic in ("eor", "pxor", "veor"):
                counts["xor"] += 1
                if first_xor == idaapi.BADADDR:
                    first_xor = ea
            elif mnemonic.startswith(("rol", "ror", "rcl", "rcr")):
                counts["rotate"] += 1
            elif mnemonic.startswith(("shl", "shr", "sar", "lsl", "lsr")):
                counts["shift"] += 1
            elif mnemonic.startswith(("add", "sub")):
                counts["addsub"] += 1
            for target in idautils.CodeRefsFrom(ea, False):
                if func_ea <= target < ea:
                    counts["loop"] += 1
            for operand in range(4):
                operand_type = idc.get_operand_type(ea, operand)
                if operand_type == getattr(ida_ua, "o_imm", 5):
                    value = int(idc.get_operand_value(ea, operand)) & 0xFFFFFFFF
                    if value in _KNOWN_CONSTANTS:
                        constants.setdefault(_KNOWN_CONSTANTS[value][0], []).append((value, ea, _KNOWN_CONSTANTS[value][1]))
                elif operand_type in (getattr(ida_ua, "o_mem", 2), getattr(ida_ua, "o_displ", 4)):
                    counts["table"] += 1
        for algorithm, hits in constants.items():
            required = _ALGORITHM_MIN_HITS.get(algorithm, 1)
            if len({value for value, _ea, _label in hits}) >= required:
                evidence = ", ".join("0x%08X at %s (%s)" % (value, _hex(ea), label) for value, ea, label in hits[:12])
                confidence = "high" if len({value for value, _ea, _label in hits}) > required or algorithm in ("TEA/XTEA", "CRC-32", "FNV-1a") else "medium"
                rows.append(_row("Known constants", algorithm, func_ea, evidence, confidence, _func_name(func_ea), "Instruction mix: %s" % counts))
        mixing = counts["xor"] + counts["rotate"] + counts["shift"] + counts["addsub"]
        if counts["loop"] and counts["xor"] and mixing >= 4:
            algorithm = "XOR/rolling decoder" if counts["rotate"] + counts["shift"] < 2 else "Custom encoding/crypto loop"
            rows.append(_row("Custom routine", algorithm, first_xor if first_xor != idaapi.BADADDR else func_ea, "%d XOR, %d rotate, %d shift, %d arithmetic operations, %d backward edges" % (counts["xor"], counts["rotate"], counts["shift"], counts["addsub"], counts["loop"]), "medium", _func_name(func_ea), "Pattern evidence only; review loop inputs and output buffer."))
        elif counts["loop"] and counts["rotate"] + counts["shift"] >= 3 and counts["xor"] >= 1:
            rows.append(_row("Hash candidate", "Custom hash/mixer", func_ea, "rotate/shift/XOR mixing inside a loop", "low", _func_name(func_ea), "No unique standard constant set was found."))
        if ida_kernwin.user_cancelled() or len(rows) >= _MAX_RESULTS:
            break
    return rows


def scan_data_signatures():
    rows, scanned = [], 0
    chunk_size = 1024 * 1024
    overlap = max(len(signature) for _name, signature, _label in _SIGNATURES) - 1
    for seg_ea in idautils.Segments():
        segment = ida_segment.getseg(seg_ea)
        if not segment or not (segment.perm & ida_segment.SEGPERM_READ):
            continue
        cursor = int(segment.start_ea)
        tail = b""
        while cursor < segment.end_ea:
            if scanned >= _MAX_DATA_SCAN or len(rows) >= _MAX_RESULTS or ida_kernwin.user_cancelled():
                return rows
            size = min(chunk_size, int(segment.end_ea - cursor), _MAX_DATA_SCAN - scanned)
            data = ida_bytes.get_bytes(cursor, size) or b""
            combined = tail + data
            base = cursor - len(tail)
            for algorithm, signature, label in _SIGNATURES:
                position = combined.find(signature)
                while position >= 0:
                    ea = base + position
                    rows.append(_row("Exact signature", algorithm, ea, label, "high", detail="%d-byte exact signature" % len(signature)))
                    position = combined.find(signature, position + 1)
            tail = combined[-overlap:] if overlap else b""
            cursor += size
            scanned += size
    return rows


def scan_data_constants():
    rows, scanned = [], 0
    for seg_ea in idautils.Segments():
        segment = ida_segment.getseg(seg_ea)
        if not segment or (segment.perm & ida_segment.SEGPERM_EXEC):
            continue
        ea = (int(segment.start_ea) + 3) & ~3
        while ea + 4 <= segment.end_ea:
            if scanned >= _MAX_DATA_SCAN or len(rows) >= _MAX_RESULTS or ida_kernwin.user_cancelled():
                return rows
            value = int(ida_bytes.get_dword(ea)) & 0xFFFFFFFF
            if value in _KNOWN_CONSTANTS:
                algorithm, label = _KNOWN_CONSTANTS[value]
                rows.append(_row("Constant table", algorithm, ea, "0x%08X (%s)" % (value, label), "medium"))
            ea += 4
            scanned += 4
    return rows


def scan_encoded_strings():
    rows = []
    for item in idautils.Strings():
        text = str(item).strip()
        if text == "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/":
            continue
        if not _BASE64_TEXT.fullmatch(text) or len(text) % 4:
            continue
        try:
            decoded = base64.b64decode(text, validate=True)
        except Exception:
            continue
        if len(decoded) < 8:
            continue
        printable = sum(1 for value in decoded if value in (9, 10, 13) or 32 <= value < 127) / float(len(decoded))
        evidence = "valid Base64; %d decoded bytes; entropy %.2f; printable %.0f%%" % (len(decoded), _entropy(decoded), printable * 100)
        rows.append(_row("Encoded string", "Base64", int(item.ea), evidence, "medium", detail=decoded[:128].decode("utf-8", "replace")))
        if len(rows) >= _MAX_RESULTS or ida_kernwin.user_cancelled():
            break
    return rows


def explore_crypto_and_encoding():
    rows = []
    for scanner in (scan_crypto_apis, analyze_function_patterns, scan_data_signatures, scan_data_constants, scan_encoded_strings):
        rows.extend(scanner())
        if ida_kernwin.user_cancelled() or len(rows) >= _MAX_RESULTS:
            break
    unique = {}
    for item in rows[:_MAX_RESULTS]:
        unique[(item["category"], item["algorithm"], item["ea"], item["evidence"])] = item
    return sorted(unique.values(), key=lambda item: (item["algorithm"].lower(), item["category"], item["ea"]))


class CryptoEncodingExplorer(ida_kernwin.PluginForm):
    def __init__(self):
        super().__init__()
        self.rows = []

    def OnCreate(self, form):
        self.parent = self.FormToPyQtWidget(form)
        apply_mac_workspace(self.parent)
        root = QtWidgets.QVBoxLayout(self.parent)
        root.setContentsMargins(16, 14, 16, 14)
        root.setSpacing(10)
        header = PageHeader("Crypto and Encoding Explorer", "Cryptographic constants, algorithms, XOR loops, hashes, Base64, compression, and custom decoders")
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
        self.filter_edit.setPlaceholderText("Filter algorithms, APIs, constants, functions, encodings, or evidence…")
        self.filter_edit.setClearButtonEnabled(True)
        self.filter_edit.textChanged.connect(self.apply_filter)
        root.addWidget(self.filter_edit)
        splitter = QtWidgets.QSplitter(QtCore.Qt.Horizontal)
        table_card = Card()
        self.table = QtWidgets.QTableWidget(0, 7)
        self.table.setHorizontalHeaderLabels(["Category", "Algorithm / family", "Address", "Function", "Confidence", "Evidence", "Details"])
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
        detail_card = Card("Detection evidence")
        self.details = QtWidgets.QTextBrowser()
        detail_card.add_widget(self.details)
        splitter.addWidget(detail_card)
        splitter.setSizes([1000, 420])
        root.addWidget(splitter, 1)
        self.status = QtWidgets.QLabel("Ready")
        self.status.setProperty("pnMuted", True)
        root.addWidget(self.status)
        QtCore.QTimer.singleShot(0, self.refresh)

    def refresh(self):
        ida_kernwin.show_wait_box("Detecting cryptography, encoding, and compression…\nPress Cancel to stop safely.")
        try:
            self.rows = explore_crypto_and_encoding()
        except Exception as exc:
            self.rows = []
            ida_kernwin.warning("Crypto and Encoding Explorer failed:\n%s" % exc)
        finally:
            ida_kernwin.hide_wait_box()
        self.populate()

    def populate(self):
        self.table.setSortingEnabled(False)
        self.table.setRowCount(len(self.rows))
        for row_index, row in enumerate(self.rows):
            values = [row["category"], row["algorithm"], _hex(row["ea"]), row["function"], row["confidence"], row["evidence"], row["detail"]]
            for column, value in enumerate(values):
                item = QtWidgets.QTableWidgetItem(value)
                item.setData(QtCore.Qt.UserRole, row_index)
                self.table.setItem(row_index, column, item)
        self.table.resizeColumnsToContents()
        self.table.setColumnWidth(5, max(400, self.table.columnWidth(5)))
        self.table.setSortingEnabled(True)
        self.apply_filter(self.filter_edit.text())
        counts = {}
        for row in self.rows:
            counts[row["algorithm"]] = counts.get(row["algorithm"], 0) + 1
        self.status.setText("%d detections • %s" % (len(self.rows), " • ".join("%s: %d" % item for item in sorted(counts.items())[:16])))

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
            haystack = " ".join(self.table.item(row, column).text() for column in range(self.table.columnCount()) if self.table.item(row, column)).lower()
            self.table.setRowHidden(row, bool(needle and needle not in haystack))

    def show_details(self):
        row = self.selected_row()
        if not row:
            self.details.setPlainText("Select a detection to inspect its evidence and confidence.")
            return
        self.details.setPlainText("Category: %s\nAlgorithm / family: %s\nAddress: %s\nFunction: %s\nConfidence: %s\n\nEvidence: %s\n\nDetails:\n%s\n\nPattern-only custom routines require analyst confirmation." % (row["category"], row["algorithm"], _hex(row["ea"]), row["function"] or "N/A", row["confidence"], row["evidence"], row["detail"]))

    def navigate_selected(self, *_args):
        row = self.selected_row()
        if row:
            ida_kernwin.jumpto(row["ea"])

    def _csv_text(self, rows):
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["Category", "Algorithm", "Address", "Function", "Confidence", "Evidence", "Details"])
        for row in rows:
            writer.writerow([row["category"], row["algorithm"], _hex(row["ea"]), row["function"], row["confidence"], row["evidence"], row["detail"]])
        return output.getvalue()

    def copy_selected(self):
        row = self.selected_row()
        if row:
            QtWidgets.QApplication.clipboard().setText(self._csv_text([row]))
            self.status.setText("Copied selected detection")

    def export_csv(self):
        path, _selected = QtWidgets.QFileDialog.getSaveFileName(self.parent, "Export Crypto and Encoding Results", "crypto_encoding.csv", "CSV files (*.csv)")
        if path:
            with open(path, "w", encoding="utf-8-sig", newline="") as handle:
                handle.write(self._csv_text(self.rows))
            self.status.setText("Exported %d detections to %s" % (len(self.rows), os.path.basename(path)))

    def OnClose(self, form):
        global _explorer
        if _explorer is self:
            _explorer = None


def show_crypto_encoding_explorer():
    global _explorer
    if _explorer is None:
        _explorer = CryptoEncodingExplorer()
    _explorer.Show("PseudoNote - Crypto and Encoding Explorer", options=ida_kernwin.PluginForm.WOPN_PERSIST)


class CryptoEncodingExplorerHandler(idaapi.action_handler_t):
    def activate(self, ctx):
        show_crypto_encoding_explorer()
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS
