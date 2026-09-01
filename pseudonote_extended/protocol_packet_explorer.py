# -*- coding: utf-8 -*-
"""Recover C2 endpoints, protocol handlers, command IDs, and packet-layout evidence."""
import csv
import io
import ipaddress
import os
import re
from urllib.parse import urlparse

import idaapi
import ida_funcs
import ida_kernwin
import ida_nalt
import ida_ua
import idautils
import idc

from pseudonote_extended.qt_compat import QtCore, QtWidgets
from pseudonote_extended.ui.components import PageHeader, Card
from pseudonote_extended.ui.mac_workspace import apply_mac_workspace


_explorer = None
_NETWORK_API = re.compile(
    r"(?:recv|send|connect|accept|socket|bind|listen|wsarecv|wsasend|internetopen|internetread|internetwrite|"
    r"httpopen|httpsend|winhttp|urlmon|urldownload|curl_|dnsquery|getaddrinfo|websocket|ssl_read|ssl_write)", re.I,
)
_RECEIVE_API = re.compile(r"(?:recv|read|download|internetread|winhttpreaddata|ssl_read|curl_easy_perform)", re.I)
_SEND_API = re.compile(r"(?:send|write|upload|httpsend|internetwrite|winhttpwritedata|ssl_write)", re.I)
_SERIAL_API = re.compile(r"(?:ntoh|hton|byteswap|protobuf|flatbuffer|msgpack|json|xml|serialize|deserialize|pack|unpack|memcpy|copy_memory)", re.I)
_URL = re.compile(r"\b(?:https?|wss?|ftp)://[^\s\"'<>]+", re.I)
_DOMAIN = re.compile(r"(?<![\w.-])(?:[A-Za-z0-9-]{1,63}\.)+(?:com|net|org|io|dev|ru|cn|info|biz|xyz|top|local|onion)(?::\d{1,5})?(?![\w.-])", re.I)
_IP = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?(?![\d.])")
_MAX_RESULTS = 200000
_MAX_FIELDS_PER_FUNCTION = 512


def _hex(value):
    return "0x%X" % int(value)


def _func_start(ea):
    func = ida_funcs.get_func(ea)
    return int(func.start_ea) if func else idaapi.BADADDR


def _func_name(ea):
    start = _func_start(ea)
    return idc.get_func_name(start) or ("sub_%X" % start if start != idaapi.BADADDR else "")


def _is_internal_executable(ea):
    """Keep handler candidates inside executable program segments, excluding imports."""
    segment = idaapi.getseg(ea)
    if not segment:
        return False
    execute = getattr(idaapi, "SEGPERM_EXEC", 1)
    return bool(int(getattr(segment, "perm", 0)) & execute)


def _row(category, ea, value="", role="", function="", evidence="", confidence="medium", detail=""):
    return {
        "category": category, "ea": int(ea), "value": str(value), "role": role,
        "function": function or _func_name(ea), "evidence": evidence,
        "confidence": confidence, "detail": detail,
    }


def _api_calls(pattern):
    for api_ea, api_name in idautils.Names():
        if not pattern.search(api_name or ""):
            continue
        for xref in idautils.XrefsTo(api_ea, 0):
            if xref.type in (getattr(idaapi, "fl_CF", 16), getattr(idaapi, "fl_CN", 17)) and _func_start(xref.frm) != idaapi.BADADDR:
                yield int(xref.frm), int(api_ea), api_name


def scan_network_functions():
    rows, functions = [], {}
    for call_ea, api_ea, api_name in _api_calls(_NETWORK_API):
        owner = _func_start(call_ea)
        role = "receive" if _RECEIVE_API.search(api_name) else "transmit" if _SEND_API.search(api_name) else "session/setup"
        functions.setdefault(owner, set()).add(role)
        rows.append(_row("Network operation", call_ea, api_name, role, _func_name(owner), "direct call to network/protocol API", "high", idc.generate_disasm_line(call_ea, 0) or ""))
    return rows, functions


def _valid_endpoint(value):
    value = value.strip().rstrip(".,;)")
    if _URL.fullmatch(value):
        parsed = urlparse(value)
        return bool(parsed.scheme and parsed.hostname)
    host = value.rsplit(":", 1)[0] if value.count(":") == 1 else value
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return bool(_DOMAIN.fullmatch(value))


def scan_endpoints():
    rows = []
    for item in idautils.Strings():
        text = str(item)
        candidates = _URL.findall(text) + _DOMAIN.findall(text) + _IP.findall(text)
        for candidate in candidates:
            if not _valid_endpoint(candidate):
                continue
            xrefs = list(idautils.XrefsTo(int(item.ea), 0))
            if xrefs:
                for xref in xrefs:
                    rows.append(_row("C2 / endpoint", xref.frm, candidate, "endpoint reference", evidence="validated network indicator string", confidence="high", detail=text[:512]))
            else:
                rows.append(_row("C2 / endpoint", int(item.ea), candidate, "unreferenced endpoint", evidence="validated network indicator string without code xref", confidence="medium", detail=text[:512]))
    return rows


def _switch_cases(ea):
    switch = ida_nalt.get_switch_info(ea)
    if not switch:
        return []
    calculator = getattr(ida_nalt, "calc_switch_cases", None) or getattr(idaapi, "calc_switch_cases", None)
    if not calculator:
        return []
    try:
        info = calculator(ea, switch)
        cases, targets = list(getattr(info, "cases", []) or []), list(getattr(info, "targets", []) or [])
        output = []
        for index, target in enumerate(targets):
            values = list(cases[index]) if index < len(cases) else []
            output.append((values, int(target)))
        return output
    except Exception:
        return []


def scan_command_dispatch(network_functions):
    rows = []
    for func_ea, roles in network_functions.items():
        seen_values = set()
        for ea in idautils.FuncItems(func_ea):
            cases = _switch_cases(ea)
            for values, target in cases:
                for value in values[:256]:
                    value = int(value)
                    seen_values.add(value)
                    rows.append(_row("Command ID", ea, _hex(value), "switch dispatch", _func_name(func_ea), "IDA switch metadata → handler %s" % _hex(target), "high", "handler: %s (%s)" % (_func_name(target), _hex(target))))
            mnemonic = (idc.print_insn_mnem(ea) or "").lower()
            if mnemonic in ("cmp", "test", "cmn"):
                for operand in range(2):
                    if idc.get_operand_type(ea, operand) == getattr(ida_ua, "o_imm", 5):
                        value = int(idc.get_operand_value(ea, operand))
                        if 0 <= value <= 0xFFFF and value not in seen_values:
                            seen_values.add(value)
                            rows.append(_row("Command ID candidate", ea, _hex(value), "comparison", _func_name(func_ea), "small immediate compared in network-related function", "heuristic", idc.generate_disasm_line(ea, 0) or ""))
        if ida_kernwin.user_cancelled() or len(rows) >= _MAX_RESULTS:
            break
    return rows


def _dtype_size(dtype):
    getter = getattr(ida_ua, "get_dtype_size", None)
    if getter:
        try:
            return max(1, int(getter(dtype)))
        except Exception:
            pass
    return 0


def scan_packet_fields(network_functions):
    rows = []
    for func_ea, roles in network_functions.items():
        fields = {}
        for ea in idautils.FuncItems(func_ea):
            insn = ida_ua.insn_t()
            if ida_ua.decode_insn(insn, ea) <= 0:
                continue
            for index, operand in enumerate(insn.ops):
                if operand.type != getattr(ida_ua, "o_displ", 4):
                    continue
                offset = int(getattr(operand, "addr", 0))
                if not 0 <= offset <= 0x10000:
                    continue
                width = _dtype_size(getattr(operand, "dtype", 0))
                key = (offset, width)
                fields.setdefault(key, []).append((ea, idc.generate_disasm_line(ea, 0) or ""))
            if len(fields) >= _MAX_FIELDS_PER_FUNCTION:
                break
        for (offset, width), accesses in fields.items():
            evidence = "%d displacement access(es) in %s path" % (len(accesses), "/".join(sorted(roles)))
            detail = "\n".join("%s: %s" % (_hex(ea), line) for ea, line in accesses[:16])
            rows.append(_row("Packet field candidate", accesses[0][0], "+0x%X (%s bytes)" % (offset, width or "?"), "buffer field", _func_name(func_ea), evidence, "heuristic", detail))
        if ida_kernwin.user_cancelled() or len(rows) >= _MAX_RESULTS:
            break
    return rows


def scan_serialization_routines(network_functions):
    rows = []
    serial_functions = {}
    for call_ea, api_ea, api_name in _api_calls(_SERIAL_API):
        owner = _func_start(call_ea)
        serial_functions.setdefault(owner, set()).add(api_name)
        rows.append(_row("Serialization", call_ea, api_name, "serializer/deserializer primitive", _func_name(owner), "direct call to byte-order, serialization, or copy API", "high", idc.generate_disasm_line(call_ea, 0) or ""))
    # Promote serialization helpers called directly from network paths.
    for network_ea, roles in network_functions.items():
        for item_ea in idautils.FuncItems(network_ea):
            for target in idautils.CodeRefsFrom(item_ea, False):
                target_start = _func_start(target)
                if target_start in serial_functions:
                    rows.append(_row("Protocol helper", item_ea, _func_name(target_start), "/".join(sorted(roles)), _func_name(network_ea), "network path calls serialization routine", "high", ", ".join(sorted(serial_functions[target_start]))))
    return rows


def scan_request_response_handlers(network_functions):
    rows = []
    for func_ea, roles in network_functions.items():
        role = "/".join(sorted(roles))
        seen = set()
        for item_ea in idautils.FuncItems(func_ea):
            for target in idautils.CodeRefsFrom(item_ea, False):
                target_start = _func_start(target)
                if (target_start == idaapi.BADADDR or target_start == func_ea or
                        target_start in seen or not _is_internal_executable(target_start)):
                    continue
                seen.add(target_start)
                rows.append(_row("Request/response handler", item_ea, _func_name(target_start), role, _func_name(func_ea), "direct internal callee of network-related function", "medium", "handler candidate %s" % _hex(target_start)))
    return rows


def explore_protocol_and_packets():
    network_rows, network_functions = scan_network_functions()
    rows = network_rows + scan_endpoints()
    if network_functions:
        for scanner in (scan_command_dispatch, scan_packet_fields, scan_serialization_routines, scan_request_response_handlers):
            rows.extend(scanner(network_functions))
            if ida_kernwin.user_cancelled() or len(rows) >= _MAX_RESULTS:
                break
    unique = {}
    for item in rows[:_MAX_RESULTS]:
        unique[(item["category"], item["ea"], item["value"], item["role"], item["evidence"])] = item
    return sorted(unique.values(), key=lambda item: (item["category"], item["function"], item["ea"]))


class ProtocolPacketExplorer(ida_kernwin.PluginForm):
    def __init__(self):
        super().__init__()
        self.rows = []

    def OnCreate(self, form):
        self.parent = self.FormToPyQtWidget(form)
        apply_mac_workspace(self.parent)
        root = QtWidgets.QVBoxLayout(self.parent)
        root.setContentsMargins(16, 14, 16, 14)
        root.setSpacing(10)
        header = PageHeader("C2, Protocol and Packet Explorer", "Endpoints, message layouts, command IDs, serialization, and request/response handlers")
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
        self.filter_edit.setPlaceholderText("Filter endpoints, command IDs, packet offsets, APIs, handlers, or evidence…")
        self.filter_edit.setClearButtonEnabled(True)
        self.filter_edit.textChanged.connect(self.apply_filter)
        root.addWidget(self.filter_edit)
        splitter = QtWidgets.QSplitter(QtCore.Qt.Horizontal)
        table_card = Card()
        self.table = QtWidgets.QTableWidget(0, 7)
        self.table.setHorizontalHeaderLabels(["Category", "Address", "Function", "Value", "Role", "Confidence", "Evidence"])
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
        detail_card = Card("Protocol evidence")
        self.details = QtWidgets.QTextBrowser()
        detail_card.add_widget(self.details)
        splitter.addWidget(detail_card)
        splitter.setSizes([1000, 430])
        root.addWidget(splitter, 1)
        self.status = QtWidgets.QLabel("Ready")
        self.status.setProperty("pnMuted", True)
        root.addWidget(self.status)
        QtCore.QTimer.singleShot(0, self.refresh)

    def refresh(self):
        ida_kernwin.show_wait_box("Recovering C2 and protocol behavior…\nPress Cancel to stop safely.")
        try:
            self.rows = explore_protocol_and_packets()
        except Exception as exc:
            self.rows = []
            ida_kernwin.warning("C2, Protocol and Packet Explorer failed:\n%s" % exc)
        finally:
            ida_kernwin.hide_wait_box()
        self.populate()

    def populate(self):
        self.table.setSortingEnabled(False)
        self.table.setRowCount(len(self.rows))
        for row_index, row in enumerate(self.rows):
            values = [row["category"], _hex(row["ea"]), row["function"], row["value"], row["role"], row["confidence"], row["evidence"]]
            for column, value in enumerate(values):
                item = QtWidgets.QTableWidgetItem(value)
                item.setData(QtCore.Qt.UserRole, row_index)
                self.table.setItem(row_index, column, item)
        self.table.resizeColumnsToContents()
        self.table.setColumnWidth(6, max(420, self.table.columnWidth(6)))
        self.table.setSortingEnabled(True)
        self.apply_filter(self.filter_edit.text())
        counts = {}
        for row in self.rows:
            counts[row["category"]] = counts.get(row["category"], 0) + 1
        self.status.setText("%d protocol records • %s" % (len(self.rows), " • ".join("%s: %d" % item for item in sorted(counts.items()))))

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
            source = self.rows[int(self.table.item(row, 0).data(QtCore.Qt.UserRole))]
            haystack += " " + source["detail"].lower()
            self.table.setRowHidden(row, bool(needle and needle not in haystack))

    def show_details(self):
        row = self.selected_row()
        if not row:
            self.details.setPlainText("Select a protocol record to inspect its evidence.")
            return
        self.details.setPlainText("Category: %s\nAddress: %s\nFunction: %s\nValue: %s\nRole: %s\nConfidence: %s\n\nEvidence: %s\n\nDetails:\n%s\n\nPacket fields and comparison-based command IDs are structural candidates requiring analyst validation." % (row["category"], _hex(row["ea"]), row["function"] or "N/A", row["value"], row["role"], row["confidence"], row["evidence"], row["detail"]))

    def navigate_selected(self, *_args):
        row = self.selected_row()
        if row:
            ida_kernwin.jumpto(row["ea"])

    def _csv_text(self, rows):
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["Category", "Address", "Function", "Value", "Role", "Confidence", "Evidence", "Details"])
        for row in rows:
            writer.writerow([row["category"], _hex(row["ea"]), row["function"], row["value"], row["role"], row["confidence"], row["evidence"], row["detail"]])
        return output.getvalue()

    def copy_selected(self):
        row = self.selected_row()
        if row:
            QtWidgets.QApplication.clipboard().setText(self._csv_text([row]))
            self.status.setText("Copied selected protocol record")

    def export_csv(self):
        path, _selected = QtWidgets.QFileDialog.getSaveFileName(self.parent, "Export C2 and Protocol Results", "c2_protocol_packets.csv", "CSV files (*.csv)")
        if path:
            with open(path, "w", encoding="utf-8-sig", newline="") as handle:
                handle.write(self._csv_text(self.rows))
            self.status.setText("Exported %d records to %s" % (len(self.rows), os.path.basename(path)))

    def OnClose(self, form):
        global _explorer
        if _explorer is self:
            _explorer = None


def show_protocol_packet_explorer():
    global _explorer
    if _explorer is None:
        _explorer = ProtocolPacketExplorer()
    _explorer.Show("PseudoNote - C2, Protocol and Packet Explorer", options=ida_kernwin.PluginForm.WOPN_PERSIST)


class ProtocolPacketExplorerHandler(idaapi.action_handler_t):
    def activate(self, ctx):
        show_protocol_packet_explorer()
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS
