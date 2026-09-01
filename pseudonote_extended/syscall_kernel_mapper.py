# -*- coding: utf-8 -*-
"""Map syscalls, IOCTLs, device interfaces, callbacks, and kernel trust boundaries."""
import csv
import io
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


_mapper = None
_SYSCALL_MNEMONICS = {"syscall", "sysenter", "svc", "swi", "ecall", "sc"}
_NATIVE_API = re.compile(r"^(?:__imp_|_imp__)?(?:Nt|Zw)[A-Z]", re.I)
_DEVICE_API = re.compile(r"(?:deviceiocontrol|ntdeviceiocontrolfile|createdevice|createfile|openfile|iokit|io_connect|ioctl)", re.I)
_KERNEL_CALLBACK_API = re.compile(
    r"(?:pssetcreate(?:process|thread|image)notifyroutine|obregistercallbacks|cmregistercallback|"
    r"exregistercallback|ioregisterplugplaynotification|keinitialize(?:dpc|timer)|iosetcompletionroutine|"
    r"wdf.*callback|register.*notify|set.*callback)", re.I,
)
_TRUST_API = re.compile(
    r"(?:probeforread|probeforwrite|mmcopymemory|copy_from_user|copy_to_user|get_user|put_user|"
    r"access_ok|copyin|copyout|mprobe|seprobe|capture.*buffer|mapuser|lockpages)", re.I,
)
_DRIVER_HANDLER = re.compile(r"(?:driverentry|dispatch|majorfunction|devicecontrol|internaldevicecontrol|irp_mj|ioctl|unlocked_ioctl|compat_ioctl)", re.I)
_DEVICE_PATH = re.compile(r"(?:\\\\\.\\|\\device\\|\\dosdevices\\|\\global\?\?\\|/dev/|ioregistry|iokit)", re.I)
_MAX_RESULTS = 200000


def _hex(value):
    return "0x%X" % int(value)


def _func_start(ea):
    func = ida_funcs.get_func(ea)
    return int(func.start_ea) if func else idaapi.BADADDR


def _func_name(ea):
    start = _func_start(ea)
    return idc.get_func_name(start) or ("sub_%X" % start if start != idaapi.BADADDR else "")


def _owner(ea):
    name = _func_name(ea)
    start = _func_start(ea)
    return "%s (%s)" % (name, _hex(start)) if name else "<outside function>"


def _row(category, site, interface="", value=None, target=idaapi.BADADDR, evidence="", confidence="high", detail=""):
    return {
        "category": category, "site": int(site), "owner": _owner(site), "interface": interface,
        "value": value, "target": int(target), "target_name": _func_name(target) if target != idaapi.BADADDR else "",
        "evidence": evidence, "confidence": confidence, "detail": detail,
    }


def _same_function_backwards(ea, limit=12):
    owner = _func_start(ea)
    cursor = int(ea)
    for _index in range(limit):
        cursor = idc.prev_head(cursor)
        if cursor == idaapi.BADADDR or _func_start(cursor) != owner:
            break
        yield cursor


def _nearby_immediates(ea, limit=12):
    values = []
    for cursor in _same_function_backwards(ea, limit):
        for operand in range(3):
            if idc.get_operand_type(cursor, operand) == getattr(ida_ua, "o_imm", 5):
                values.append((int(idc.get_operand_value(cursor, operand)), cursor, idc.print_operand(cursor, operand)))
    return values


def _nearby_functions(ea, limit=14):
    found = {}
    for cursor in _same_function_backwards(ea, limit):
        for operand in range(3):
            if idc.get_operand_type(cursor, operand) in (
                getattr(ida_ua, "o_imm", 5), getattr(ida_ua, "o_mem", 2),
                getattr(ida_ua, "o_near", 7), getattr(ida_ua, "o_far", 6),
            ):
                value = idc.get_operand_value(cursor, operand)
                start = _func_start(value)
                if start != idaapi.BADADDR:
                    found[start] = cursor
    return found


def _syscall_number(ea):
    register_pattern = re.compile(r"^(?:e?ax|r7|x8|w8|a7)$", re.I)
    for cursor in _same_function_backwards(ea, 10):
        if idc.print_insn_mnem(cursor).lower() not in ("mov", "movz", "li", "addi", "addiu"):
            continue
        if register_pattern.match(idc.print_operand(cursor, 0) or "") and idc.get_operand_type(cursor, 1) == getattr(ida_ua, "o_imm", 5):
            return int(idc.get_operand_value(cursor, 1)), cursor
    return None, idaapi.BADADDR


def scan_direct_syscalls():
    rows = []
    for func_ea in idautils.Functions():
        for ea in idautils.FuncItems(func_ea):
            mnemonic = (idc.print_insn_mnem(ea) or "").lower()
            is_int2e = mnemonic == "int" and "2eh" in (idc.print_operand(ea, 0) or "").lower()
            if mnemonic not in _SYSCALL_MNEMONICS and not is_int2e:
                continue
            number, setup = _syscall_number(ea)
            evidence = "direct %s instruction" % mnemonic
            if setup != idaapi.BADADDR:
                evidence += "; syscall number loaded at %s" % _hex(setup)
            rows.append(_row("Direct syscall", ea, mnemonic, number, evidence=evidence, confidence="high" if number is not None else "number unresolved", detail=idc.generate_disasm_line(ea, 0) or ""))
    return rows


def _api_calls(pattern):
    for api_ea, api_name in idautils.Names():
        if not pattern.search(api_name or ""):
            continue
        for xref in idautils.XrefsTo(api_ea, 0):
            if xref.type in (getattr(idaapi, "fl_CF", 16), getattr(idaapi, "fl_CN", 17)) and _func_start(xref.frm) != idaapi.BADADDR:
                yield int(xref.frm), int(api_ea), api_name


def scan_native_interfaces():
    return [_row("Native kernel interface", call, name, target=api, evidence="direct call to Nt/Zw interface", confidence="high", detail=idc.generate_disasm_line(call, 0) or "") for call, api, name in _api_calls(_NATIVE_API)]


def decode_ioctl(code):
    code = int(code) & 0xFFFFFFFF
    return {
        "device_type": (code >> 16) & 0xFFFF,
        "access": (code >> 14) & 0x3,
        "function": (code >> 2) & 0xFFF,
        "method": code & 0x3,
    }


def _plausible_ioctl(value):
    value = int(value) & 0xFFFFFFFF
    decoded = decode_ioctl(value)
    return value >= 0x10000 and decoded["function"] != 0


def scan_device_and_ioctls():
    rows = []
    for call, api, name in _api_calls(_DEVICE_API):
        candidates = [(value, setup) for value, setup, _text in _nearby_immediates(call, 16) if _plausible_ioctl(value)]
        if "ioctl" in name.lower() and candidates:
            value, setup = candidates[0]
            fields = decode_ioctl(value)
            detail = "CTL_CODE device=0x%X function=0x%X method=%d access=%d; setup %s" % (fields["device_type"], fields["function"], fields["method"], fields["access"], _hex(setup))
            rows.append(_row("IOCTL", call, name, value, api, "immediate control code near device-control call", "inferred argument", detail))
        else:
            rows.append(_row("Device communication", call, name, target=api, evidence="call to device/kernel communication API", confidence="high", detail=idc.generate_disasm_line(call, 0) or ""))
    return rows


def scan_device_paths():
    rows = []
    strings = idautils.Strings()
    for item in strings:
        text = str(item)
        if not _DEVICE_PATH.search(text):
            continue
        xrefs = list(idautils.XrefsTo(int(item.ea), 0))
        if xrefs:
            for xref in xrefs:
                rows.append(_row("Device endpoint", xref.frm, text, target=int(item.ea), evidence="reference to device path string", confidence="high"))
        else:
            rows.append(_row("Device endpoint", int(item.ea), text, target=int(item.ea), evidence="device path string", confidence="high"))
    return rows


def scan_kernel_callbacks():
    rows = []
    for call, api, name in _api_calls(_KERNEL_CALLBACK_API):
        candidates = _nearby_functions(call)
        if candidates:
            for target, setup in candidates.items():
                rows.append(_row("Kernel callback", call, name, target=target, evidence="function address prepared before callback registration", confidence="inferred argument", detail="setup at %s" % _hex(setup)))
        else:
            rows.append(_row("Kernel callback", call, name, target=api, evidence="callback registration call; callback target unresolved", confidence="unresolved"))
    return rows


def scan_trust_boundaries():
    rows = []
    for call, api, name in _api_calls(_TRUST_API):
        rows.append(_row("User/kernel trust boundary", call, name, target=api, evidence="user-memory validation or copy primitive", confidence="high", detail=idc.generate_disasm_line(call, 0) or ""))
    for ea in idautils.Functions():
        name = idc.get_func_name(ea) or ""
        if _DRIVER_HANDLER.search(name):
            rows.append(_row("Driver dispatch", ea, name, target=ea, evidence="driver/IOCTL dispatch naming pattern", confidence="symbol-backed"))
    return rows


def scan_driver_dispatch_tables():
    """Recover handlers assigned near named DriverObject/MajorFunction storage."""
    rows = []
    for object_ea, object_name in idautils.Names():
        if not re.search(r"(?:majorfunction|driverobject|dispatchtable|irp_mj)", object_name or "", re.I):
            continue
        for xref in idautils.XrefsTo(object_ea, 0):
            if _func_start(xref.frm) == idaapi.BADADDR:
                continue
            candidates = _nearby_functions(xref.frm, 10)
            if candidates:
                for target, setup in candidates.items():
                    rows.append(_row("Driver dispatch", xref.frm, object_name, target=target, evidence="function address assigned near driver dispatch storage", confidence="inferred assignment", detail="handler setup at %s" % _hex(setup)))
            else:
                rows.append(_row("Driver dispatch", xref.frm, object_name, target=object_ea, evidence="reference to driver dispatch storage; handler unresolved", confidence="unresolved"))
    return rows


def map_syscalls_and_kernel_interfaces():
    rows = []
    for scanner in (scan_direct_syscalls, scan_native_interfaces, scan_device_and_ioctls, scan_device_paths, scan_kernel_callbacks, scan_trust_boundaries, scan_driver_dispatch_tables):
        rows.extend(scanner())
        if ida_kernwin.user_cancelled() or len(rows) >= _MAX_RESULTS:
            break
    unique = {}
    for item in rows[:_MAX_RESULTS]:
        unique[(item["category"], item["site"], item["interface"], item["value"], item["target"])] = item
    return sorted(unique.values(), key=lambda item: (item["category"], item["site"], item["interface"]))


class SyscallKernelInterfaceMapper(ida_kernwin.PluginForm):
    def __init__(self):
        super().__init__()
        self.rows = []

    def OnCreate(self, form):
        self.parent = self.FormToPyQtWidget(form)
        apply_mac_workspace(self.parent)
        root = QtWidgets.QVBoxLayout(self.parent)
        root.setContentsMargins(16, 14, 16, 14)
        root.setSpacing(10)
        header = PageHeader("Syscall and Kernel Interface Mapper", "Direct syscalls, IOCTLs, devices, kernel callbacks, and user/kernel trust boundaries")
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
        self.filter_edit.setPlaceholderText("Filter syscalls, IOCTLs, device paths, callbacks, dispatch routines, or trust boundaries…")
        self.filter_edit.setClearButtonEnabled(True)
        self.filter_edit.textChanged.connect(self.apply_filter)
        root.addWidget(self.filter_edit)
        splitter = QtWidgets.QSplitter(QtCore.Qt.Horizontal)
        table_card = Card()
        self.table = QtWidgets.QTableWidget(0, 8)
        self.table.setHorizontalHeaderLabels(["Category", "Site", "Function", "Interface", "Value", "Target", "Confidence", "Evidence"])
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
        detail_card = Card("Kernel-interface evidence")
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
        ida_kernwin.show_wait_box("Mapping syscalls and kernel interfaces…\nPress Cancel to stop safely.")
        try:
            self.rows = map_syscalls_and_kernel_interfaces()
        except Exception as exc:
            self.rows = []
            ida_kernwin.warning("Syscall and Kernel Interface Mapper failed:\n%s" % exc)
        finally:
            ida_kernwin.hide_wait_box()
        self.populate()

    def populate(self):
        self.table.setSortingEnabled(False)
        self.table.setRowCount(len(self.rows))
        for row_index, row in enumerate(self.rows):
            value = _hex(row["value"]) if isinstance(row["value"], int) else "—"
            target = _hex(row["target"]) if row["target"] != idaapi.BADADDR else "—"
            values = [row["category"], _hex(row["site"]), row["owner"], row["interface"], value, target, row["confidence"], row["evidence"]]
            for column, text in enumerate(values):
                item = QtWidgets.QTableWidgetItem(text)
                item.setData(QtCore.Qt.UserRole, row_index)
                self.table.setItem(row_index, column, item)
        self.table.resizeColumnsToContents()
        self.table.setColumnWidth(7, max(380, self.table.columnWidth(7)))
        self.table.setSortingEnabled(True)
        self.apply_filter(self.filter_edit.text())
        counts = {}
        for row in self.rows:
            counts[row["category"]] = counts.get(row["category"], 0) + 1
        self.status.setText("%d interfaces • %s" % (len(self.rows), " • ".join("%s: %d" % item for item in sorted(counts.items()))))

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
            haystack += " " + source["detail"].lower() + " " + source["target_name"].lower()
            self.table.setRowHidden(row, bool(needle and needle not in haystack))

    def show_details(self):
        row = self.selected_row()
        if not row:
            self.details.setPlainText("Select a mapped interface to inspect its evidence.")
            return
        ioctl_detail = ""
        if row["category"] == "IOCTL" and isinstance(row["value"], int):
            fields = decode_ioctl(row["value"])
            ioctl_detail = "\nDecoded IOCTL: device type 0x%X, function 0x%X, method %d, access %d" % (fields["device_type"], fields["function"], fields["method"], fields["access"])
        self.details.setPlainText(
            "Category: %s\nSite: %s\nFunction: %s\nInterface: %s\nValue: %s\nTarget: %s %s\nConfidence: %s%s\n\nEvidence: %s\n\nDetails:\n%s" % (
                row["category"], _hex(row["site"]), row["owner"], row["interface"],
                _hex(row["value"]) if isinstance(row["value"], int) else "N/A",
                _hex(row["target"]) if row["target"] != idaapi.BADADDR else "N/A", row["target_name"],
                row["confidence"], ioctl_detail, row["evidence"], row["detail"],
            )
        )

    def navigate_selected(self, *_args):
        row = self.selected_row()
        if row:
            ida_kernwin.jumpto(row["site"])

    def _csv_text(self, rows):
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["Category", "Site", "Function", "Interface", "Value", "Target", "Target name", "Confidence", "Evidence", "Detail"])
        for row in rows:
            writer.writerow([row["category"], _hex(row["site"]), row["owner"], row["interface"], _hex(row["value"]) if isinstance(row["value"], int) else "", _hex(row["target"]) if row["target"] != idaapi.BADADDR else "", row["target_name"], row["confidence"], row["evidence"], row["detail"]])
        return output.getvalue()

    def copy_selected(self):
        row = self.selected_row()
        if row:
            QtWidgets.QApplication.clipboard().setText(self._csv_text([row]))
            self.status.setText("Copied selected kernel interface")

    def export_csv(self):
        path, _selected = QtWidgets.QFileDialog.getSaveFileName(self.parent, "Export Syscall and Kernel Interfaces", "syscall_kernel_interfaces.csv", "CSV files (*.csv)")
        if path:
            with open(path, "w", encoding="utf-8-sig", newline="") as handle:
                handle.write(self._csv_text(self.rows))
            self.status.setText("Exported %d interfaces to %s" % (len(self.rows), os.path.basename(path)))

    def OnClose(self, form):
        global _mapper
        if _mapper is self:
            _mapper = None


def show_syscall_kernel_mapper():
    global _mapper
    if _mapper is None:
        _mapper = SyscallKernelInterfaceMapper()
    _mapper.Show("PseudoNote - Syscall and Kernel Interface Mapper", options=ida_kernwin.PluginForm.WOPN_PERSIST)


class SyscallKernelInterfaceMapperHandler(idaapi.action_handler_t):
    def activate(self, ctx):
        show_syscall_kernel_mapper()
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS
