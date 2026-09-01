# -*- coding: utf-8 -*-
"""Reviewed standard-API enum recovery inspired by junron/auto-enum (MIT)."""

import idc
import idaapi
import ida_kernwin
import ida_nalt
import ida_typeinf
import idautils

from pseudonote_extended.qt_compat import QtCore, QtWidgets
from pseudonote_extended.ui.components import Card, PageHeader
from pseudonote_extended.ui.mac_workspace import apply_mac_workspace


# A compact, dependency-free corpus focused on APIs commonly encountered during
# malware reversing. Values are deliberately kept as plain dictionaries so the
# scanner can be tested without importing IDA.
ENUMS = {
    "PN_MEM_ALLOCATION_TYPE": {
        "MEM_COMMIT": 0x1000, "MEM_RESERVE": 0x2000, "MEM_DECOMMIT": 0x4000,
        "MEM_RELEASE": 0x8000, "MEM_RESET": 0x80000, "MEM_TOP_DOWN": 0x100000,
        "MEM_WRITE_WATCH": 0x200000, "MEM_PHYSICAL": 0x400000,
    },
    "PN_PAGE_PROTECTION": {
        "PAGE_NOACCESS": 0x01, "PAGE_READONLY": 0x02, "PAGE_READWRITE": 0x04,
        "PAGE_WRITECOPY": 0x08, "PAGE_EXECUTE": 0x10, "PAGE_EXECUTE_READ": 0x20,
        "PAGE_EXECUTE_READWRITE": 0x40, "PAGE_EXECUTE_WRITECOPY": 0x80,
        "PAGE_GUARD": 0x100, "PAGE_NOCACHE": 0x200, "PAGE_WRITECOMBINE": 0x400,
    },
    "PN_PROCESS_ACCESS": {
        "PROCESS_TERMINATE": 0x0001, "PROCESS_CREATE_THREAD": 0x0002,
        "PROCESS_VM_OPERATION": 0x0008, "PROCESS_VM_READ": 0x0010,
        "PROCESS_VM_WRITE": 0x0020, "PROCESS_DUP_HANDLE": 0x0040,
        "PROCESS_CREATE_PROCESS": 0x0080, "PROCESS_QUERY_INFORMATION": 0x0400,
        "PROCESS_SUSPEND_RESUME": 0x0800, "PROCESS_QUERY_LIMITED_INFORMATION": 0x1000,
        "PROCESS_ALL_ACCESS": 0x001F0FFF,
    },
    "PN_FILE_ACCESS": {
        "GENERIC_READ": 0x80000000, "GENERIC_WRITE": 0x40000000,
        "GENERIC_EXECUTE": 0x20000000, "GENERIC_ALL": 0x10000000,
    },
    "PN_FILE_SHARE": {
        "FILE_SHARE_READ": 0x1, "FILE_SHARE_WRITE": 0x2, "FILE_SHARE_DELETE": 0x4,
    },
    "PN_CREATION_DISPOSITION": {
        "CREATE_NEW": 1, "CREATE_ALWAYS": 2, "OPEN_EXISTING": 3,
        "OPEN_ALWAYS": 4, "TRUNCATE_EXISTING": 5,
    },
    "PN_PROCESS_CREATION_FLAGS": {
        "DEBUG_PROCESS": 0x1, "DEBUG_ONLY_THIS_PROCESS": 0x2,
        "CREATE_SUSPENDED": 0x4, "DETACHED_PROCESS": 0x8,
        "CREATE_NEW_CONSOLE": 0x10, "CREATE_NEW_PROCESS_GROUP": 0x200,
        "CREATE_UNICODE_ENVIRONMENT": 0x400, "CREATE_NO_WINDOW": 0x08000000,
    },
    "PN_SOCKET_FAMILY": {"AF_UNSPEC": 0, "AF_UNIX": 1, "AF_INET": 2, "AF_INET6": 23},
    "PN_SOCKET_TYPE": {"SOCK_STREAM": 1, "SOCK_DGRAM": 2, "SOCK_RAW": 3, "SOCK_SEQPACKET": 5},
    "PN_SHUTDOWN_MODE": {"SD_RECEIVE": 0, "SD_SEND": 1, "SD_BOTH": 2},
    "PN_MMAP_PROTECTION": {"PROT_NONE": 0, "PROT_READ": 1, "PROT_WRITE": 2, "PROT_EXEC": 4},
    "PN_MMAP_FLAGS": {
        "MAP_SHARED": 0x01, "MAP_PRIVATE": 0x02, "MAP_FIXED": 0x10,
        "MAP_ANONYMOUS": 0x20, "MAP_GROWSDOWN": 0x0100, "MAP_HUGETLB": 0x40000,
    },
    "PN_OPEN_FLAGS": {
        "O_RDONLY": 0, "O_WRONLY": 1, "O_RDWR": 2, "O_CREAT": 0x40,
        "O_EXCL": 0x80, "O_TRUNC": 0x200, "O_APPEND": 0x400,
        "O_NONBLOCK": 0x800, "O_CLOEXEC": 0x80000,
    },
    "PN_DLOPEN_FLAGS": {"RTLD_LAZY": 1, "RTLD_NOW": 2, "RTLD_NOLOAD": 4, "RTLD_DEEPBIND": 8, "RTLD_GLOBAL": 0x100},
}


RULES = {
    # Zero-based indexes include every parameter in the documented prototype.
    "VirtualAlloc": ((2, "flAllocationType", "PN_MEM_ALLOCATION_TYPE"), (3, "flProtect", "PN_PAGE_PROTECTION")),
    "VirtualAllocEx": ((3, "flAllocationType", "PN_MEM_ALLOCATION_TYPE"), (4, "flProtect", "PN_PAGE_PROTECTION")),
    "VirtualProtect": ((2, "flNewProtect", "PN_PAGE_PROTECTION"),),
    "VirtualProtectEx": ((3, "flNewProtect", "PN_PAGE_PROTECTION"),),
    "OpenProcess": ((0, "dwDesiredAccess", "PN_PROCESS_ACCESS"),),
    "CreateFile": ((1, "dwDesiredAccess", "PN_FILE_ACCESS"), (2, "dwShareMode", "PN_FILE_SHARE"), (4, "dwCreationDisposition", "PN_CREATION_DISPOSITION")),
    "CreateProcess": ((5, "dwCreationFlags", "PN_PROCESS_CREATION_FLAGS"),),
    "socket": ((0, "af", "PN_SOCKET_FAMILY"), (1, "type", "PN_SOCKET_TYPE")),
    "WSASocket": ((0, "af", "PN_SOCKET_FAMILY"), (1, "type", "PN_SOCKET_TYPE")),
    "shutdown": ((1, "how", "PN_SHUTDOWN_MODE"),),
    "mmap": ((2, "prot", "PN_MMAP_PROTECTION"), (3, "flags", "PN_MMAP_FLAGS")),
    "mprotect": ((2, "prot", "PN_MMAP_PROTECTION"),),
    "open": ((1, "flags", "PN_OPEN_FLAGS"),),
    "openat": ((2, "flags", "PN_OPEN_FLAGS"),),
    "dlopen": ((1, "flags", "PN_DLOPEN_FLAGS"),),
}

FLAG_ENUMS = {
    "PN_MEM_ALLOCATION_TYPE", "PN_PAGE_PROTECTION", "PN_PROCESS_ACCESS",
    "PN_FILE_ACCESS", "PN_FILE_SHARE", "PN_PROCESS_CREATION_FLAGS",
    "PN_MMAP_PROTECTION", "PN_MMAP_FLAGS", "PN_OPEN_FLAGS", "PN_DLOPEN_FLAGS",
}


def normalize_api_name(name):
    name = str(name or "").split("@")[0].lstrip("_")
    if name.startswith("imp_"):
        name = name[4:]
    for base in RULES:
        if name == base or (name in (base + "A", base + "W")):
            return base
    return name


def collect_imports():
    rows = []
    def callback(ea, name, ordinal):
        base = normalize_api_name(name)
        if base in RULES:
            _is_pointer, details = _function_details(int(ea))
            xref_count = sum(1 for _xref in idautils.XrefsTo(int(ea), 0))
            for index, argument, enum_name in RULES[base]:
                valid = details is not None and index < len(details)
                rows.append({
                    "apply": False, "ea": int(ea), "api": str(name or base),
                    "argument": argument, "index": index, "enum": enum_name,
                    "members": len(ENUMS[enum_name]), "xrefs": xref_count,
                    "status": "Review" if valid else "Prototype/index unavailable",
                    "valid": valid,
                })
        return True
    for module_index in range(int(ida_nalt.get_import_module_qty())):
        ida_nalt.enum_import_names(module_index, callback)
    return rows


def _enum_id(enum_name):
    enum_id = idc.get_enum(enum_name)
    if enum_id != idaapi.BADADDR:
        return enum_id
    enum_id = idc.add_enum(-1, enum_name, idaapi.hex_flag())
    if enum_id == idaapi.BADADDR:
        raise RuntimeError("IDA could not create enum %s" % enum_name)
    if enum_name in FLAG_ENUMS:
        idc.set_enum_bf(enum_id, True)
    for member, value in ENUMS[enum_name].items():
        result = idc.add_enum_member(enum_id, member, value, -1)
        if result not in (0, None):
            # Existing symbol collisions should not discard the remaining enum.
            idc.add_enum_member(enum_id, "%s_%X" % (member, value), value, -1)
    return enum_id


def _function_details(ea):
    tif = ida_typeinf.tinfo_t()
    details = ida_typeinf.func_type_data_t()
    if not ida_nalt.get_tinfo(tif, ea):
        return None, None
    is_pointer = tif.is_funcptr()
    target = tif.get_pointed_object() if is_pointer else tif
    if not target.is_func() or not target.get_func_details(details):
        return None, None
    return is_pointer, details


def apply_proposals(rows):
    by_function = {}
    for row in rows:
        if row.get("apply"):
            by_function.setdefault(row["ea"], []).append(row)
    applied = failed = 0
    for ea, proposals in by_function.items():
        is_pointer, details = _function_details(ea)
        if details is None:
            for row in proposals: row["status"] = "Missing function prototype"
            failed += len(proposals)
            continue
        changed = []
        for row in proposals:
            if row["index"] >= len(details):
                row["status"] = "Argument index is unavailable"
                failed += 1
                continue
            try:
                _enum_id(row["enum"])
                enum_type = ida_typeinf.tinfo_t()
                if not enum_type.get_named_type(idaapi.get_idati(), row["enum"]):
                    raise RuntimeError("enum type did not load")
                details[row["index"]].type = enum_type
                changed.append(row)
            except Exception as exc:
                row["status"] = "Failed: %s" % exc
                failed += 1
        if not changed:
            continue
        function_type = ida_typeinf.tinfo_t()
        function_type.create_func(details)
        applied_type = function_type
        if is_pointer:
            applied_type = ida_typeinf.tinfo_t()
            applied_type.create_ptr(function_type)
        if ida_typeinf.apply_tinfo(ea, applied_type, ida_typeinf.TINFO_DEFINITE):
            for row in changed: row["status"] = "Applied"
            applied += len(changed)
        else:
            for row in changed: row["status"] = "IDA rejected prototype"
            failed += len(changed)
    return applied, failed


class AutoEnumExplorer(ida_kernwin.PluginForm):
    def __init__(self):
        super().__init__()
        self.rows = []

    def OnCreate(self, form):
        self.parent = self.FormToPyQtWidget(form)
        apply_mac_workspace(self.parent)
        root = QtWidgets.QVBoxLayout(self.parent)
        root.setContentsMargins(16, 14, 16, 14)
        root.setSpacing(10)
        header = PageHeader(
            "Automatic Enum Recovery",
            "Type validated imported-API parameters so Hex-Rays can render constants symbolically",
        )
        scan = QtWidgets.QPushButton("Scan Imported APIs")
        scan.setProperty("pnVariant", "primary")
        scan.clicked.connect(self.refresh)
        header.add_action(scan)
        apply_button = QtWidgets.QPushButton("Apply Selected")
        apply_button.setProperty("pnVariant", "success")
        apply_button.clicked.connect(self.apply_selected)
        header.add_action(apply_button)
        root.addWidget(header)
        self.filter_edit = QtWidgets.QLineEdit()
        self.filter_edit.setPlaceholderText("Filter API, argument, enum, address, or status...")
        self.filter_edit.setClearButtonEnabled(True)
        self.filter_edit.textChanged.connect(self.apply_filter)
        root.addWidget(self.filter_edit)
        card = Card()
        self.table = QtWidgets.QTableWidget(0, 8)
        self.table.setHorizontalHeaderLabels(["Apply", "Import Slot", "API", "Argument", "Index", "Enum", "Xrefs", "Status"])
        self.table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.itemChanged.connect(self._item_changed)
        self.table.itemDoubleClicked.connect(self.navigate)
        card.add_widget(self.table)
        root.addWidget(card, 1)
        self.status = QtWidgets.QLabel("Ready")
        self.status.setProperty("pnMuted", True)
        root.addWidget(self.status)
        QtCore.QTimer.singleShot(0, self.refresh)

    def refresh(self):
        self.rows = collect_imports()
        self.populate()

    def populate(self):
        self.table.blockSignals(True)
        self.table.setRowCount(len(self.rows))
        for row_index, row in enumerate(self.rows):
            values = ["", "0x%X" % row["ea"], row["api"], row["argument"], str(row["index"]), row["enum"], str(row["xrefs"]), row["status"]]
            for column, value in enumerate(values):
                item = QtWidgets.QTableWidgetItem(value)
                item.setData(QtCore.Qt.UserRole, row_index)
                if column == 0:
                    item.setFlags(item.flags() | QtCore.Qt.ItemIsUserCheckable)
                    item.setCheckState(QtCore.Qt.Checked if row["apply"] else QtCore.Qt.Unchecked)
                    if not row.get("valid", False):
                        item.setFlags(item.flags() & ~QtCore.Qt.ItemIsEnabled)
                self.table.setItem(row_index, column, item)
        self.table.blockSignals(False)
        self.table.resizeColumnsToContents()
        self.table.setColumnWidth(7, max(260, self.table.columnWidth(7)))
        self.apply_filter(self.filter_edit.text())
        valid = sum(1 for row in self.rows if row.get("valid"))
        self.status.setText("%d validated proposals; %d unavailable across %d supported imports" %
                            (valid, len(self.rows) - valid, len(set(row["ea"] for row in self.rows))))

    def _item_changed(self, item):
        if item.column() == 0:
            index = item.data(QtCore.Qt.UserRole)
            if index is not None:
                self.rows[int(index)]["apply"] = item.checkState() == QtCore.Qt.Checked

    def apply_filter(self, text):
        needle = str(text or "").strip().lower()
        for row in range(self.table.rowCount()):
            haystack = " ".join(self.table.item(row, column).text() for column in range(1, self.table.columnCount())).lower()
            self.table.setRowHidden(row, bool(needle and needle not in haystack))

    def apply_selected(self):
        selected = sum(1 for row in self.rows if row.get("apply"))
        if not selected:
            ida_kernwin.warning("Select at least one enum proposal first.")
            return
        if QtWidgets.QMessageBox.question(self.parent, "Apply Enum Types",
                "Apply %d reviewed enum argument types to imported API prototypes?" % selected,
                QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No, QtWidgets.QMessageBox.No) != QtWidgets.QMessageBox.Yes:
            return
        applied, failed = apply_proposals(self.rows)
        self.populate()
        idaapi.request_refresh(idaapi.IWID_PSEUDOCODE)
        self.status.setText("Applied %d enum types; %d failed. Re-decompile affected functions to refresh constants." % (applied, failed))

    def navigate(self, item):
        index = item.data(QtCore.Qt.UserRole)
        if index is not None:
            ida_kernwin.jumpto(self.rows[int(index)]["ea"])

    def OnClose(self, form):
        global _explorer
        if _explorer is self:
            _explorer = None


_explorer = None


def show_auto_enum_explorer():
    global _explorer
    if _explorer is None:
        _explorer = AutoEnumExplorer()
    _explorer.Show("PseudoNote - Automatic Enum Recovery", options=ida_kernwin.PluginForm.WOPN_PERSIST)


class AutoEnumExplorerHandler(idaapi.action_handler_t):
    def activate(self, ctx):
        show_auto_enum_explorer()
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS
