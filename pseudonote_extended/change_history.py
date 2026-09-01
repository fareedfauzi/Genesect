# -*- coding: utf-8 -*-
"""Persistent IDB change journal with verified selective rollback."""
import datetime
import json
import uuid

import idaapi
import ida_bytes
import ida_kernwin
import ida_netnode
import idc

from pseudonote_extended.qt_compat import QtCore, QtWidgets
from pseudonote_extended.ui.components import PageHeader, Card
from pseudonote_extended.ui.mac_workspace import apply_mac_workspace


_NODE_NAME = "$ pseudonote_extended:change_history"
_MAX_RECORDS = 5000
_explorer = None
_hooks = None


def _hex(ea):
    return "0x%X" % int(ea)


def _load_records():
    try:
        node = ida_netnode.netnode(_NODE_NAME, 0, False)
        if not node or node == ida_netnode.BADNODE:
            return []
        raw = node.getblob(0, ord("H"))
        value = json.loads(raw.decode("utf-8")) if raw else []
        return value if isinstance(value, list) else []
    except Exception:
        return []


def _save_records(records):
    try:
        node = ida_netnode.netnode(_NODE_NAME, 0, True)
        node.setblob(json.dumps(records[-_MAX_RECORDS:], ensure_ascii=False).encode("utf-8"), 0, ord("H"))
        return True
    except Exception:
        return False


def _display_value(value):
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.hex(" ").upper()
    return str(value)


class ChangeJournalHooks(idaapi.IDB_Hooks):
    """Capture pre-change state where IDA exposes it and persist post-change values."""
    def __init__(self):
        super().__init__()
        self.pending = {}
        self.suspended = False

    def _remember(self, kind, ea, before, meta=None):
        if not self.suspended:
            self.pending[(kind, int(ea), json.dumps(meta or {}, sort_keys=True))] = before

    def _take(self, kind, ea, meta=None):
        return self.pending.pop((kind, int(ea), json.dumps(meta or {}, sort_keys=True)), None)

    def _record(self, kind, ea, before, after, meta=None):
        if self.suspended or before == after:
            return
        records = _load_records()
        records.append({
            "id": uuid.uuid4().hex,
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "kind": kind, "ea": int(ea), "before": before, "after": after,
            "meta": meta or {}, "status": "active",
        })
        _save_records(records)

    def renamed(self, ea, new_name, local_name=False, old_name=None, *args):
        # IDA supplies old_name directly (including IDA 8.3), so renames remain
        # journaled even though there is no public pre-rename IDB event.
        before = str(old_name or "") if old_name is not None else self._take("name", ea)
        if before is not None:
            self._record("name", ea, before, idc.get_name(ea) or str(new_name or ""), {"local": bool(local_name)})

    def changing_cmt(self, ea, repeatable, new_comment, *args):
        meta = {"repeatable": bool(repeatable)}
        self._remember("comment", ea, idc.get_cmt(ea, int(bool(repeatable))) or "", meta)
        return 0

    def cmt_changed(self, ea, repeatable, *args):
        meta = {"repeatable": bool(repeatable)}
        before = self._take("comment", ea, meta)
        if before is not None:
            self._record("comment", ea, before, idc.get_cmt(ea, int(bool(repeatable))) or "", meta)

    def changing_range_cmt(self, kind, address_range, new_comment, repeatable, *args):
        start_ea = int(getattr(address_range, "start_ea", idaapi.BADADDR))
        if start_ea != idaapi.BADADDR:
            meta = {"repeatable": bool(repeatable), "range_kind": int(kind)}
            self._remember("function_comment", start_ea, idc.get_func_cmt(start_ea, int(bool(repeatable))) or "", meta)
        return 0

    def range_cmt_changed(self, kind, address_range, new_comment, repeatable, *args):
        start_ea = int(getattr(address_range, "start_ea", idaapi.BADADDR))
        if start_ea != idaapi.BADADDR:
            meta = {"repeatable": bool(repeatable), "range_kind": int(kind)}
            before = self._take("function_comment", start_ea, meta)
            if before is not None:
                self._record("function_comment", start_ea, before, idc.get_func_cmt(start_ea, int(bool(repeatable))) or "", meta)

    def changing_ti(self, ea, new_type, new_fields, *args):
        self._remember("type", ea, idc.get_type(ea) or "")
        return 0

    def ti_changed(self, ea, new_type=None, new_fields=None, *args):
        before = self._take("type", ea)
        if before is not None:
            self._record("type", ea, before, idc.get_type(ea) or "")

    def byte_patched(self, ea, old_value, *args):
        try:
            before = int(old_value) & 0xFF
            after = int(ida_bytes.get_wide_byte(ea)) & 0xFF
            self._record("byte", ea, before, after)
        except Exception:
            pass


def start_change_history_hooks():
    global _hooks
    if _hooks is None:
        _hooks = ChangeJournalHooks()
        _hooks.hook()
    return _hooks


def stop_change_history_hooks():
    global _hooks
    if _hooks is not None:
        try:
            _hooks.unhook()
        except Exception:
            pass
        _hooks = None


def _current_value(record):
    kind, ea, meta = record["kind"], int(record["ea"]), record.get("meta", {})
    if kind == "name":
        return idc.get_name(ea) or ""
    if kind == "comment":
        return idc.get_cmt(ea, int(bool(meta.get("repeatable")))) or ""
    if kind == "function_comment":
        return idc.get_func_cmt(ea, int(bool(meta.get("repeatable")))) or ""
    if kind == "type":
        return idc.get_type(ea) or ""
    if kind == "byte":
        return int(ida_bytes.get_wide_byte(ea)) & 0xFF
    return None


def rollback_record(record):
    """Rollback only when the IDB still contains the recorded after-value."""
    if record.get("status") != "active":
        return False, "This change is no longer active."
    current = _current_value(record)
    if current != record.get("after"):
        return False, "Current IDB value differs from the recorded after-value; rollback was skipped to protect newer work."
    kind, ea, before, meta = record["kind"], int(record["ea"]), record.get("before"), record.get("meta", {})
    global _hooks
    if _hooks:
        _hooks.suspended = True
    try:
        if kind == "name":
            flags = getattr(idc, "SN_NOWARN", 1) | getattr(idc, "SN_FORCE", 0x800)
            if meta.get("local"):
                flags |= getattr(idc, "SN_LOCAL", 0x200)
            success = bool(idc.set_name(ea, str(before or ""), flags))
        elif kind == "comment":
            success = bool(idc.set_cmt(ea, str(before or ""), int(bool(meta.get("repeatable")))))
        elif kind == "function_comment":
            success = bool(idc.set_func_cmt(ea, str(before or ""), int(bool(meta.get("repeatable")))))
        elif kind == "type":
            success = bool(idc.SetType(ea, str(before or "")))
        elif kind == "byte":
            success = bool(ida_bytes.patch_byte(ea, int(before) & 0xFF))
        else:
            return False, "This change type is not rollback-capable."
    finally:
        if _hooks:
            _hooks.suspended = False
    if not success:
        return False, "IDA rejected the rollback operation."
    if _current_value(record) != before:
        return False, "Rollback returned success but verification did not match the recorded before-value."
    return True, "Rolled back."


class ChangeHistoryExplorer(ida_kernwin.PluginForm):
    def __init__(self):
        super().__init__()
        self.records = []

    def OnCreate(self, form):
        self.parent = self.FormToPyQtWidget(form)
        apply_mac_workspace(self.parent)
        root = QtWidgets.QVBoxLayout(self.parent)
        root.setContentsMargins(16, 14, 16, 14)
        root.setSpacing(10)
        header = PageHeader("Change History and Undo Explorer", "Persistent before/after journal with verified selective rollback")
        refresh = QtWidgets.QPushButton("Refresh")
        refresh.clicked.connect(self.refresh)
        header.add_action(refresh)
        self.rollback_btn = QtWidgets.QPushButton("Rollback Selected")
        self.rollback_btn.setProperty("pnVariant", "danger")
        self.rollback_btn.clicked.connect(self.rollback_selected)
        header.add_action(self.rollback_btn)
        root.addWidget(header)
        self.filter_edit = QtWidgets.QLineEdit()
        self.filter_edit.setPlaceholderText("Filter by change type, address, timestamp, status, or value…")
        self.filter_edit.setClearButtonEnabled(True)
        self.filter_edit.textChanged.connect(self.apply_filter)
        root.addWidget(self.filter_edit)
        splitter = QtWidgets.QSplitter(QtCore.Qt.Vertical)
        table_card = Card()
        self.table = QtWidgets.QTableWidget(0, 7)
        self.table.setHorizontalHeaderLabels(["Rollback", "Time (UTC)", "Type", "Address", "Before", "After", "Status"])
        self.table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.itemSelectionChanged.connect(self.show_details)
        self.table.itemDoubleClicked.connect(self.navigate_selected)
        table_card.add_widget(self.table)
        splitter.addWidget(table_card)
        detail_card = Card("Before / after verification")
        self.details = QtWidgets.QPlainTextEdit()
        self.details.setReadOnly(True)
        detail_card.add_widget(self.details)
        splitter.addWidget(detail_card)
        splitter.setSizes([700, 240])
        root.addWidget(splitter, 1)
        self.status = QtWidgets.QLabel("History records modifications made after PseudoNote Extended initialized its journal.")
        self.status.setProperty("pnMuted", True)
        root.addWidget(self.status)
        self.refresh()

    def refresh(self):
        self.records = list(reversed(_load_records()))
        self.populate()

    def populate(self):
        self.table.setSortingEnabled(False)
        self.table.setRowCount(len(self.records))
        for row_index, record in enumerate(self.records):
            checkbox = QtWidgets.QTableWidgetItem()
            checkbox.setFlags(checkbox.flags() | QtCore.Qt.ItemIsUserCheckable)
            checkbox.setCheckState(QtCore.Qt.Unchecked)
            checkbox.setData(QtCore.Qt.UserRole, row_index)
            if record.get("status") != "active":
                checkbox.setFlags(checkbox.flags() & ~QtCore.Qt.ItemIsEnabled)
            self.table.setItem(row_index, 0, checkbox)
            timestamp = str(record.get("timestamp", "")).replace("T", " ").replace("+00:00", "Z")
            values = [timestamp, record.get("kind", ""), _hex(record.get("ea", 0)), _display_value(record.get("before")), _display_value(record.get("after")), record.get("status", "active")]
            for column, value in enumerate(values, 1):
                item = QtWidgets.QTableWidgetItem(value)
                item.setData(QtCore.Qt.UserRole, row_index)
                self.table.setItem(row_index, column, item)
        self.table.resizeColumnsToContents()
        self.table.setColumnWidth(4, min(420, max(180, self.table.columnWidth(4))))
        self.table.setColumnWidth(5, min(420, max(180, self.table.columnWidth(5))))
        self.table.setSortingEnabled(True)
        self.apply_filter(self.filter_edit.text())
        active = sum(1 for record in self.records if record.get("status") == "active")
        self.status.setText("%d recorded changes • %d active and rollback-capable" % (len(self.records), active))

    def selected_record(self):
        selected = self.table.selectionModel().selectedRows() if self.table.selectionModel() else []
        if not selected:
            return None
        item = self.table.item(selected[0].row(), 0)
        index = item.data(QtCore.Qt.UserRole) if item else None
        return self.records[int(index)] if index is not None and 0 <= int(index) < len(self.records) else None

    def checked_records(self):
        selected = []
        for row in range(self.table.rowCount()):
            item = self.table.item(row, 0)
            if item and item.checkState() == QtCore.Qt.Checked:
                index = int(item.data(QtCore.Qt.UserRole))
                selected.append(self.records[index])
        return selected

    def apply_filter(self, text):
        needle = str(text or "").strip().lower()
        for row in range(self.table.rowCount()):
            haystack = " ".join(self.table.item(row, column).text() for column in range(1, self.table.columnCount()) if self.table.item(row, column)).lower()
            self.table.setRowHidden(row, bool(needle and needle not in haystack))

    def show_details(self):
        record = self.selected_record()
        if not record:
            self.details.setPlainText("Select a history record to compare its values with the current IDB.")
            return
        current = _current_value(record)
        safe = current == record.get("after") and record.get("status") == "active"
        self.details.setPlainText(
            "Type: %s\nAddress: %s\nTimestamp: %s\nStatus: %s\n\nBEFORE\n%s\n\nAFTER\n%s\n\nCURRENT IDB VALUE\n%s\n\nRollback verification: %s" % (
                record.get("kind"), _hex(record.get("ea", 0)), record.get("timestamp"), record.get("status"),
                _display_value(record.get("before")), _display_value(record.get("after")), _display_value(current),
                "safe — current value still matches AFTER" if safe else "blocked — current value changed or record is inactive",
            )
        )

    def navigate_selected(self, *_args):
        record = self.selected_record()
        if record:
            ida_kernwin.jumpto(int(record["ea"]))

    def rollback_selected(self):
        selected = self.checked_records()
        if not selected:
            ida_kernwin.info("Check one or more active changes to roll back.")
            return
        answer = QtWidgets.QMessageBox.question(self.parent, "Confirm selective rollback", "Roll back %d selected change(s)?\n\nEach item will be skipped if its current value no longer matches the recorded after-value." % len(selected), QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No, QtWidgets.QMessageBox.No)
        if answer != QtWidgets.QMessageBox.Yes:
            return
        succeeded, failed = 0, []
        all_records = _load_records()
        by_id = {record.get("id"): record for record in all_records}
        for record in selected:
            canonical = by_id.get(record.get("id"))
            if not canonical:
                failed.append("%s: history record missing" % _hex(record.get("ea", 0)))
                continue
            ok, message = rollback_record(canonical)
            if ok:
                canonical["status"] = "rolled_back"
                canonical["rolled_back_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
                succeeded += 1
            else:
                failed.append("%s: %s" % (_hex(canonical.get("ea", 0)), message))
        _save_records(all_records)
        self.refresh()
        summary = "Rolled back %d change(s)." % succeeded
        if failed:
            summary += "\n\nSkipped %d:\n%s" % (len(failed), "\n".join(failed[:20]))
        ida_kernwin.info(summary)

    def OnClose(self, form):
        global _explorer
        if _explorer is self:
            _explorer = None


def show_change_history_explorer():
    global _explorer
    if _explorer is None:
        _explorer = ChangeHistoryExplorer()
    _explorer.Show("PseudoNote - Change History and Undo Explorer", options=ida_kernwin.PluginForm.WOPN_PERSIST)


class ChangeHistoryExplorerHandler(idaapi.action_handler_t):
    def activate(self, ctx):
        show_change_history_explorer()
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS
