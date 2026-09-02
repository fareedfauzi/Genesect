# -*- coding: utf-8 -*-
"""
AI Chat interface for multiple functions in a chain.
Allows users to select specific functions from a call graph and chat about them.
"""

import idaapi
from pseudonote_extended.qt_compat import PluginFormWrapper
import ida_kernwin
import ida_nalt
import ida_funcs
import idautils
import idc
import html
import time
import json
import threading
from pseudonote_extended.qt_compat import (
    QtWidgets, QtCore, QtGui, QThread, Signal, Slot, QDialog,
    QVBoxLayout, QHBoxLayout, QSplitter, QTextBrowser, QPushButton,
    QLabel, QProgressBar, QSpinBox, QGroupBox, QLineEdit, QTableWidget,
    QTableWidgetItem, QHeaderView, QCheckBox
)
import pseudonote_extended.ai_client as _ai_mod
from pseudonote_extended.config import CONFIG, LOGGER
from pseudonote_extended.deep_analyzer import build_call_graph, FuncNode, STYLES_ANALYZER
from pseudonote_extended.renamer import get_code_fast
from pseudonote_extended.chat import (
    ChatBubble, ChatInput, ResponsiveChatScrollArea, get_ida_colors, get_chat_font,
)
from pseudonote_extended.idb_storage import save_to_idb, load_from_idb
from pseudonote_extended.chat_export import export_chat_log
from pseudonote_extended.deep_session import binary_fingerprint
from pseudonote_extended.chat_state import (
    build_context_snapshot, normalize_chat_history, selection_signature,
)
from pseudonote_extended.ui.workspace import RequestGate
from pseudonote_extended.ui.mac_workspace import apply_mac_workspace
from pseudonote_extended.ui.theme import current_theme

CHAIN_CHAT_HISTORY_TAG = 97

class ChatChainWorker(QThread):
    log_signal = Signal(str, str)
    finished_signal = Signal(object)
    
    def __init__(self, entry_ea, max_depth, max_funcs):
        super().__init__()
        self.entry_ea = entry_ea
        self.max_depth = max_depth
        self.max_funcs = max_funcs
        self._stop = False
        
    def stop(self):
        self._stop = True
        
    def run(self):
        self.log_signal.emit(f"Building function graph from 0x{self.entry_ea:X}...", "info")
        
        graph = build_call_graph(
            self.entry_ea,
            stop_checker=lambda: self._stop,
            log_fn=lambda m, l: self.log_signal.emit(m, l),
            max_depth=self.max_depth,
            max_nodes=max(25, self.max_funcs * 3),
        )
            
        if self._stop: return
        
        if not graph:
            self.log_signal.emit("No function graph could be built.", "err")
            print(f"[PseudoNote] ERROR: build_call_graph returned empty for 0x{self.entry_ea:X}")
            return
            
        print(f"[PseudoNote] Graph discovery for 0x{self.entry_ea:X} found {len(graph)} total nodes.")
        self.log_signal.emit(f"Found {len(graph)} total functions.", "ok")
        self.finished_signal.emit(graph)

class ChatChainDialog(QtWidgets.QDialog):
    def __init__(self, entry_ea=None, parent=None):
        super().__init__(parent)
        self.setWindowTitle("PseudoNote - Chat About a Function Chain")
        self.resize(1200, 800)
        self.setWindowFlags(self.windowFlags() | QtCore.Qt.WindowMaximizeButtonHint | QtCore.Qt.WindowMinimizeButtonHint | QtCore.Qt.WindowCloseButtonHint)
        
        self.entry_ea = entry_ea or idc.get_screen_ea()
        self.graph = {}
        self.worker = None
        self.history = []
        self.request_gate = RequestGate()
        self._active_request_id = None
        self._context_signature = ()
        self._context_snapshot = ""
        self._closed = False
        
        self.setup_ui()
        self.on_use_current_function()
        self.load_history()

    def setup_ui(self):
        colors = get_ida_colors()
        apply_mac_workspace(self)
        
        main_layout = QVBoxLayout(self)
        main_layout.setSpacing(0)
        main_layout.setContentsMargins(0, 0, 0, 0)

        # Header Panel
        header = QtWidgets.QFrame()
        header.setStyleSheet(f"background-color: {colors['alt_base']}; border-bottom: 1px solid {colors['mid']};")
        header_layout = QVBoxLayout(header)
        header_layout.setContentsMargins(15, 10, 15, 10)
        
        entry_row = QHBoxLayout()
        self.entry_label = QLabel("Entry:")
        self.entry_label.setStyleSheet(f"color: {colors['window_text']}; font-weight: bold;")
        entry_row.addWidget(self.entry_label)
        
        self.entry_combo = QtWidgets.QComboBox()
        self.entry_combo.setEditable(True)
        self.entry_combo.setInsertPolicy(QtWidgets.QComboBox.NoInsert)
        self.entry_combo.setMaxVisibleItems(24)
        self.entry_combo.setToolTip("Select or search for a function by name or address")
        self.entry_combo.lineEdit().setPlaceholderText("Search function name or address...")
        self.entry_combo.setStyleSheet(f"""
            QComboBox {{
                color: {colors['highlight']}; font-family: monospace; font-size: 13px;
                background: transparent; border: 1px solid {colors['mid']}; border-radius: 6px;
                padding: 2px 7px;
            }}
            QComboBox:focus {{ border-color: {colors['highlight']}; }}
        """)
        self._populate_function_selector()
        completer = self.entry_combo.completer()
        if completer:
            completer.setCaseSensitivity(QtCore.Qt.CaseInsensitive)
            match_contains = getattr(QtCore.Qt, "MatchContains", None)
            if match_contains is None and hasattr(QtCore.Qt, "MatchFlag"):
                match_contains = QtCore.Qt.MatchFlag.MatchContains
            if match_contains is not None and hasattr(completer, "setFilterMode"):
                completer.setFilterMode(match_contains)
            completer.setCompletionMode(QtWidgets.QCompleter.PopupCompletion)
        self.entry_combo.activated.connect(self.on_entry_selected)
        self.entry_combo.lineEdit().returnPressed.connect(self.on_entry_search_submitted)
        entry_row.addWidget(self.entry_combo, 1)

        self.entry_dropdown_btn = QtWidgets.QToolButton()
        self.entry_dropdown_btn.setText("\u25be")
        self.entry_dropdown_btn.setFixedSize(28, 28)
        self.entry_dropdown_btn.setToolTip("Show all entry functions")
        self.entry_dropdown_btn.setAccessibleName("Show entry function list")
        self.entry_dropdown_btn.setStyleSheet(f"""
            QToolButton {{
                color: {colors['window_text']};
                background: {colors['base']};
                border: 1px solid {colors['mid']};
                border-radius: 6px;
                font-size: 14px;
                font-weight: bold;
                padding: 0;
            }}
            QToolButton:hover {{
                color: white;
                background: {colors['highlight']};
                border-color: {colors['highlight']};
            }}
            QToolButton:pressed {{
                background: {colors['highlight']};
            }}
        """)
        self.entry_dropdown_btn.clicked.connect(self.entry_combo.showPopup)
        entry_row.addWidget(self.entry_dropdown_btn)
        
        clear_btn = QPushButton("Clear History")
        clear_btn.setFlat(True)
        clear_btn.setStyleSheet(f"QPushButton {{ color: {colors['mid']}; font-weight: bold; font-size: 11px; }} QPushButton:hover {{ color: {colors['highlight']}; text-decoration: underline; }}")
        clear_btn.clicked.connect(self.clear_chat)
        entry_row.addWidget(clear_btn)
        preview_btn = QPushButton("Context Preview")
        preview_btn.clicked.connect(self.show_context_preview)
        entry_row.addWidget(preview_btn)
        export_btn = QPushButton("Export Log")
        export_btn.clicked.connect(self.export_conversation)
        entry_row.addWidget(export_btn)
        header_layout.addLayout(entry_row)
        
        config_row = QHBoxLayout()
        load_btn = QPushButton("Current Func")
        load_btn.clicked.connect(self.on_use_current_function)
        config_row.addWidget(load_btn)
        
        config_row.addWidget(QLabel("Depth:"))
        self.depth_sp = QSpinBox()
        self.depth_sp.setRange(1, 20)
        self.depth_sp.setValue(10)
        config_row.addWidget(self.depth_sp)
        
        config_row.addWidget(QLabel("Max Funcs:"))
        self.func_sp = QSpinBox()
        self.func_sp.setRange(1, 1000)
        self.func_sp.setValue(100)
        config_row.addWidget(self.func_sp)
        
        self.build_btn = QPushButton("Build Function Graph")
        self.build_btn.setObjectName("buildFunctionGraphButton")
        self.build_btn.setProperty("pnVariant", "primary")
        # Keep this primary action readable regardless of IDA's native palette
        # or parent stylesheet precedence. This button has historically inherited
        # a pale disabled palette even while it was the workflow's main action.
        button_theme = current_theme(self, "system")
        self.build_btn.setStyleSheet(f"""
            QPushButton#buildFunctionGraphButton {{
                min-height: 26px; padding: 0 10px; border-radius: 6px;
                background: {button_theme.accent}; border: 1px solid {button_theme.accent};
                color: {button_theme.accent_text}; font-weight: 600;
            }}
            QPushButton#buildFunctionGraphButton:hover {{
                background: {button_theme.accent_hover}; border-color: {button_theme.accent_hover};
            }}
            QPushButton#buildFunctionGraphButton:pressed {{
                background: {button_theme.accent_pressed}; border-color: {button_theme.accent_pressed};
            }}
            QPushButton#buildFunctionGraphButton:disabled {{
                background: {button_theme.surface_alt}; border-color: {button_theme.border_strong};
                color: {button_theme.text_muted};
            }}
        """)
        self.build_btn.setToolTip("Build or rebuild the selectable caller/callee function graph")
        self.build_btn.clicked.connect(self.start_build)
        config_row.addWidget(self.build_btn)

        self.context_estimate = QLabel("0 selected • 0 context chars")
        config_row.addWidget(self.context_estimate)
        self.cancel_context_btn = QPushButton("Cancel Context")
        self.cancel_context_btn.setEnabled(False)
        self.cancel_context_btn.clicked.connect(self.cancel_context_injection)
        config_row.addWidget(self.cancel_context_btn)
        header_layout.addLayout(config_row)
        
        main_layout.addWidget(header)

        # Main Splitter
        self.splitter = QSplitter(QtCore.Qt.Horizontal)
        self.splitter.setStyleSheet(f"QSplitter::handle {{ background-color: {colors['mid']}; }}")
        
        # Left Side (Selector)
        left_widget = QtWidgets.QWidget()
        left_layout = QVBoxLayout(left_widget)
        left_layout.setContentsMargins(10, 10, 10, 10)
        
        self.func_table = QTableWidget(0, 4)
        self.func_table.setHorizontalHeaderLabels(["", "Address", "Function Name", "Depth"])
        self.func_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Fixed)
        self.func_table.setColumnWidth(0, 30)
        self.func_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.func_table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.func_table.doubleClicked.connect(self.navigate_to_selected_function)
        left_layout.addWidget(self.func_table)
        
        sel_btn_layout = QHBoxLayout()
        all_btn = QPushButton("Select All")
        all_btn.clicked.connect(lambda: self.set_all_checks(True))
        none_btn = QPushButton("Deselect All")
        none_btn.clicked.connect(lambda: self.set_all_checks(False))
        sel_btn_layout.addWidget(all_btn)
        sel_btn_layout.addWidget(none_btn)
        left_layout.addLayout(sel_btn_layout)
        
        self.splitter.addWidget(left_widget)
        
        # Right Side (Chat)
        right_widget = QtWidgets.QWidget()
        right_layout = QVBoxLayout(right_widget)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(0)
        
        self.chat_area = ResponsiveChatScrollArea()
        self.chat_area.setWidgetResizable(True)
        self.chat_area.setFrameShape(QtWidgets.QFrame.NoFrame)
        self.chat_area.setStyleSheet(f"background-color: {colors['window']};")
        
        self.chat_content = QtWidgets.QWidget()
        self.chat_layout = QVBoxLayout(self.chat_content)
        self.chat_layout.setContentsMargins(10, 10, 10, 10)
        self.chat_layout.setSpacing(10)
        self.chat_layout.addStretch() # Push messages to top
        
        self.chat_area.setWidget(self.chat_content)
        self.chat_area.viewportResized.connect(self._resize_chat_bubbles)
        right_layout.addWidget(self.chat_area, 1)
        
        # Typing indicator
        self.typing_container = QtWidgets.QFrame()
        self.typing_container.setVisible(False)
        self.typing_container.setStyleSheet(f"background-color: {colors['alt_base']}; border-top: 1px solid {colors['mid']};")
        ti_layout = QHBoxLayout(self.typing_container)
        ti_layout.setContentsMargins(15, 8, 15, 8)
        
        self.typing_lbl = QLabel("AI is thinking...")
        self.typing_lbl.setStyleSheet(f"color: {colors['highlight']}; font-style: italic; font-size: 11px;")
        ti_layout.addWidget(self.typing_lbl)
        self.chat_progress = QProgressBar()
        self.chat_progress.setRange(0, 0)
        self.chat_progress.setFixedHeight(4)
        self.chat_progress.setTextVisible(False)
        ti_layout.addWidget(self.chat_progress)
        right_layout.addWidget(self.typing_container)
        
        self.chat_input = ChatInput()
        self.chat_input.submitted.connect(self.on_chat_submit)
        
        input_wrap = QtWidgets.QWidget()
        input_wrap_layout = QVBoxLayout(input_wrap)
        input_wrap_layout.setContentsMargins(15, 10, 15, 15)
        input_wrap_layout.addWidget(self.chat_input)
        right_layout.addWidget(input_wrap)
        
        self.splitter.addWidget(right_widget)
        self.splitter.setSizes([400, 800])
        main_layout.addWidget(self.splitter, 1)
        
        # Log/Status Area
        self.status_bar = QHBoxLayout()
        self.status_bar.setContentsMargins(10, 2, 10, 2)
        self.status_lbl = QLabel("Ready")
        self.status_lbl.setStyleSheet(f"color: {colors['mid']}; font-size: 10px;")
        self.status_bar.addWidget(self.status_lbl)
        main_layout.addLayout(self.status_bar)

    def _populate_function_selector(self):
        """Load every IDB function into the searchable entry dropdown."""
        functions = []
        for ea in idautils.Functions():
            name = idc.get_func_name(ea) or f"sub_{ea:X}"
            functions.append((int(ea), str(name)))
        functions.sort(key=lambda item: (item[1].lower(), item[0]))
        self.entry_combo.blockSignals(True)
        self.entry_combo.clear()
        for ea, name in functions:
            self.entry_combo.addItem(f"0x{ea:X}  -  {name}", ea)
        self.entry_combo.blockSignals(False)

    def _select_entry_in_dropdown(self, ea):
        index = self.entry_combo.findData(int(ea))
        if index >= 0:
            self.entry_combo.blockSignals(True)
            self.entry_combo.setCurrentIndex(index)
            self.entry_combo.blockSignals(False)

    def _switch_entry_function(self, ea):
        f = ida_funcs.get_func(int(ea))
        if not f:
            self.status_lbl.setText("Selected address is not inside a function.")
            return False
        target_ea = int(f.start_ea)
        self._select_entry_in_dropdown(target_ea)
        self.build_btn.setEnabled(True)
        if self.entry_ea == target_ea:
            return True

        self._cancel_active_request()
        self.save_history()
        self.entry_ea = target_ea
        self.history = []
        self.graph = {}
        self._context_signature = ()
        self._context_snapshot = ""
        self.func_table.setRowCount(0)
        self.context_estimate.setText("0 selected â€¢ 0 context chars")
        self._clear_chat_widgets()
        self.load_history()
        self.status_lbl.setText(f"Entry set to {idc.get_func_name(target_ea) or hex(target_ea)}.")
        return True

    def on_entry_selected(self, index):
        ea = self.entry_combo.itemData(int(index))
        if ea is not None:
            self._switch_entry_function(int(ea))

    def on_entry_search_submitted(self):
        text = self.entry_combo.currentText().strip()
        index = self.entry_combo.findText(text, QtCore.Qt.MatchFixedString)
        if index >= 0:
            self.on_entry_selected(index)
            return
        token = text.split("-", 1)[0].strip()
        try:
            ea = int(token, 16) if token.lower().startswith("0x") else idc.get_name_ea_simple(text)
        except Exception:
            ea = idaapi.BADADDR
        if ea not in (None, idaapi.BADADDR) and self._switch_entry_function(int(ea)):
            return
        self.status_lbl.setText("No matching function. Choose an item from the search results.")

    def on_use_current_function(self):
        ea = idc.get_screen_ea()
        f = ida_funcs.get_func(ea)
        if f:
            self._switch_entry_function(f.start_ea)
        else:
            self.build_btn.setEnabled(False)
            self.status_lbl.setText("No function at cursor.")

    def start_build(self):
        if self.worker and self.worker.isRunning():
            self.worker.stop()
            self.build_btn.setEnabled(False)
            self.status_lbl.setText("Cancelling graph build...")
            return
            
        self.build_btn.setEnabled(True)
        self.build_btn.setText("Cancel Build")
        self.func_table.setRowCount(0)
        self.graph = {}
        self.status_lbl.setText("Building graph...")
        
        self.worker = ChatChainWorker(self.entry_ea, self.depth_sp.value(), self.func_sp.value())
        self.worker.log_signal.connect(lambda m, l: self.status_lbl.setText(m))
        self.worker.finished_signal.connect(self.on_graph_built)
        self.worker.finished.connect(self.on_graph_worker_finished)
        self.worker.start()

    def on_graph_worker_finished(self):
        self.build_btn.setEnabled(True)
        self.build_btn.setText("Build Function Graph")
        if not self.graph and "Cancelling" in self.status_lbl.text():
            self.status_lbl.setText("Graph build cancelled.")
        self.worker = None

    def on_graph_built(self, graph):
        self.build_btn.setEnabled(True)
        self.graph = graph

        print(f"[PseudoNote] on_graph_built received {len(graph)} nodes.")
        
        nodes = []
        for ea, n in graph.items():
            is_lib = getattr(n, 'is_library', False)
            depth = getattr(n, 'depth', -1)
            
            if len(nodes) < 5:
                print(f"[PseudoNote] Node 0x{ea:X}: depth={depth}, is_lib={is_lib}, type={type(n)}")
                
            if not is_lib or depth == 0:
                nodes.append(n)

        nodes.sort(key=lambda n: getattr(n, 'depth', 0))
        
        if not nodes and graph:
            print(f"[PseudoNote] Fallback triggered. Graph size: {len(graph)}")
            nodes = list(graph.values())
            nodes.sort(key=lambda n: getattr(n, 'depth', 0))

        nodes = nodes[:self.func_sp.value()]

        self.func_table.setRowCount(len(nodes))
        for i, node in enumerate(nodes):
            # Checkbox
            cb_container = QtWidgets.QWidget()
            cb_layout = QHBoxLayout(cb_container)
            cb_layout.setContentsMargins(5, 0, 0, 0)
            cb = QCheckBox()
            cb.setChecked(True)
            cb.toggled.connect(lambda _checked: self.update_context_estimate())
            cb_layout.addWidget(cb)
            cb_layout.setAlignment(QtCore.Qt.AlignCenter)
            self.func_table.setCellWidget(i, 0, cb_container)
            
            # Address
            addr_item = QTableWidgetItem(f"0x{node.ea:X}")
            addr_item.setData(QtCore.Qt.UserRole, node.ea)
            addr_item.setFlags(addr_item.flags() ^ QtCore.Qt.ItemIsEditable)
            self.func_table.setItem(i, 1, addr_item)
            
            # Name
            name_item = QTableWidgetItem(node.name)
            name_item.setFlags(name_item.flags() ^ QtCore.Qt.ItemIsEditable)
            self.func_table.setItem(i, 2, name_item)
            
            # Depth
            depth_item = QTableWidgetItem(str(node.depth))
            depth_item.setFlags(depth_item.flags() ^ QtCore.Qt.ItemIsEditable)
            self.func_table.setItem(i, 3, depth_item)
            
        self.status_lbl.setText(f"Graph built: {len(nodes)} functions available.")
        self.update_context_estimate()

    def set_all_checks(self, checked):
        for i in range(self.func_table.rowCount()):
            cw = self.func_table.cellWidget(i, 0)
            if cw:
                cb = cw.findChild(QCheckBox)
                if cb:
                    cb.setChecked(checked)
        self.update_context_estimate()

    def update_context_estimate(self):
        selected = self.get_selected_eas()
        estimated = sum(len(getattr(self.graph.get(ea), "name", "")) + 8000 for ea in selected)
        self.context_estimate.setText(f"{len(selected)} selected • ~{estimated:,} context chars")

        if self.history and selection_signature(selected) != self._context_signature:
            self.status_lbl.setText("Selection changed; context will rebuild with the next question.")

    def _cancel_active_request(self):
        self.request_gate.advance()
        request_id = self._active_request_id
        self._active_request_id = None
        client = _ai_mod.AI_CLIENT
        if request_id is not None and client:
            client.cancel_request(request_id)

    def _request_is_current(self, token):
        return not self._closed and self.request_gate.accepts(token, self.entry_ea)

    def cancel_context_injection(self):
        self._context_cancelled = True
        self._cancel_active_request()
        self.cancel_context_btn.setEnabled(False)
        self.cancel_context_btn.setText("Cancel Context")
        self.chat_input.setEnabled(True)
        self.typing_container.setVisible(False)
        self.status_lbl.setText("Context injection cancelled.")

    def get_selected_eas(self):
        eas = []
        for i in range(self.func_table.rowCount()):
            cw = self.func_table.cellWidget(i, 0)
            if cw:
                cb = cw.findChild(QCheckBox)
                if cb and cb.isChecked():
                    item = self.func_table.item(i, 1)
                    if item:
                        eas.append(item.data(QtCore.Qt.UserRole))
        return eas

    def on_chat_submit(self, text):
        if not _ai_mod.AI_CLIENT:
            QtWidgets.QMessageBox.warning(self, "AI Not Configured", "Configure and test an AI provider first.")
            return
        selected_eas = self.get_selected_eas()
        if not selected_eas:
            QtWidgets.QMessageBox.warning(self, "Selection", "Please select at least one function to talk about.")
            return

        selected_signature = selection_signature(selected_eas)
        if self.history and selected_signature != self._context_signature:
            self._cancel_active_request()
            self.history = []
            self._clear_chat_widgets()
            self.add_chat_message("Function selection changed. A new context snapshot will be created.", is_user=False)
            self.status_lbl.setText("Selection changed; rebuilding AI context...")

        self.add_chat_message(text, is_user=True)
        
        # Prepare context if history is empty
        if not self.history:
            self.status_lbl.setText("Gathering decompiled code...")
            
            code_blocks = []
            def _gather_code():
                for ea in selected_eas:
                    # Request more code (30k chars) to ensure full function logic is captured
                    c = get_code_fast(ea, max_len=60000)
                    if c:
                        name = idc.get_func_name(ea) or f"sub_{ea:X}"
                        code_blocks.append(f"### Function: {name} (0x{ea:X})\n```c\n{c}\n```\n")
            
            idaapi.execute_sync(_gather_code, idaapi.MFF_READ)
            
            if not code_blocks:
                self.add_chat_message("Error: Could not retrieve code.", is_user=False)
                return

            self.pending_question = text
            self.start_context_injection(code_blocks)
        else:
            self.history.append({"role": "user", "content": text})
            self.query_ai()

    def start_context_injection(self, blocks):
        """Create one bounded context snapshot and submit the pending question."""
        self._context_cancelled = False
        self._context_signature = selection_signature(self.get_selected_eas())
        self._context_token = self.request_gate.issue(self.entry_ea)
        snapshot, included, truncated = build_context_snapshot(blocks, max_chars=120000)
        self._context_snapshot = snapshot
        truncation_note = (
            f"\n\nContext budget note: {truncated} selected function(s) were omitted or truncated."
            if truncated else ""
        )
        self.history = [{
            "role": "system",
            "content": (
                "You are a professional reverse-engineering assistant. Analyze only the "
                "provided IDA pseudocode and distinguish evidence from inference. The context "
                f"contains {included} selected function(s).{truncation_note}\n\n{snapshot}"
            ),
        }]
        self.history.append({"role": "user", "content": self.pending_question})
        self.status_lbl.setText(
            f"Analyzing {included} function(s), {len(snapshot):,} context characters"
            + (f"; {truncated} truncated/omitted" if truncated else "")
        )
        self.query_ai(token=self._context_token)

    def query_ai(self, token=None):
        AI_CLIENT = _ai_mod.AI_CLIENT
        if not AI_CLIENT:
            self.add_chat_message("Error: AI Client not configured.", is_user=False)
            self.chat_input.setEnabled(True)
            self.typing_container.setVisible(False)
            return

        self.chat_input.setEnabled(False)
        self.typing_container.setVisible(True)
        self.status_lbl.setText("AI is processing...")
        self.cancel_context_btn.setText("Stop Request")
        self.cancel_context_btn.setEnabled(True)
        
        token = token or self.request_gate.issue(self.entry_ea)

        def fin_cb(response, **kwargs):
            if not self._request_is_current(token):
                return
            self._active_request_id = None
            self.cancel_context_btn.setEnabled(False)
            self.cancel_context_btn.setText("Cancel Context")
            self.typing_container.setVisible(False)
            self.chat_input.setEnabled(True)
            self.chat_input.setFocus()
            
            if response:
                self.history.append({"role": "assistant", "content": response})
                self.add_chat_message(response, is_user=False)
                self.save_history()
                self.status_lbl.setText("Analysis complete.")
            else:
                self.add_chat_message("Error: No response from AI.", is_user=False)
                self.status_lbl.setText("AI Error.")

        self._active_request_id = AI_CLIENT.query_model_async(self.history, fin_cb)

    def add_chat_message(self, text, is_user=True):
        bubble = ChatBubble(text, is_user)
        bubble.set_available_width(self.chat_area.viewport().width())
        
        # Insert before the stretch (which is at index count-1)
        self.chat_layout.insertWidget(self.chat_layout.count() - 1, bubble)
        QtCore.QTimer.singleShot(100, self.scroll_to_bottom)

    def _resize_chat_bubbles(self, width):
        for index in range(self.chat_layout.count()):
            widget = self.chat_layout.itemAt(index).widget()
            if isinstance(widget, ChatBubble):
                widget.set_available_width(width)

    def navigate_to_selected_function(self, _index=None):
        row = self.func_table.currentRow()
        item = self.func_table.item(row, 1) if row >= 0 else None
        if item:
            ida_kernwin.jumpto(int(item.data(QtCore.Qt.UserRole)))

    def show_context_preview(self):
        dialog = QtWidgets.QDialog(self)
        dialog.setWindowTitle("Function Chain Context Preview")
        dialog.resize(850, 600)
        layout = QVBoxLayout(dialog)
        layout.addWidget(QLabel(
            f"{len(self._context_signature)} functions • {len(self._context_snapshot):,} characters"
        ))
        viewer = QtWidgets.QPlainTextEdit(
            self._context_snapshot or "No context snapshot has been created yet."
        )
        viewer.setReadOnly(True)
        layout.addWidget(viewer)
        dialog.exec_()

    def export_conversation(self):
        path = export_chat_log(
            self, "Export Function Chain Chat Log", f"chain_chat_{self.entry_ea:X}.md",
            {"title": "Function Chain Chat", "mode": "function_chain", "entry_address": f"0x{self.entry_ea:X}", "context_function_count": len(self._context_signature)},
            self.history,
            {"selected_functions": list(self._context_signature), "context_characters": len(self._context_snapshot)},
        )
        if path:
            self.status_lbl.setText(f"Conversation exported to {path}")

    def _clear_chat_widgets(self):
        while self.chat_layout.count() > 1:
            item = self.chat_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

    def clear_chat(self):
        if not QtWidgets.QMessageBox.question(self, "Clear Chat", "Clear entire conversation history?") == QtWidgets.QMessageBox.Yes:
            return
        
        # Keep only the stretch
        self._clear_chat_widgets()
        
        self._cancel_active_request()
        self.history = []
        self._context_signature = ()
        self._context_snapshot = ""
        self.save_history()
        self.load_history() # Reload (will show welcome or stay empty)
        self.status_lbl.setText("History cleared.")

    def save_history(self):
        if self.entry_ea == idaapi.BADADDR:
            return
        try:
            if not self.history:
                save_to_idb(self.entry_ea, "", tag=CHAIN_CHAT_HISTORY_TAG)
                return
            data = json.dumps({
                "schema_version": 2,
                "entry_ea": self.entry_ea,
                "binary_id": binary_fingerprint(ida_nalt.get_input_file_path() or ""),
                "graph_eas": sorted(int(ea) for ea in self.graph),
                "context_eas": list(self._context_signature),
                "history": self.history,
            })
            save_to_idb(self.entry_ea, data, tag=CHAIN_CHAT_HISTORY_TAG)
        except Exception as e:
            print(f"[PseudoNote] Error saving history: {e}")

    def load_history(self):
        if self.entry_ea == idaapi.BADADDR:
            return
        try:
            data = load_from_idb(self.entry_ea, tag=CHAIN_CHAT_HISTORY_TAG)
            if data:
                saved = json.loads(data)
                if isinstance(saved, dict):
                    if int(saved.get("schema_version", 1)) > 2:
                        self.status_lbl.setText("Saved chain history uses a newer unsupported format.")
                        return
                    expected_id = binary_fingerprint(ida_nalt.get_input_file_path() or "")
                    if saved.get("entry_ea") != self.entry_ea or (saved.get("binary_id") and saved.get("binary_id") != expected_id):
                        self.status_lbl.setText("Saved chain history belongs to a different graph or binary.")
                        return
                    self.history = normalize_chat_history(saved.get("history", []))
                    self._context_signature = selection_signature(saved.get("context_eas", ()))
                else:
                    self.history = normalize_chat_history(saved)
                legacy_injection = any(
                    "System Context Update" in message.get("content", "")
                    for message in self.history
                )
                if legacy_injection:
                    self._context_signature = ()
                    self.status_lbl.setText("Legacy context detected; it will rebuild on the next question.")
                if self.history and self.history[0].get("role") == "system":
                    content = self.history[0].get("content", "")
                    if "\n\n" in content and not legacy_injection:
                        self._context_snapshot = content.split("\n\n", 1)[1]
                # Populate UI (skip system messages)
                for msg in self.history:
                    if msg.get('role') in ('user', 'assistant'):
                        # Check if it was a system context update message (skip those)
                        content = msg.get('content', '')
                        is_ack = legacy_injection and msg.get('role') == 'assistant' and content.strip().upper() == "OK"
                        if "System Context Update" not in content and not is_ack:
                            self.add_chat_message(content, is_user=(msg.get('role') == 'user'))
                if not legacy_injection:
                    self.status_lbl.setText("History loaded from IDB.")
            else:
                # Show welcome message for new chain
                welcome = "I'm ready to analyze this function chain. Please build the graph, select the functions you're interested in, and ask your first question!"
                self.add_chat_message(welcome, is_user=False)
                # We don't save history yet, wait for first real message
        except Exception as e:
            print(f"[PseudoNote] Error loading history: {e}")

    def scroll_to_bottom(self):
        self.chat_area.verticalScrollBar().setValue(self.chat_area.verticalScrollBar().maximum())

    def closeEvent(self, event):
        self._closed = True
        self._cancel_active_request()
        self.save_history() # Ensure state is saved on close
        if self.worker and self.worker.isRunning():
            self.worker.stop()
            if not self.worker.wait(3000):
                self._closed = False
                self.status_lbl.setText("Graph cancellation is still finishing; close again shortly.")
                event.ignore()
                return
        super().closeEvent(event)

class ChatChainHandler(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)
        self.dlg = None
        
    def activate(self, ctx):
        ea = ctx.cur_ea if ctx.cur_ea != idaapi.BADADDR else idaapi.get_screen_ea()
        f = ida_funcs.get_func(ea)
        if not f:
            print("No function selected.")
            return 1

        from pseudonote_extended.qt_compat import get_ida_main_window
        self.dlg = ChatChainDialog(f.start_ea, parent=None)

        self._wrapper = PluginFormWrapper(self.dlg, "PseudoNote - Ask AI Chain")
        self._wrapper.show_form()
        return 1
        
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS
