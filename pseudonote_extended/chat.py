# -*- coding: utf-8 -*-
"""
AI Chat interface for PseudoNote.
Provides a dockable widget to chat with AI about the current function.
"""

import re
import html
import functools
import os

import idaapi
import ida_kernwin
import ida_hexrays
import idc
import idautils

import json
from pseudonote_extended.qt_compat import QtWidgets, QtCore, QtGui, Signal, qt_cast_flags
from pseudonote_extended.config import CONFIG, LOGGER
import pseudonote_extended.ai_client as _ai_mod
from pseudonote_extended.idb_storage import save_to_idb, load_from_idb
from pseudonote_extended.ui.workspace import RequestGate
from pseudonote_extended.chat_state import normalize_chat_history
from pseudonote_extended.ui.typography import ui_font
from pseudonote_extended.ui.mac_workspace import apply_mac_workspace
from pseudonote_extended.chat_tool_runtime import (
    build_chat_tool_prompt, direct_read_tool, execute_chat_tool, new_chat_policy, parse_agent_response,
)
from pseudonote_extended.chat_export import export_chat_log

CHAT_HISTORY_TAG = 96

CHAT_TOOL_GROUPS = (
    ("Inspect Live IDB", (
        ("Show pseudocode", "prompt", "Show the actual Hex-Rays pseudocode for this function. Use the decompile tool and preserve important addresses."),
        ("Show assembly", "prompt", "Show the actual IDA disassembly for this function. Use the disassemble tool; do not infer assembly from pseudocode."),
        ("Show callers / callees", "prompt", "Use the cross-reference tools to show this function's callers and callees with addresses."),
        ("Show variables / stack", "prompt", "Use the stack-layout tool to show arguments, local variables, locations, and types for this function."),
        ("Show basic blocks", "prompt", "Use the basic-block tool to show this function's control-flow blocks and edges."),
    )),
    ("Understand", (
        ("Explain function", "prompt", "Explain this function step by step, prioritizing the decompiled logic and citing important operations."),
        ("Summarize behavior", "prompt", "Summarize this function's purpose, inputs, outputs, side effects, and important callees."),
        ("Find IOCs / C2", "prompt", "Find any evidence of C2 infrastructure or other IOCs in this function. Cite exact strings and explain confidence."),
        ("Identify vulnerabilities", "prompt", "Review this function for memory-safety, validation, and logic vulnerabilities. Cite the relevant pseudocode."),
    )),
    ("Rename & Types", (
        ("Suggest function name", "action", "pseudonote_extended:rename_function"),
        ("Malware-aware function name", "action", "pseudonote_extended:rename_function_malware"),
        ("Suggest variable names", "action", "pseudonote_extended:rename_variables"),
        ("Suggest function prototype", "action", "pseudonote_extended:suggest_function_prototype"),
        ("Infer / edit structure", "action", "pseudonote_extended:analyze_struct"),
    )),
    ("Document", (
        ("Generate pseudocode comments", "action", "pseudonote_extended:add_comments"),
        ("Open readable code", "action", "pseudonote_extended:readable_code"),
        ("Open analyst notes", "action", "pseudonote_extended:analyst_notes"),
    )),
    ("Inspect", (
        ("Open call tree", "action", "pseudonote_extended:dnspy_xrefs"),
    )),
)

AI_WORKFLOW_ACTIONS = frozenset((
    "pseudonote_extended:rename_function",
    "pseudonote_extended:rename_function_malware",
    "pseudonote_extended:rename_variables",
    "pseudonote_extended:suggest_function_prototype",
    "pseudonote_extended:analyze_struct",
    "pseudonote_extended:add_comments",
))

CONFIRM_CHAT_ACTIONS = {
    "pseudonote_extended:rename_function": "generate and review a suggested function rename",
    "pseudonote_extended:rename_function_malware": "generate and review a malware-aware function rename",
    "pseudonote_extended:rename_variables": "generate and review variable renames",
    "pseudonote_extended:add_comments": "generate and review pseudocode comments",
}


def chat_tool_execution_type(kind, payload):
    """Return the user-facing execution type for a Chat sidebar entry."""
    kind = str(kind or "")
    payload = str(payload or "")
    if kind == "prompt":
        # Explicit display requests are answered directly from the live IDB;
        # the remaining prompts require model analysis.
        return "Tool" if direct_read_tool(payload) else "AI"
    return "AI" if payload in AI_WORKFLOW_ACTIONS else "Tool"

def get_ida_colors():
    """Get theme-aware colors from IDA's palette."""
    app = QtWidgets.QApplication.instance()
    palette = app.palette()

    return {
        "window": palette.color(QtGui.QPalette.Window).name(),
        "window_text": palette.color(QtGui.QPalette.WindowText).name(),
        "base": palette.color(QtGui.QPalette.Base).name(),
        "alt_base": palette.color(QtGui.QPalette.AlternateBase).name(),
        "text": palette.color(QtGui.QPalette.Text).name(),
        "button": palette.color(QtGui.QPalette.Button).name(),
        "button_text": palette.color(QtGui.QPalette.ButtonText).name(),
        "highlight": palette.color(QtGui.QPalette.Highlight).name(),
        "highlight_text": palette.color(QtGui.QPalette.HighlightedText).name(),
        "mid": palette.color(QtGui.QPalette.Mid).name(),
        "dark": palette.color(QtGui.QPalette.Dark).name(),
        "light": palette.color(QtGui.QPalette.Light).name(),
        "link": palette.color(QtGui.QPalette.Link).name(),
    }
def get_chat_font():
    """Get the preferred aesthetic font for chat interactions."""
    return ui_font(11.0)

def markdown_to_html(text):
    """
    Parse Markdown using Qt's native QTextDocument engine for 'proper' results.
    This handles complex structures like lists and nested formatting much better than regex.
    """
    colors = get_ida_colors()
    
    # We use a QTextDocument to convert Markdown to a clean, theme-aware HTML.
    doc = QtGui.QTextDocument()
    
    font = get_chat_font()
    
    # 1. Define a CSS stylesheet that matches IDA's theme for the parsed content
    # Note: QTextDocument supports a limited subset of CSS.
    style = f"""
        body {{ 
            font-family: '{font.family()}';
            font-size: {font.pointSize()}pt;
            color: {colors['text']}; 
            line-height: 1.55;
        }}
        h1, h2, h3 {{ 
            color: {colors['highlight']}; 
            font-weight: bold;
            margin-top: 12px;
            margin-bottom: 4px;
        }}
        h1 {{ font-size: 1.2em; }}
        h2 {{ font-size: 1.1em; border-bottom: 1px solid {colors['mid']}; }}
        h3 {{ font-size: 1.0em; }}
        
        /* Technical terms / Inline code */
        code {{ 
            font-family: 'Consolas', 'Courier New', monospace; 
            color: {colors['link']};
            background-color: transparent;
            font-weight: bold;
        }}
        
        /* Code blocks: Mono with subtle indent, no boxes */
        pre {{ 
            font-family: 'Consolas', 'Courier New', monospace; 
            color: {colors['text']};
            margin: 10px 0;
            padding-left: 10px;
        }}
        
        /* Lists: Proper alignment and spacing */
        li {{ margin-bottom: 2px; }}
        ul, ol {{ margin-left: 15px; padding-left: 5px; }}
        
        a {{ color: {colors['link']}; text-decoration: none; }}
    """
    
    doc.setDefaultStyleSheet(style)
    
    # 2. Native Markdown parsing (Qt 5.14+)
    # This is the "proper" way to handle the conversion.
    doc.setMarkdown(text)
    
    # 3. Handle specific formatting tweaks that setMarkdown might miss in translation
    html_content = doc.toHtml()
    
    # Fix potential 'boxy' behavior in generic HTML generation
    html_content = html_content.replace('border: 1px solid', 'border: none')
    
    return html_content

class ChatBubble(QtWidgets.QWidget):
    def __init__(self, text, is_user=True, parent=None):
        super(ChatBubble, self).__init__(parent)
        self.is_user = is_user
        self.setup_ui(text)

    def setup_ui(self, text):
        colors = get_ida_colors()
        self.setAttribute(QtCore.Qt.WA_TranslucentBackground)
        
        main_layout = QtWidgets.QHBoxLayout(self)
        main_layout.setContentsMargins(10, 4, 10, 4)
        main_layout.setSpacing(0)

        # Bubble Container
        self.bubble = QtWidgets.QFrame()
        bubble_layout = QtWidgets.QVBoxLayout(self.bubble)
        bubble_layout.setContentsMargins(20, 15, 20, 15)
        bubble_layout.setSpacing(4)

        self.label = QtWidgets.QLabel()
        self.label.setWordWrap(True)
        
        # Aesthetic font selection
        font = get_chat_font()
        self.label.setFont(font)

        # Ensure text is selectable by mouse and keyboard, and links are clickable
        self.label.setTextInteractionFlags(QtCore.Qt.TextBrowserInteraction)
        self.label.setOpenExternalLinks(True)
        self.label.setCursor(QtCore.Qt.IBeamCursor)

        if self.is_user:
            # Wrap in a DIV for better selection handling in some Qt versions
            self.label.setTextFormat(QtCore.Qt.RichText)
            self.label.setText(f"<div>{html.escape(text)}</div>")
            
            # Selection visibility fix: Use a slightly different color or specify selection style
            # Actually, using a slightly darker/lighter variant for background or specific selection colors:
            self.bubble.setStyleSheet(f"""
                QFrame {{
                    background-color: {colors['highlight']};
                    border-radius: 20px;
                    border-bottom-right-radius: 4px;
                }}
                QLabel {{
                    color: {colors['highlight_text']};
                    background: transparent;
                    selection-background-color: {colors['base']};
                    selection-color: {colors['text']};
                }}
            """)
            main_layout.addStretch()
            main_layout.addWidget(self.bubble)
        else:
            self.label.setTextFormat(QtCore.Qt.RichText)
            # Use the "Proper" Markdown Parser
            self.label.setText(markdown_to_html(text))
            
            self.bubble.setStyleSheet(f"""
                QFrame {{
                    background-color: {colors['base']};
                    border-radius: 20px;
                    border-bottom-left-radius: 4px;
                }}
                QLabel {{
                    color: {colors['text']};
                    background: transparent;
                }}
            """)
            main_layout.addWidget(self.bubble)
            main_layout.addStretch()

        bubble_layout.addWidget(self.label)
        
        # Reasonable sizing for better readability across various window sizes
        self.set_available_width(720)

    def set_available_width(self, available_width):
        """Keep short messages readable while allowing long answers to breathe."""
        available = max(320, int(available_width or 0) - 24)
        minimum_ratio = 0.24 if self.is_user else 0.38
        minimum_cap = 360 if self.is_user else 440
        minimum = min(minimum_cap, max(260, int(available * minimum_ratio)))
        maximum = min(820, max(minimum, int(available * 0.72)))
        self.bubble.setMinimumWidth(minimum)
        self.bubble.setMaximumWidth(maximum)


class ResponsiveChatScrollArea(QtWidgets.QScrollArea):
    viewportResized = Signal(int)

    def resizeEvent(self, event):
        super(ResponsiveChatScrollArea, self).resizeEvent(event)
        self.viewportResized.emit(self.viewport().width())

class ChatInput(QtWidgets.QWidget):
    submitted = Signal(str)

    def __init__(self, parent=None):
        super(ChatInput, self).__init__(parent)
        self.setup_ui()

    def setup_ui(self):
        input_layout = QtWidgets.QHBoxLayout(self)
        input_layout.setContentsMargins(0, 0, 0, 0)
        input_layout.setSpacing(10)

        colors = get_ida_colors()
        self.input_box = QtWidgets.QPlainTextEdit()
        self.input_box.setPlaceholderText("Ask AI about this function...")
        self.input_box.setMaximumHeight(100)
        self.input_box.setMinimumHeight(45)
        self.input_box.setStyleSheet(f"""
            QPlainTextEdit {{
                background-color: {colors['base']};
                color: {colors['text']};
                border: 1.5px solid {colors['mid']};
                border-radius: 20px;
                padding-left: 15px;
                padding-right: 15px;
                padding-top: 10px;
                font-size: 13px;
            }}
            QPlainTextEdit:focus {{
                border-color: {colors['highlight']};
            }}
        """)
        self.input_box.installEventFilter(self)

        self.send_btn = QtWidgets.QPushButton("⌲")
        self.send_btn.setFixedSize(32, 32)
        self.send_btn.setCursor(QtCore.Qt.PointingHandCursor)
        self.send_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {colors['highlight']};
                color: {colors['highlight_text']};
                border-radius: 16px;
                font-size: 18px;
                font-weight: bold;
                border: none;
                padding: 0 1px 2px 0;
                text-align: center;
                font-family: 'Segoe UI Symbol', 'Apple Symbols', 'Noto Sans Symbols 2';
            }}
            QPushButton:hover {{
                background-color: {colors['light']};
            }}
            QPushButton:disabled {{
                background-color: {colors['mid']};
            }}
        """)
        self.send_btn.clicked.connect(self.submit)

        input_layout.addWidget(self.input_box)
        input_layout.addWidget(self.send_btn)

    def eventFilter(self, obj, event):
        if obj is self.input_box and event.type() == QtCore.QEvent.KeyPress:
            if event.key() in (QtCore.Qt.Key_Return, QtCore.Qt.Key_Enter):
                if not (event.modifiers() & QtCore.Qt.ShiftModifier):
                    self.submit()
                    return True
        return super(ChatInput, self).eventFilter(obj, event)

    def submit(self):
        text = self.input_box.toPlainText().strip()
        if text:
            self.submitted.emit(text)
            self.input_box.clear()

    def setEnabled(self, enabled):
        super(ChatInput, self).setEnabled(enabled)
        self.input_box.setEnabled(enabled)
        self.send_btn.setEnabled(enabled)

    def setFocus(self, reason=QtCore.Qt.OtherFocusReason):
        self.input_box.setFocus(reason)

class IDAChatForm(ida_kernwin.PluginForm):
    def __init__(self, address, function_name, decompiled_code):
        super(IDAChatForm, self).__init__()
        self.address = address
        self.function_name = function_name
        self.decompiled_code = decompiled_code
        self.request_gate = RequestGate()
        self._active_request_id = None
        self._closed = False
        self._continuation_count = 0
        self._chat_tool_rounds = 0
        self._chat_protocol_repairs = 0
        self._max_chat_tool_rounds = 4
        self._chat_finalize_requested = False
        self._chat_tool_signatures = set()
        self._successful_tool_results = []
        self.tool_policy = new_chat_policy()
        
        # System prompt always reflects the current state of decompilation
        self.system_prompt = build_chat_tool_prompt(address, function_name, decompiled_code)
        
        # Load messages from IDB
        self.history = []
        saved_history = load_from_idb(self.address, tag=CHAT_HISTORY_TAG)
        if saved_history and saved_history.strip():
            try:
                self.history = json.loads(saved_history)
            except Exception as e:
                LOGGER.log(f"Failed to load chat history: {e}")
        
        self.history = normalize_chat_history(self.history, self.system_prompt)

    def OnCreate(self, form):
        self.parent = self.FormToPyQtWidget(form)
        self.setup_ui()

    def setup_ui(self):
        colors = get_ida_colors()
        apply_mac_workspace(self.parent)
        
        layout = QtWidgets.QVBoxLayout(self.parent)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # Header
        header = QtWidgets.QFrame()
        header.setStyleSheet(f"background-color: {colors['alt_base']};")
        header_vbox = QtWidgets.QVBoxLayout(header)
        header_vbox.setContentsMargins(20, 10, 20, 10)
        
        h_layout = QtWidgets.QHBoxLayout()
        self.title_label = QtWidgets.QLabel(f'<span style="font-size: 13px; color: {colors["window_text"]};">Analyzing: </span><b style="font-size: 14px; color: {colors["highlight"]}; font-family: monospace;">{self.function_name}</b>')
        h_layout.addWidget(self.title_label)
        h_layout.addStretch()

        preview_btn = QtWidgets.QPushButton("Context Preview")
        preview_btn.clicked.connect(self.show_context_preview)
        h_layout.addWidget(preview_btn)
        export_btn = QtWidgets.QPushButton("Export Log")
        export_btn.clicked.connect(self.export_conversation)
        h_layout.addWidget(export_btn)
        regen_btn = QtWidgets.QPushButton("Regenerate")
        regen_btn.clicked.connect(self.regenerate_last)
        h_layout.addWidget(regen_btn)

        self.allow_changes_cb = QtWidgets.QCheckBox("Enable IDA changes")
        self.allow_changes_cb.setChecked(True)
        self.allow_changes_cb.setToolTip(
            "Allow reviewed rename, comment, prototype, and structure actions. "
            "Each operation still shows a confirmation dialog."
        )
        h_layout.addWidget(self.allow_changes_cb)
        
        clear_btn = QtWidgets.QPushButton("Clear Conversation")
        clear_btn.setFlat(True)
        clear_btn.setStyleSheet(f"QPushButton {{ color: {colors['mid']}; font-weight: 600; font-size: 9pt; }} QPushButton:hover {{ color: {colors['highlight']}; }}")
        clear_btn.clicked.connect(self.clear_chat)
        h_layout.addWidget(clear_btn)
        
        header_vbox.addLayout(h_layout)

        self.auto_context_cb = QtWidgets.QCheckBox("Auto-change context when navigating to a new function")
        self.auto_context_cb.setStyleSheet(f"color: {colors['text']}; font-size: 11px;")
        self.auto_context_cb.setChecked(True)
        header_vbox.addWidget(self.auto_context_cb)
        
        layout.addWidget(header)

        # Chat History
        self.scroll = ResponsiveChatScrollArea()
        self.scroll.setWidgetResizable(True)
        self.scroll.setFrameShape(QtWidgets.QFrame.NoFrame)
        self.scroll.setStyleSheet("background: transparent;")
        
        self.scroll_content = QtWidgets.QWidget()
        self.scroll_layout = QtWidgets.QVBoxLayout(self.scroll_content)
        self.scroll_layout.setContentsMargins(5, 5, 5, 5)
        self.scroll_layout.addStretch()
        
        self.scroll.setWidget(self.scroll_content)
        self.scroll.viewportResized.connect(self._resize_message_bubbles)
        workspace = QtWidgets.QSplitter(QtCore.Qt.Horizontal)
        workspace.setChildrenCollapsible(False)
        workspace.addWidget(self.scroll)
        workspace.addWidget(self._build_tools_panel(colors))
        workspace.setStretchFactor(0, 1)
        workspace.setStretchFactor(1, 0)
        workspace.setSizes([900, 260])
        layout.addWidget(workspace, stretch=1)

        # "Asking AI" Indicator with Progress Bar
        self.typing_container = QtWidgets.QFrame()
        self.typing_container.setMinimumHeight(40)
        self.typing_container.setStyleSheet(f"background-color: {colors['alt_base']}; border-top: 1px solid {colors['mid']};")
        indicator_layout = QtWidgets.QHBoxLayout(self.typing_container)
        indicator_layout.setContentsMargins(15, 0, 15, 0)
        indicator_layout.setSpacing(10)

        self.typing_indicator = QtWidgets.QLabel("Thinking...")
        self.typing_indicator.setStyleSheet(f"color: {colors['highlight']}; font-style: italic; font-weight: bold; font-size: 11px;")
        indicator_layout.addWidget(self.typing_indicator)

        self.chat_progress = QtWidgets.QProgressBar()
        self.chat_progress.setRange(0, 0) # Marquee
        self.chat_progress.setFixedHeight(4)
        self.chat_progress.setTextVisible(False)
        self.chat_progress.setStyleSheet(f"""
            QProgressBar {{ background-color: {colors['window']}; border: none; border-radius: 2px; }}
            QProgressBar::chunk {{ background-color: {colors['highlight']}; border-radius: 2px; }}
        """)
        indicator_layout.addWidget(self.chat_progress, 1)

        self.progress_details = QtWidgets.QLabel("")
        self.progress_details.setStyleSheet(f"color: {colors['text']}; font-size: 10px; font-family: monospace;")
        indicator_layout.addWidget(self.progress_details)

        self.stop_request_btn = QtWidgets.QPushButton("Stop")
        self.stop_request_btn.setToolTip("Cancel the current AI request")
        self.stop_request_btn.clicked.connect(self.stop_request)
        indicator_layout.addWidget(self.stop_request_btn)

        self.typing_container.setVisible(False)
        layout.addWidget(self.typing_container)
        
        # Internal state for tracking chunks
        self._received_chars = 0

        # Input Area
        input_container = QtWidgets.QFrame()
        input_container.setStyleSheet(f"background-color: {colors['window']}; border: none;")
        input_layout = QtWidgets.QVBoxLayout(input_container)
        input_layout.setContentsMargins(15, 10, 15, 15)
        
        self.input_box = ChatInput()
        self.input_box.submitted.connect(self.send_message)
        input_layout.addWidget(self.input_box)
        layout.addWidget(input_container)

        # Initial or Restored messages
        if len(self.history) <= 1:
            welcome_msg = (
                f"I've analyzed this function `{self.function_name}`. How can I help you understand its logic?\n\n"
                "Use the Tools sidebar for common analysis prompts and reviewed IDA actions."
            )
            self.add_message(welcome_msg, is_user=False)
            self.history.append({"role": "assistant", "content": welcome_msg})
            self.save_history()
        else:
            for msg in self.history[1:]: # Skip system prompt
                content = msg.get('content', '')
                role = msg.get('role', '')
                self.add_message(content, is_user=(role == 'user'))

        self.context_timer = QtCore.QTimer(self.parent)
        self.context_timer.timeout.connect(self.check_context_change)
        self.context_timer.start(500)

    def _build_tools_panel(self, colors):
        panel = QtWidgets.QFrame()
        panel.setObjectName("chatToolsPanel")
        panel.setMinimumWidth(220)
        panel.setMaximumWidth(310)
        panel.setStyleSheet(f"""
            QFrame#chatToolsPanel {{ background:{colors['alt_base']}; border-left:1px solid {colors['mid']}; }}
            QLabel#chatToolsTitle {{ font-size:14px; font-weight:700; color:{colors['window_text']}; }}
            QLabel#chatToolsHint {{ font-size:10px; color:{colors['text']}; }}
            QTreeWidget {{ background:transparent; border:0; outline:0; padding:4px; }}
            QTreeWidget::item {{ min-height:27px; padding:2px 6px; border-radius:6px; }}
            QTreeWidget::item:hover {{ background:{colors['button']}; }}
            QTreeWidget::item:selected {{ background:{colors['highlight']}; color:{colors['highlight_text']}; }}
        """)
        panel_layout = QtWidgets.QVBoxLayout(panel)
        panel_layout.setContentsMargins(14, 14, 14, 14)
        panel_layout.setSpacing(6)
        title = QtWidgets.QLabel("Tools")
        title.setObjectName("chatToolsTitle")
        panel_layout.addWidget(title)
        hint = QtWidgets.QLabel("Click prompts  |  Double-click tools and workflows")
        hint.setObjectName("chatToolsHint")
        panel_layout.addWidget(hint)

        self.tools_tree = QtWidgets.QTreeWidget()
        self.tools_tree.setHeaderHidden(True)
        self.tools_tree.setRootIsDecorated(True)
        self.tools_tree.setIndentation(14)
        self.tools_tree.setFocusPolicy(QtCore.Qt.NoFocus)
        self.tools_tree.setSelectionMode(QtWidgets.QAbstractItemView.NoSelection)
        role = int(QtCore.Qt.UserRole)
        for group_name, rows in CHAT_TOOL_GROUPS:
            group = QtWidgets.QTreeWidgetItem([group_name])
            group.setFlags(group.flags() & ~QtCore.Qt.ItemIsSelectable)
            self.tools_tree.addTopLevelItem(group)
            for label, kind, payload in rows:
                execution_type = chat_tool_execution_type(kind, payload)
                item = QtWidgets.QTreeWidgetItem([f"[{execution_type}] {label}"])
                item.setData(0, role, kind)
                item.setData(0, role + 1, payload)
                item.setData(0, role + 2, execution_type)
                if kind == "prompt":
                    tooltip = f"{execution_type}: click once to prepare this chat prompt"
                else:
                    tooltip = f"{execution_type}: double-click to open this workflow or tool"
                item.setToolTip(0, tooltip)
                group.addChild(item)
            group.setExpanded(True)
        self.tools_tree.itemClicked.connect(self._activate_chat_prompt)
        self.tools_tree.itemDoubleClicked.connect(self._activate_chat_action)
        panel_layout.addWidget(self.tools_tree, 1)
        return panel

    def _activate_chat_prompt(self, item, column=0):
        role = int(QtCore.Qt.UserRole)
        if str(item.data(0, role) or "") == "prompt":
            self._activate_chat_tool(item, column)

    def _activate_chat_action(self, item, column=0):
        role = int(QtCore.Qt.UserRole)
        if str(item.data(0, role) or "") == "action":
            self._activate_chat_tool(item, column)

    def _activate_chat_tool(self, item, _column=0):
        role = int(QtCore.Qt.UserRole)
        kind = item.data(0, role)
        payload = item.data(0, role + 1)
        if not kind or not payload:
            return
        if str(kind) == "prompt":
            self.input_box.input_box.setPlainText(str(payload))
            self.input_box.setFocus()
            return

        confirmation = CONFIRM_CHAT_ACTIONS.get(str(payload))
        if confirmation:
            answer = QtWidgets.QMessageBox.question(
                self.parent,
                "Confirm PseudoNote Action",
                f"Are you sure you want to {confirmation}?",
                QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No,
                QtWidgets.QMessageBox.No,
            )
            if answer != QtWidgets.QMessageBox.Yes:
                return

        if str(payload) == "pseudonote_extended:analyze_struct":
            try:
                vdui = ida_hexrays.open_pseudocode(self.address, 0)
                widget = getattr(vdui, "ct", None) if vdui else None
                if widget:
                    ida_kernwin.activate_widget(widget, True)
            except Exception:
                pass
            self.add_message(
                "Infer / Edit Structure needs a specific local variable. "
                "In the pseudocode view, right-click directly on the variable name and choose "
                "PseudoNote → Infer / Edit Structure.",
                is_user=False,
            )
            return

        try:
            vdui = ida_hexrays.open_pseudocode(self.address, 0)
            widget = getattr(vdui, "ct", None) if vdui else None
            if not widget:
                self.add_message("Could not open this function in pseudocode view.", is_user=False)
                return
            ida_kernwin.activate_widget(widget, True)

            def run_action():
                if not ida_kernwin.process_ui_action(str(payload)):
                    self.add_message(
                        f"Could not start `{payload}` in the current IDA context.",
                        is_user=False,
                    )

            QtCore.QTimer.singleShot(0, run_action)
        except Exception as exc:
            self.add_message(f"Tool failed: {exc}", is_user=False)

    def add_message(self, text, is_user=True):
        bubble = ChatBubble(text, is_user)
        bubble.set_available_width(self.scroll.viewport().width())
        self.scroll_layout.insertWidget(self.scroll_layout.count() - 1, bubble)
        QtCore.QTimer.singleShot(
            0, lambda b=bubble: b.set_available_width(self.scroll.viewport().width())
        )
        QtCore.QTimer.singleShot(100, self.scroll_to_bottom)

    def _resize_message_bubbles(self, width):
        for index in range(self.scroll_layout.count()):
            widget = self.scroll_layout.itemAt(index).widget()
            if isinstance(widget, ChatBubble):
                widget.set_available_width(width)

    def _clear_message_widgets(self):
        """Remove message bubbles while preserving the final layout stretch."""
        while self.scroll_layout.count() > 1:
            item = self.scroll_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

    def _render_history(self):
        self._clear_message_widgets()
        for msg in self.history[1:]:
            role = msg.get("role", "")
            if role in ("user", "assistant"):
                self.add_message(msg.get("content", ""), is_user=(role == "user"))

    def _cancel_active_request(self):
        self.request_gate.advance()
        request_id = self._active_request_id
        self._active_request_id = None
        client = _ai_mod.AI_CLIENT
        if request_id is not None and client:
            client.cancel_request(request_id)

    def _request_is_current(self, token):
        return not self._closed and self.request_gate.accepts(token, self.address)

    def stop_request(self):
        if self._active_request_id is None:
            return
        self._cancel_active_request()
        self.typing_container.setVisible(False)
        self.progress_details.setText("")
        self.input_box.setEnabled(True)
        self.add_message("Request cancelled.", is_user=False)

    def scroll_to_bottom(self):
        self.scroll.verticalScrollBar().setValue(self.scroll.verticalScrollBar().maximum())

    def check_context_change(self):
        if not self.auto_context_cb.isChecked():
            return
            
        ea = idaapi.get_screen_ea()
        func = idaapi.get_func(ea)
        if not func:
            return
            
        if func.start_ea != self.address:
            self.change_context(func.start_ea)

    def change_context(self, new_address):
        self._cancel_active_request()
        try:
            cfunc = ida_hexrays.decompile(new_address)
            if not cfunc:
                return
            new_code = str(cfunc)
        except Exception:
            return
            
        new_name = idc.get_func_name(new_address)
        if not new_name:
            return

        old_address = self.address
        old_name = getattr(self, 'function_name', None)
        old_code = getattr(self, 'decompiled_code', None)

        self.save_history()
        
        self.address = new_address
        self.function_name = new_name
        self.decompiled_code = new_code
        
        is_called_from_old = False
        if old_address is not None:
            for xref in idautils.XrefsTo(new_address):
                func = idaapi.get_func(xref.frm)
                if func and func.start_ea == old_address:
                    is_called_from_old = True
                    break
                    
        caller_context = ""
        if is_called_from_old and old_code:
            caller_context = f"\n\nContext - This function is called by `{old_name}`:\n```c\n{old_code}\n```"
        
        self.system_prompt = build_chat_tool_prompt(
            self.address, self.function_name, self.decompiled_code + caller_context,
        )
        
        colors = get_ida_colors()
        self.title_label.setText(f'<span style="font-size: 13px; color: {colors["window_text"]};">Analyzing: </span><b style="font-size: 14px; color: {colors["highlight"]}; font-family: monospace;">{self.function_name}</b>')
        
        self._clear_message_widgets()

        self.history = []
        saved_history = load_from_idb(self.address, tag=CHAT_HISTORY_TAG)
        if saved_history and saved_history.strip():
            try:
                self.history = json.loads(saved_history)
            except Exception as e:
                LOGGER.log(f"Failed to load chat history: {e}")
                
        self.history = normalize_chat_history(self.history, self.system_prompt)
            
        for msg in self.history[1:]:
            content = msg.get('content', '')
            role = msg.get('role', '')
            self.add_message(content, is_user=(role == 'user'))
            
        if len(self.history) <= 1 or "Analyzing... OK, I understand everything." not in self.history[-1].get('content', ''):
            if is_called_from_old:
                transition_msg = f"You changed to `{self.function_name}`. I have included `{old_name}` as caller context - Analyzing... OK, I understand everything. Please ask if you have any questions."
            else:
                transition_msg = f"You changed to `{self.function_name}` - Analyzing... OK, I understand everything. Please ask if you have any questions."
            self.add_message(transition_msg, is_user=False)
            self.history.append({"role": "assistant", "content": transition_msg})
            self.save_history()

    def save_history(self):
        """Persist chat history to IDB."""
        try:
            save_to_idb(self.address, json.dumps(self.history), tag=CHAT_HISTORY_TAG)
        except Exception as e:
            LOGGER.log(f"Failed to save chat history: {e}")

    def show_context_preview(self):
        dialog = QtWidgets.QDialog(self.parent)
        dialog.setWindowTitle(f"Context Preview — {self.function_name}")
        dialog.resize(760, 520)
        layout = QtWidgets.QVBoxLayout(dialog)
        label = QtWidgets.QLabel(f"Function 0x{self.address:X} • {len(self.decompiled_code):,} characters")
        layout.addWidget(label)
        viewer = QtWidgets.QPlainTextEdit(self.decompiled_code)
        viewer.setReadOnly(True)
        layout.addWidget(viewer)
        dialog.exec_()

    def export_conversation(self):
        path = export_chat_log(
            self.parent, "Export PseudoNote Chat Log", f"chat_{self.function_name}.md",
            {"title": "PseudoNote Chat", "mode": "single_function", "function": self.function_name, "address": f"0x{self.address:X}"},
            self.history,
            {"tool_audit": json.loads(self.tool_policy.export_json()), "context": {"decompiled_characters": len(self.decompiled_code)}},
        )
        if path:
            LOGGER.log(f"Chat log exported to {path}")

    def regenerate_last(self):
        if len(self.history) < 2 or self.history[-1].get("role") != "assistant":
            return
        self.history.pop()
        self._continuation_count = 0
        self.save_history()
        self._render_history()
        self.add_message("Regenerating the previous response…", is_user=False)
        client = _ai_mod.AI_CLIENT
        if client:
            self.input_box.setEnabled(False)
            self.typing_container.setVisible(True)
            token = self.request_gate.issue(self.address)
            callback = lambda response, **kwargs: self.handle_response(response, token=token, **kwargs)
            self._active_request_id = client.query_model_async(self.history, callback)

    def clear_chat(self):
        if not ida_kernwin.ask_yn(ida_kernwin.ASKBTN_NO, "Clear chat?") == idaapi.ASKBTN_YES:
            return
        self._cancel_active_request()
        self._clear_message_widgets()
        self.history = [self.history[0]]
        self.save_history()
        self.add_message("Chat cleared.", is_user=False)

    def send_message(self, text):
        self.add_message(text, is_user=True)
        self.history.append({"role": "user", "content": text})
        self.save_history()

        if self._try_direct_read_request(text):
            return
        
        AI_CLIENT = _ai_mod.AI_CLIENT
        if not AI_CLIENT:
            self.add_message("Error: AI Client not initialized.", is_user=False)
            return

        self.input_box.setEnabled(False)
        self.typing_container.setVisible(True)
        self._received_chars = 0
        self._continuation_count = 0
        self._chat_tool_rounds = 0
        self._chat_protocol_repairs = 0
        self._chat_finalize_requested = False
        self.tool_policy = new_chat_policy()
        self.tool_policy.allow_mutations = self.allow_changes_cb.isChecked()
        self._chat_tool_signatures = set()
        self._successful_tool_results = []
        self.progress_details.setText("Connecting...")
        
        # Ensure UI updates immediately
        QtWidgets.QApplication.processEvents()

        def on_chunk(text):
            if not self._request_is_current(token):
                return
            self._received_chars += len(text)
            self.progress_details.setText(f"Streaming: {self._received_chars} chars")

        token = self.request_gate.issue(self.address)
        callback = lambda response, **kwargs: self.handle_response(response, token=token, **kwargs)
        self._active_request_id = AI_CLIENT.query_model_async(self.history, callback, on_chunk=on_chunk)

    def handle_response(self, response, token=None, **kwargs):
        if token is not None and not self._request_is_current(token):
            return
        finish_reason = kwargs.get("finish_reason", "stop")
        
        if finish_reason == "length" and response and self._continuation_count < 2:
            self._continuation_count += 1
            # We don't hide typing indicator if continuing
            self.progress_details.setText(f"Continuing... ({len(response)} chars so far)")
            QtWidgets.QApplication.processEvents()
            
            AI_CLIENT = _ai_mod.AI_CLIENT
            
            # Temporary history for continuation prompt
            # We don't want to pollute real history yet
            cont_history = self.history + [{"role": "assistant", "content": response}]
            cont_prompt = "The previous response was cut off. Please continue from exactly where you left off. Do not repeat what you already said."
            cont_history.append({"role": "user", "content": cont_prompt})
            
            def on_c_chunk(text):
                if token is not None and not self._request_is_current(token):
                    return
                self._received_chars += len(text)
                self.progress_details.setText(f"Streaming (Continued): {self._received_chars} chars")

            def on_c_fin(new_resp, **c_kwargs):
                full_resp = response + (new_resp or "")
                self.handle_response(full_resp, token=token, **c_kwargs)

            self._active_request_id = AI_CLIENT.query_model_async(cont_history, on_c_fin, on_chunk=on_c_chunk)
            return

        self._active_request_id = None

        envelope, envelope_error = parse_agent_response(response or "")
        if envelope is None and envelope_error and '"action"' in str(response or ""):
            if self._chat_protocol_repairs < 1:
                self._chat_protocol_repairs += 1
                self.history.append({
                    "role": "system",
                    "content": (
                        f"Your previous tool envelope was invalid ({envelope_error}). "
                        "Return one corrected JSON envelope only. Use at most four tool calls; "
                        "split additional calls into a later round."
                    ),
                })
                self.progress_details.setText("Correcting invalid tool request...")
                self._request_chat_tool_followup(token)
                return
            response = (
                "The model repeatedly returned an invalid internal tool request, so the investigation "
                "was stopped without displaying protocol JSON. Please retry the skill."
            )
            envelope = {"action": "final", "report": response}
        if envelope and envelope.get("action") == "tools":
            if self._chat_tool_rounds >= self._max_chat_tool_rounds:
                if self._chat_finalize_requested:
                    response = (
                        "I stopped after the regular-chat tool limit was reached. "
                        "Please narrow the request or use Autonomous Investigation for a deeper workflow."
                    )
                    envelope = {"action": "final", "report": response}
                else:
                    self._chat_finalize_requested = True
                    self.history.append({
                        "role": "system",
                        "content": "Tool-round limit reached. Return action=final now using existing evidence.",
                    })
                    self._request_chat_tool_followup(token)
                    return
            if envelope.get("action") != "tools":
                response = envelope["report"]
            else:
                self._chat_tool_rounds += 1
                observations = []
                change_cancelled = False
                changes_disabled = False
                for call in envelope["calls"]:
                    tool_name, args = call["tool"], call["args"]
                    signature = json.dumps(
                        [tool_name, args], sort_keys=True, ensure_ascii=False, default=str
                    )
                    if signature in self._chat_tool_signatures:
                        result = "Skipped: Identical tool call already attempted in this request."
                    else:
                        self._chat_tool_signatures.add(signature)
                        result = execute_chat_tool(
                            self.tool_policy, tool_name, args, self.address, self._confirm_chat_tool,
                        )
                        if not result.startswith(("Error:", "Skipped:")):
                            self._successful_tool_results.append((tool_name, result))
                    if "User denied this IDA-changing tool call" in result:
                        change_cancelled = True
                    if "read-only mode blocks IDA-changing tools" in result:
                        changes_disabled = True
                    observations.append(self.tool_policy.untrusted_result(tool_name, result))
                    summary = result[:220] + ("..." if len(result) > 220 else "")
                    self.add_message(f"Tool `{tool_name}`: {summary}", is_user=False)
                self.history.append({"role": "system", "content": "\n\n".join(observations)})
                if change_cancelled or changes_disabled:
                    response = (
                        "IDA changes are disabled. Turn on Enable IDA changes and ask again; each proposed "
                        "operation will still be shown for review."
                        if changes_disabled else
                        "IDA change cancelled. Nothing was modified. Ask again when you are ready to "
                        "review the proposed operation."
                    )
                    self.history.append({"role": "assistant", "content": response})
                    self.add_message(response, is_user=False)
                    self.typing_container.setVisible(False)
                    self.progress_details.setText("")
                    self.input_box.setEnabled(True)
                    self.input_box.setFocus()
                    self.save_history()
                    return
                self._request_chat_tool_followup(token)
                return

        if envelope and envelope.get("action") == "final":
            response = envelope["report"]
        elif envelope_error and response:
            # Compatibility fallback for providers that ignore the JSON envelope.
            response = response.strip()

        self.typing_container.setVisible(False)
        self.progress_details.setText("")
        self.input_box.setEnabled(True)
        self.input_box.setFocus()
        
        if response:
            self.history.append({"role": "assistant", "content": response})
            self.add_message(response, is_user=False)
            self.save_history()
        else:
            self.add_message("Error: No response from AI.", is_user=False)

    def _direct_read_tool(self, text):
        return direct_read_tool(text)

    def _format_tool_result(self, tool_name, result):
        titles = {
            "decompile": ("Hex-Rays pseudocode", "c"),
            "disassemble": ("IDA disassembly", "asm"),
            "get_xrefs": ("Callers and callees", "text"),
            "stack_layout": ("Variables and stack layout", "text"),
            "basic_blocks": ("Basic blocks", "text"),
        }
        title, language = titles.get(tool_name, (tool_name.replace("_", " ").title(), "text"))
        if str(result).startswith("Error:"):
            return f"**{title} failed:** {result}"
        if tool_name == "stack_layout":
            try:
                rows = json.loads(result)
                lines = []
                for row in rows:
                    roles = []
                    if row.get("argument"): roles.append("argument")
                    if row.get("result"): roles.append("result")
                    role = f" [{', '.join(roles)}]" if roles else ""
                    lines.append(
                        f"- `{row.get('name') or '<unnamed>'}`: "
                        f"`{row.get('type') or 'unknown type'}`{role} — {row.get('location') or 'unknown storage'}"
                    )
                body = "\n".join(lines) if lines else "- No Hex-Rays variables were reported."
                return f"### {title}\n\n{body}"
            except (TypeError, ValueError):
                pass
        if tool_name == "basic_blocks":
            try:
                rows = json.loads(result)
                lines = [
                    "Shows the primary function body's control-flow structure: branches, merges, loops, and exits."
                ]
                for row in rows:
                    successors = row.get("successors") or []
                    destination = ", ".join(f"B{item}" for item in successors) if successors else "exit"
                    lines.append(
                        f"- **B{row.get('id')}**: `{row.get('start')}`–`{row.get('end')}` → {destination}"
                    )
                if not rows:
                    lines.append("- No primary-body blocks were reported.")
                return f"### {title}\n\n" + "\n".join(lines)
            except (TypeError, ValueError):
                pass
        return f"### {title}\n\n```{language}\n{result}\n```"

    def _try_direct_read_request(self, text):
        tool_name = self._direct_read_tool(text)
        if not tool_name:
            return False
        policy = new_chat_policy()
        result = execute_chat_tool(
            policy, tool_name, {"ea": self.address}, self.address,
            lambda *_args: False,
        )
        response = self._format_tool_result(tool_name, result)
        self.history.append({"role": "assistant", "content": response})
        self.add_message(response, is_user=False)
        self.save_history()
        return True

    def _confirm_chat_tool(self, tool_name, args, category):
        preview = json.dumps(args, indent=2, ensure_ascii=False)[:3000]
        dialog = QtWidgets.QMessageBox(self.parent)
        dialog.setWindowTitle("Review IDA Change")
        dialog.setIcon(QtWidgets.QMessageBox.Question)
        dialog.setText(f"Apply the proposed {tool_name} operation?")
        dialog.setInformativeText(
            "Review the arguments below. This operation changes the IDA database."
        )
        dialog.setDetailedText(f"Category: {category}\n\nArguments:\n{preview}")
        apply_btn = dialog.addButton("Apply Change", QtWidgets.QMessageBox.AcceptRole)
        cancel_btn = dialog.addButton("Cancel", QtWidgets.QMessageBox.RejectRole)
        dialog.setDefaultButton(cancel_btn)
        dialog.exec_()
        return dialog.clickedButton() is apply_btn

    def _request_chat_tool_followup(self, token):
        if not self._request_is_current(token):
            return
        client = _ai_mod.AI_CLIENT
        if not client:
            return
        self.typing_container.setVisible(True)
        self.input_box.setEnabled(False)
        self.progress_details.setText("Using IDA tool results...")
        callback = lambda response, **kwargs: self.handle_response(response, token=token, **kwargs)
        self._active_request_id = client.query_model_async(self.history, callback)

    def OnClose(self, form):
        self._closed = True
        self._cancel_active_request()
        self.save_history()
        if getattr(self, "context_timer", None):
            self.context_timer.stop()

_chat_form_instance = None


def show_chat(address):
    """Open or focus the chat widget for a given function."""
    func = idaapi.get_func(address)
    if not func:
        print("[PseudoNote] No function at current address.")
        return

    name = idc.get_func_name(func.start_ea)
    try:
        cfunc = ida_hexrays.decompile(func.start_ea)
        if not cfunc:
            print("[PseudoNote] Failed to decompile function.")
            return
        code = str(cfunc)
    except:
        print("[PseudoNote] Error during decompilation.")
        return

    title = "PseudoNote - Chat About This Function"
    global _chat_form_instance
    widget = ida_kernwin.find_widget(title)
    if widget:
        ida_kernwin.activate_widget(widget, True)
        if _chat_form_instance and _chat_form_instance.address != func.start_ea:
            _chat_form_instance.change_context(func.start_ea)
    else:
        _chat_form_instance = IDAChatForm(func.start_ea, name, code)
        _chat_form_instance.Show(title, options=ida_kernwin.PluginForm.WOPN_DP_RIGHT | ida_kernwin.PluginForm.WOPN_PERSIST)
