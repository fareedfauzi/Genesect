# -*- coding: utf-8 -*-
from pseudonote_extended.qt_compat import QtWidgets, QtCore, QtGui
from pseudonote_extended.decryption_models import DecryptionTarget
from pseudonote_extended.decryption_algorithms import ENGINE
from pseudonote_extended.decryption_apply import apply_comment, apply_patch
import binascii

class DecryptionWorkbenchUI(QtWidgets.QDialog):
    def __init__(self, target: DecryptionTarget, parent=None):
        super().__init__(parent)
        self.target = target
        self.setWindowTitle(f"Decryption Workbench - {target.display_name}")
        self.resize(800, 600)
        self.setup_ui()
        self.update_source_preview()

    def setup_ui(self):
        layout = QtWidgets.QVBoxLayout(self)

        # 10.1 Header
        header_layout = QtWidgets.QHBoxLayout()
        title = QtWidgets.QLabel(f"<b>Decryption Workbench</b>")
        badge = QtWidgets.QLabel(f"[{self.target.source_kind.upper()}] {self.target.patchability}")
        header_layout.addWidget(title)
        header_layout.addWidget(badge)
        header_layout.addStretch()
        layout.addLayout(header_layout)

        # Splitter for Source/Algorithms and Results
        splitter = QtWidgets.QSplitter(QtCore.Qt.Vertical)
        
        # Top Panel
        top_panel = QtWidgets.QWidget()
        top_layout = QtWidgets.QHBoxLayout(top_panel)
        
        # 10.2 Source Card
        source_group = QtWidgets.QGroupBox("Source Preview")
        source_layout = QtWidgets.QVBoxLayout()
        self.source_text = QtWidgets.QPlainTextEdit()
        self.source_text.setReadOnly(True)
        self.source_text.setFont(QtGui.QFont("Consolas", 10))
        source_layout.addWidget(self.source_text)
        source_group.setLayout(source_layout)
        top_layout.addWidget(source_group)
        
        # 10.3 Engine Tabs
        engine_tabs = QtWidgets.QTabWidget()
        
        # Known Algorithms Tab
        known_tab = QtWidgets.QWidget()
        known_layout = QtWidgets.QVBoxLayout(known_tab)
        
        algo_form = QtWidgets.QFormLayout()
        self.algo_combo = QtWidgets.QComboBox()
        for algo_id, algo in ENGINE.registry.items():
            self.algo_combo.addItem(f"{algo.title}", algo_id)
        algo_form.addRow("Algorithm:", self.algo_combo)
        
        self.param_value = QtWidgets.QLineEdit()
        algo_form.addRow("Key/Value (Hex):", self.param_value)
        
        run_btn = QtWidgets.QPushButton("Run Deterministic Algorithm")
        run_btn.clicked.connect(self.on_run_deterministic)
        algo_form.addRow("", run_btn)
        
        known_layout.addLayout(algo_form)
        known_layout.addStretch()
        engine_tabs.addTab(known_tab, "Known Algorithms")
        
        # AI Tab
        ai_tab = QtWidgets.QWidget()
        ai_layout = QtWidgets.QVBoxLayout(ai_tab)
        ai_layout.addWidget(QtWidgets.QLabel("AI Analyze Algorithm - (Phase 3)"))
        ai_layout.addStretch()
        engine_tabs.addTab(ai_tab, "AI Analyze Algorithm")
        
        top_layout.addWidget(engine_tabs)
        splitter.addWidget(top_panel)
        
        # 10.4 Results Card
        results_group = QtWidgets.QGroupBox("Results Preview")
        results_layout = QtWidgets.QVBoxLayout()
        self.results_text = QtWidgets.QPlainTextEdit()
        self.results_text.setReadOnly(True)
        self.results_text.setFont(QtGui.QFont("Consolas", 10))
        results_layout.addWidget(self.results_text)
        results_group.setLayout(results_layout)
        splitter.addWidget(results_group)
        
        layout.addWidget(splitter)
        
        # 10.5 Actions
        actions_layout = QtWidgets.QHBoxLayout()
        
        self.btn_comment = QtWidgets.QPushButton("Add Comment...")
        self.btn_comment.clicked.connect(self.on_add_comment)
        self.btn_comment.setEnabled(False)
        actions_layout.addWidget(self.btn_comment)
        
        self.btn_patch = QtWidgets.QPushButton("Patch Data...")
        self.btn_patch.clicked.connect(self.on_patch_data)
        self.btn_patch.setEnabled(False)
        actions_layout.addWidget(self.btn_patch)
        
        actions_layout.addStretch()
        btn_close = QtWidgets.QPushButton("Close")
        btn_close.clicked.connect(self.accept)
        actions_layout.addWidget(btn_close)
        
        layout.addLayout(actions_layout)

        self.current_output = None

    def update_source_preview(self):
        raw = self.target.raw_bytes
        hex_str = binascii.hexlify(raw).decode('utf-8')
        spaced_hex = ' '.join(hex_str[i:i+2] for i in range(0, len(hex_str), 2))
        ascii_str = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in raw)
        
        display = f"Length: {len(raw)} bytes\n\nHex:\n{spaced_hex}\n\nASCII:\n{ascii_str}"
        self.source_text.setPlainText(display)

    def on_run_deterministic(self):
        algo_id = self.algo_combo.currentData()
        hex_param = self.param_value.text().strip().replace(" ", "")
        
        try:
            if hex_param:
                param_bytes = binascii.unhexlify(hex_param)
            else:
                param_bytes = b""
        except Exception:
            QtWidgets.QMessageBox.warning(self, "Invalid Parameter", "Key/Value must be valid hex.")
            return

        params = {}
        schema = ENGINE.registry[algo_id].parameter_schema
        if "key" in schema:
            params["key"] = param_bytes
        if "value" in schema:
            params["value"] = param_bytes

        try:
            out = ENGINE.run_algorithm(algo_id, self.target.raw_bytes, params)
            self.current_output = out
            self.update_results_preview(out)
            self.btn_comment.setEnabled(True)
            if self.target.patchability == "exact":
                self.btn_patch.setEnabled(True)
        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "Error", f"Execution failed:\n{e}")

    def update_results_preview(self, out: bytes):
        hex_str = binascii.hexlify(out).decode('utf-8')
        spaced_hex = ' '.join(hex_str[i:i+2] for i in range(0, len(hex_str), 2))
        ascii_str = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in out)
        
        display = f"Output Length: {len(out)} bytes\n\nHex:\n{spaced_hex}\n\nASCII:\n{ascii_str}"
        self.results_text.setPlainText(display)

    def on_add_comment(self):
        if not self.current_output: return
        ascii_str = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in self.current_output)
        text, ok = QtWidgets.QInputDialog.getText(self, "Add Comment", "Comment text:", QtWidgets.QLineEdit.Normal, ascii_str)
        if ok and text:
            if apply_comment(self.target, text):
                QtWidgets.QMessageBox.information(self, "Success", "Comment applied.")
            else:
                QtWidgets.QMessageBox.warning(self, "Error", "Failed to apply comment.")

    def on_patch_data(self):
        if not self.current_output: return
        reply = QtWidgets.QMessageBox.question(self, "Confirm Patch", 
                                               f"Are you sure you want to patch {len(self.current_output)} bytes in the IDB?\nThis action will modify the database.", 
                                               QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No)
        if reply == QtWidgets.QMessageBox.Yes:
            if apply_patch(self.target, self.current_output):
                QtWidgets.QMessageBox.information(self, "Success", "IDB patched successfully.")
                self.accept()
            else:
                QtWidgets.QMessageBox.warning(self, "Error", "Failed to patch IDB (bytes mismatch or invalid target).")
