# -*- coding: utf-8 -*-
"""Resolve API hash constants against the bundled apilist.txt corpus."""
import csv
import io
import json
import os
import re
import struct
import zlib

import idaapi
import ida_funcs
import ida_kernwin
import ida_hexrays
import ida_lines
import ida_ua
import idautils
import idc

from pseudonote_extended.qt_compat import QtCore, QtWidgets
from pseudonote_extended import ai_client as _ai_mod
from pseudonote_extended.ui.components import PageHeader, Card
from pseudonote_extended.ui.mac_workspace import apply_mac_workspace


_explorer = None
_API_ENTRIES = None
_MAX_RESULTS = 200000
_API_LIST = os.path.join(os.path.dirname(__file__), "apilist.txt")
_HASH_CONTEXT = {"cmp", "test", "cmn", "mov", "push", "xor", "sub", "add", "lea",
                 "imul", "mul", "rol", "ror", "shl", "shr", "and", "or"}
_CUSTOM_OPS = {"rol", "ror", "add_byte", "sub_byte", "xor_byte",
               "add_const", "xor_const", "mul_const"}


def _u32(value):
    return int(value) & 0xFFFFFFFF


def _ror32(value, count):
    value, count = _u32(value), int(count) & 31
    return _u32((value >> count) | (value << (32 - count)))


def hash_ror13_add(data):
    value = 0
    for byte in data:
        value = _u32(_ror32(value, 13) + byte)
    return value


def hash_djb2(data):
    value = 5381
    for byte in data:
        value = _u32(value * 33 + byte)
    return value


def hash_sdbm(data):
    value = 0
    for byte in data:
        value = _u32(byte + (value << 6) + (value << 16) - value)
    return value


def hash_fnv1a(data):
    value = 0x811C9DC5
    for byte in data:
        value = _u32((value ^ byte) * 0x01000193)
    return value


def hash_jenkins(data):
    value = 0
    for byte in data:
        value = _u32(value + byte)
        value = _u32(value + (value << 10))
        value ^= value >> 6
    value = _u32(value + (value << 3))
    value ^= value >> 11
    return _u32(value + (value << 15))


def hash_ror7_xor(data):
    value = 0
    for byte in data:
        value = _ror32(value, 7) ^ byte
    return _u32(value)


def hash_crc32(data):
    return zlib.crc32(data) & 0xFFFFFFFF


ALGORITHMS = {
    "ROR13 add": lambda module, name: hash_ror13_add(name.encode("ascii", errors="ignore")),
    "ROR13 add uppercase": lambda module, name: hash_ror13_add(name.upper().encode("ascii", errors="ignore")),
    "DJB2": lambda module, name: hash_djb2(name.encode("ascii", errors="ignore")),
    "SDBM": lambda module, name: hash_sdbm(name.encode("ascii", errors="ignore")),
    "FNV-1a 32": lambda module, name: hash_fnv1a(name.encode("ascii", errors="ignore")),
    "Jenkins one-at-a-time": lambda module, name: hash_jenkins(name.encode("ascii", errors="ignore")),
    "CRC32": lambda module, name: hash_crc32(name.encode("ascii", errors="ignore")),
    "ROR7 XOR": lambda module, name: hash_ror7_xor(name.encode("ascii", errors="ignore")),
    "Metasploit ROR13 module+API": lambda module, name: _u32(
        hash_ror13_add((module.upper() + "\0").encode("utf-16le", errors="ignore")) +
        hash_ror13_add((name + "\0").encode("ascii", errors="ignore"))
    ),
}


def _hex(value):
    return "0x%08X" % _u32(value)


def _func_start(ea):
    func = ida_funcs.get_func(ea)
    return int(func.start_ea) if func else idaapi.BADADDR


def _func_name(ea):
    start = _func_start(ea)
    return idc.get_func_name(start) or ("sub_%X" % start if start != idaapi.BADADDR else "")


def load_api_entries():
    global _API_ENTRIES
    if _API_ENTRIES is not None:
        return _API_ENTRIES
    entries, module = [], ""
    with open(_API_LIST, "r", encoding="utf-8", errors="replace") as handle:
        for raw in handle:
            value = raw.strip()
            if not value:
                module = ""
                continue
            if not module:
                module = value
            else:
                entries.append((module, value))
    _API_ENTRIES = entries
    return entries


def extract_hash_candidates(functions):
    candidates = {}
    for func_ea in functions:
        for ea in idautils.FuncItems(func_ea):
            mnemonic = (idc.print_insn_mnem(ea) or "").lower()
            if mnemonic not in _HASH_CONTEXT:
                continue
            for operand in range(3):
                if idc.get_operand_type(ea, operand) != getattr(ida_ua, "o_imm", 5):
                    continue
                value = _u32(idc.get_operand_value(ea, operand))
                if 0x10000 <= value < 0xFFFFFFFF:
                    candidates.setdefault(value, []).append(int(ea))
        if ida_kernwin.user_cancelled():
            break
    return candidates


def resolve_hashes(candidates, algorithm="Auto"):
    wanted = set(_u32(value) for value in candidates)
    selected = ALGORITHMS.items() if algorithm == "Auto" else [(algorithm, ALGORITHMS[algorithm])]
    rows = []
    for module, name in load_api_entries():
        for algorithm_name, function in selected:
            value = function(module, name)
            if value not in wanted:
                continue
            sites = candidates.get(value) or [idaapi.BADADDR]
            collision_count = 0
            for site in sites:
                rows.append({
                    "hash": value, "algorithm": algorithm_name, "module": module, "api": name,
                    "ea": int(site), "function": _func_name(site) if site != idaapi.BADADDR else "Manual query",
                    "evidence": "apilist.txt exact 32-bit hash match",
                })
                collision_count += 1
                if len(rows) >= _MAX_RESULTS:
                    return rows
        if ida_kernwin.user_cancelled():
            break
    groups = {}
    for row in rows:
        groups.setdefault((row["hash"], row["algorithm"]), set()).add((row["module"], row["api"]))
    for row in rows:
        row["collisions"] = len(groups[(row["hash"], row["algorithm"])])
    return sorted(rows, key=lambda row: (row["hash"], row["algorithm"], row["module"].lower(), row["api"].lower(), row["ea"]))


def parse_manual_hashes(text):
    values = {}
    for token in re.split(r"[\s,;]+", str(text or "").strip()):
        if not token:
            continue
        try:
            value = int(token, 0) if token.lower().startswith("0x") else int(token, 16)
        except ValueError:
            continue
        values.setdefault(_u32(value), []).append(idaapi.BADADDR)
    return values


def _parse_ai_json(text):
    """Extract one JSON object from a model response without executing any content."""
    cleaned = re.sub(r"^\s*```(?:json)?\s*|\s*```\s*$", "", str(text or ""), flags=re.I | re.S)
    start, end = cleaned.find("{"), cleaned.rfind("}")
    if start < 0 or end <= start:
        raise ValueError("AI response did not contain a JSON object")
    return json.loads(cleaned[start:end + 1])


def validate_custom_recipe(recipe):
    """Return a normalized, strictly declarative 32-bit hash recipe."""
    if not isinstance(recipe, dict):
        raise ValueError("recipe must be an object")
    if int(recipe.get("width", 32)) != 32:
        raise ValueError("only 32-bit custom hashes are supported")
    try:
        seed = _u32(int(str(recipe.get("seed", 0)), 0))
    except (TypeError, ValueError):
        raise ValueError("seed must be an integer or 0x-prefixed integer")
    components = recipe.get("components") or [{"source": "api", "case": "none", "encoding": "ascii", "include_null": False}]
    if not isinstance(components, list) or not 1 <= len(components) <= 3:
        raise ValueError("components must contain between one and three entries")
    normalized_components = []
    for component in components:
        if not isinstance(component, dict):
            raise ValueError("each component must be an object")
        source = str(component.get("source", "api")).lower()
        casing = str(component.get("case", "none")).lower()
        encoding = str(component.get("encoding", "ascii")).lower()
        if source not in ("api", "module") or casing not in ("none", "upper", "lower"):
            raise ValueError("unsupported component source or case")
        if encoding not in ("ascii", "utf-16le"):
            raise ValueError("unsupported component encoding")
        normalized_components.append({"source": source, "case": casing, "encoding": encoding,
                                      "include_null": bool(component.get("include_null", False))})
    steps = recipe.get("steps")
    if not isinstance(steps, list) or not 1 <= len(steps) <= 12:
        raise ValueError("steps must contain between one and twelve operations")
    normalized_steps = []
    for step in steps:
        if not isinstance(step, dict) or str(step.get("op", "")).lower() not in _CUSTOM_OPS:
            raise ValueError("recipe contains an unsupported operation")
        op = str(step["op"]).lower()
        normalized = {"op": op}
        if op in ("rol", "ror", "add_const", "xor_const", "mul_const"):
            try:
                normalized["value"] = _u32(int(str(step.get("value")), 0))
            except (TypeError, ValueError):
                raise ValueError("%s requires an integer value" % op)
            if op in ("rol", "ror") and not 1 <= normalized["value"] <= 31:
                raise ValueError("rotation count must be between 1 and 31")
        normalized_steps.append(normalized)
    return {"width": 32, "seed": seed, "components": normalized_components, "steps": normalized_steps}


def apply_custom_recipe(module, name, recipe):
    recipe = validate_custom_recipe(recipe)
    return _apply_validated_recipe(module, name, recipe)


def _apply_validated_recipe(module, name, recipe):
    value = recipe["seed"]
    for component in recipe["components"]:
        text = module if component["source"] == "module" else name
        if component["case"] == "upper":
            text = text.upper()
        elif component["case"] == "lower":
            text = text.lower()
        if component["include_null"]:
            text += "\0"
        for byte in text.encode(component["encoding"], errors="ignore"):
            for step in recipe["steps"]:
                op, operand = step["op"], step.get("value", 0)
                if op == "ror": value = _ror32(value, operand)
                elif op == "rol": value = _u32((value << operand) | (value >> (32 - operand)))
                elif op == "add_byte": value = _u32(value + byte)
                elif op == "sub_byte": value = _u32(value - byte)
                elif op == "xor_byte": value = _u32(value ^ byte)
                elif op == "add_const": value = _u32(value + operand)
                elif op == "xor_const": value = _u32(value ^ operand)
                elif op == "mul_const": value = _u32(value * operand)
    return _u32(value)


def resolve_custom_hashes(candidates, recipe, label="AI-inferred custom hash"):
    recipe = validate_custom_recipe(recipe)
    wanted, rows = set(_u32(value) for value in candidates), []
    for module, name in load_api_entries():
        value = _apply_validated_recipe(module, name, recipe)
        if value in wanted:
            for site in candidates.get(value) or [idaapi.BADADDR]:
                rows.append({"hash": value, "algorithm": label, "module": module, "api": name,
                             "ea": int(site), "function": _func_name(site) if site != idaapi.BADADDR else "Manual query",
                             "evidence": "AI-inferred recipe; locally validated against apilist.txt"})
                if len(rows) >= _MAX_RESULTS: break
        if len(rows) >= _MAX_RESULTS: break
    groups = {}
    for row in rows:
        groups.setdefault(row["hash"], set()).add((row["module"], row["api"]))
    for row in rows:
        row["collisions"] = len(groups[row["hash"]])
    return rows


def _function_context(func_ea):
    pseudocode = ""
    try:
        cfunc = ida_hexrays.decompile(func_ea)
        if cfunc:
            pseudocode = str(cfunc)
    except Exception:
        pass
    assembly = []
    for ea in idautils.FuncItems(func_ea):
        line = idc.generate_disasm_line(ea, 0) or ""
        assembly.append("0x%X: %s" % (ea, ida_lines.tag_remove(line)))
        if len(assembly) >= 400: break
    return pseudocode[:30000], "\n".join(assembly)[:30000]


class APIHashExplorer(ida_kernwin.PluginForm):
    def __init__(self):
        super().__init__()
        self.rows = []

    def OnCreate(self, form):
        self.parent = self.FormToPyQtWidget(form)
        apply_mac_workspace(self.parent)
        root = QtWidgets.QVBoxLayout(self.parent)
        root.setContentsMargins(16, 14, 16, 14)
        root.setSpacing(10)
        header = PageHeader("API Hash Explorer", "Resolve immediate constants against bundled apilist.txt using common malware API-hash algorithms")
        current = QtWidgets.QPushButton("Scan Current Function")
        current.setProperty("pnVariant", "primary")
        current.clicked.connect(self.scan_current)
        header.add_action(current)
        all_idb = QtWidgets.QPushButton("Scan Entire IDB")
        all_idb.clicked.connect(self.scan_all)
        header.add_action(all_idb)
        self.ai_custom = QtWidgets.QPushButton("Analyze Custom Hash (AI)")
        self.ai_custom.clicked.connect(self.analyze_custom_hash)
        header.add_action(self.ai_custom)
        export = QtWidgets.QPushButton("Export CSV")
        export.clicked.connect(self.export_csv)
        header.add_action(export)
        root.addWidget(header)
        query = QtWidgets.QHBoxLayout()
        self.hash_input = QtWidgets.QLineEdit()
        self.hash_input.setPlaceholderText("Enter hash values, for example 0xEC0E4E8E, 7C0DFCAA")
        query.addWidget(self.hash_input, 1)
        self.algorithm = QtWidgets.QComboBox()
        self.algorithm.addItem("Auto")
        self.algorithm.addItems(list(ALGORITHMS.keys()))
        query.addWidget(self.algorithm)
        resolve = QtWidgets.QPushButton("Resolve Hash")
        resolve.clicked.connect(self.resolve_manual)
        query.addWidget(resolve)
        root.addLayout(query)
        self.filter_edit = QtWidgets.QLineEdit()
        self.filter_edit.setPlaceholderText("Filter hash, algorithm, module, API, function, or evidence...")
        self.filter_edit.setClearButtonEnabled(True)
        self.filter_edit.textChanged.connect(self.apply_filter)
        root.addWidget(self.filter_edit)
        splitter = QtWidgets.QSplitter(QtCore.Qt.Horizontal)
        table_card = Card()
        self.table = QtWidgets.QTableWidget(0, 8)
        self.table.setHorizontalHeaderLabels(["Hash", "Algorithm", "Module", "API", "Use Site", "Function", "Collisions", "Evidence"])
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
        detail_card = Card("Hash resolution")
        self.details = QtWidgets.QTextBrowser()
        detail_card.add_widget(self.details)
        splitter.addWidget(detail_card)
        splitter.setSizes([1020, 410])
        root.addWidget(splitter, 1)
        self.status = QtWidgets.QLabel("Ready")
        self.status.setProperty("pnMuted", True)
        root.addWidget(self.status)

    def _resolve(self, candidates, label):
        if not candidates:
            ida_kernwin.warning("No eligible 32-bit hash constants were found.")
            return
        ida_kernwin.show_wait_box("%s against apilist.txt...\nPress Cancel to stop safely." % label)
        try:
            self.rows = resolve_hashes(candidates, self.algorithm.currentText())
        except Exception as exc:
            self.rows = []
            ida_kernwin.warning("API Hash Explorer failed:\n%s" % exc)
        finally:
            ida_kernwin.hide_wait_box()
        self.populate(len(candidates))

    def scan_current(self):
        func_ea = _func_start(idaapi.get_screen_ea())
        if func_ea == idaapi.BADADDR:
            ida_kernwin.warning("Place the cursor inside a function first.")
            return
        self._resolve(extract_hash_candidates([func_ea]), "Resolving current-function constants")

    def scan_all(self):
        self._resolve(extract_hash_candidates(list(idautils.Functions())), "Resolving IDB constants")

    def resolve_manual(self):
        candidates = parse_manual_hashes(self.hash_input.text())
        if not candidates:
            ida_kernwin.warning("Enter at least one hexadecimal hash value.")
            return
        self._resolve(candidates, "Resolving supplied hashes")

    def analyze_custom_hash(self):
        func_ea = _func_start(idaapi.get_screen_ea())
        if func_ea == idaapi.BADADDR:
            ida_kernwin.warning("Place the cursor inside the custom API resolver first.")
            return
        candidates = extract_hash_candidates([func_ea])
        pseudocode, assembly = _function_context(func_ea)
        if not pseudocode and not assembly:
            ida_kernwin.warning("Could not read the current function.")
            return
        preview = QtWidgets.QMessageBox(self.parent)
        preview.setWindowTitle("Share Resolver with AI")
        preview.setIcon(QtWidgets.QMessageBox.Warning)
        preview.setText("Send this function to the configured AI provider?")
        preview.setInformativeText("PseudoNote will share up to 30,000 characters each of pseudocode and disassembly from %s. No other IDB functions are included." % _func_name(func_ea))
        preview.setDetailedText("PSEUDOCODE\n%s\n\nDISASSEMBLY\n%s" % (pseudocode or "Unavailable", assembly))
        preview.setStandardButtons(QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.Cancel)
        preview.setDefaultButton(QtWidgets.QMessageBox.Cancel)
        if preview.exec_() != QtWidgets.QMessageBox.Yes:
            self.status.setText("Custom-hash AI analysis cancelled; no IDB content was sent.")
            return
        schema = '''Return JSON only using this schema:
{"summary":"short evidence-based description","confidence":"low|medium|high","recipe":{"width":32,"seed":"0x0","components":[{"source":"api|module","case":"none|upper|lower","encoding":"ascii|utf-16le","include_null":false}],"steps":[{"op":"ror|rol|add_byte|sub_byte|xor_byte|add_const|xor_const|mul_const","value":"required only for rotate/const ops"}]},"evidence":["address and instruction"]}
Operations run in listed order for every byte. Use multiple components when module and API names are combined. Do not return Python or prose outside JSON. If this is not an API-name hash, set recipe to null and explain why.'''
        prompt = [{"role": "system", "content": "You analyze malware API hashing routines from Hex-Rays pseudocode and IDA disassembly. Infer only behavior supported by direct evidence. " + schema},
                  {"role": "user", "content": "Analyze the resolver at 0x%X. Candidate constants: %s\n\nPSEUDOCODE:\n%s\n\nDISASSEMBLY:\n%s" %
                   (func_ea, ", ".join(_hex(value) for value in sorted(candidates)) or "none", pseudocode or "unavailable", assembly)}]
        self.ai_custom.setEnabled(False)
        self.status.setText("AI is analyzing the custom hash routine...")
        def finished(response=None, **kwargs):
            self.ai_custom.setEnabled(True)
            if kwargs.get("error"):
                self.status.setText("Custom-hash analysis failed: %s" % kwargs["error"])
                return
            try:
                result = _parse_ai_json(response)
                if not result.get("recipe"):
                    self.status.setText("AI found no supported API hash recipe: %s" % result.get("summary", "No reason supplied"))
                    self._show_ai_recipe(result, None, 0)
                    return
                recipe = validate_custom_recipe(result["recipe"])
                self.rows = resolve_custom_hashes(candidates, recipe)
                self.populate(len(candidates))
                self.status.setText("AI recipe validated locally | %d candidates | %d API matches" % (len(candidates), len(self.rows)))
                self._show_ai_recipe(result, recipe, len(self.rows))
            except Exception as exc:
                self.status.setText("Rejected AI recipe: %s" % exc)
                ida_kernwin.warning("The AI response was not a safe, valid custom-hash recipe:\n%s" % exc)
        try:
            _ai_mod.AI_CLIENT.query_model_async(prompt, finished, additional_options={"temperature": 0.1, "max_completion_tokens": 2500})
        except Exception as exc:
            self.ai_custom.setEnabled(True)
            self.status.setText("Could not start AI analysis: %s" % exc)

    def _show_ai_recipe(self, result, recipe, match_count):
        dialog = QtWidgets.QDialog(self.parent)
        dialog.setWindowTitle("Custom API Hash Analysis")
        dialog.resize(680, 520)
        layout = QtWidgets.QVBoxLayout(dialog)
        layout.addWidget(PageHeader("Custom hash analysis", "%s confidence • %d apilist.txt matches" %
                                    (str(result.get("confidence", "unknown")).title(), match_count)))
        report = QtWidgets.QPlainTextEdit()
        report.setReadOnly(True)
        report.setPlainText("Summary\n%s\n\nEvidence\n%s\n\nValidated recipe\n%s" %
                            (result.get("summary", ""), "\n".join("• " + str(item) for item in result.get("evidence", [])) or "None supplied",
                             json.dumps(recipe, indent=2) if recipe else "No supported recipe"))
        layout.addWidget(report, 1)
        buttons = QtWidgets.QDialogButtonBox(QtWidgets.QDialogButtonBox.Close)
        buttons.rejected.connect(dialog.reject)
        layout.addWidget(buttons)
        dialog.exec_()

    def populate(self, candidate_count=0):
        self.table.setSortingEnabled(False)
        self.table.setRowCount(len(self.rows))
        for row_index, row in enumerate(self.rows):
            site = _hex(row["ea"]) if row["ea"] != idaapi.BADADDR else "Manual"
            values = [_hex(row["hash"]), row["algorithm"], row["module"], row["api"], site, row["function"], str(row["collisions"]), row["evidence"]]
            for column, value in enumerate(values):
                item = QtWidgets.QTableWidgetItem(value)
                item.setData(QtCore.Qt.UserRole, row_index)
                self.table.setItem(row_index, column, item)
        self.table.resizeColumnsToContents()
        self.table.setColumnWidth(7, max(350, self.table.columnWidth(7)))
        self.table.setSortingEnabled(True)
        self.apply_filter(self.filter_edit.text())
        unique_hashes = len(set(row["hash"] for row in self.rows))
        self.status.setText("%d candidates | %d matched hashes | %d API/module matches" % (candidate_count, unique_hashes, len(self.rows)))

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
            row = self.rows[int(self.table.item(row_index, 0).data(QtCore.Qt.UserRole))]
            self.table.setRowHidden(row_index, bool(needle and needle not in " ".join(str(value) for value in row.values()).lower()))

    def show_details(self):
        row = self.selected_row()
        if not row:
            self.details.setPlainText("Select a resolved hash to inspect it.")
            return
        collision_note = "Unique match for this algorithm." if row["collisions"] == 1 else "%d API names share this hash; validate call context." % row["collisions"]
        self.details.setPlainText("Hash: %s\nAlgorithm: %s\nModule: %s\nAPI: %s\nUse site: %s\nFunction: %s\n\nEvidence: %s\n\n%s\n\nHash matches are candidates; confirm the resolver algorithm and calling context." % (_hex(row["hash"]), row["algorithm"], row["module"], row["api"], _hex(row["ea"]) if row["ea"] != idaapi.BADADDR else "Manual query", row["function"], row["evidence"], collision_note))

    def navigate_selected(self, *_args):
        row = self.selected_row()
        if row and row["ea"] != idaapi.BADADDR:
            ida_kernwin.jumpto(row["ea"])

    def _csv_text(self):
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["Hash", "Algorithm", "Module", "API", "Use site", "Function", "Collisions", "Evidence"])
        for row in self.rows:
            writer.writerow([_hex(row["hash"]), row["algorithm"], row["module"], row["api"], _hex(row["ea"]) if row["ea"] != idaapi.BADADDR else "", row["function"], row["collisions"], row["evidence"]])
        return output.getvalue()

    def export_csv(self):
        path, _selected = QtWidgets.QFileDialog.getSaveFileName(self.parent, "Export API Hash Matches", "api_hash_matches.csv", "CSV files (*.csv)")
        if path:
            with open(path, "w", encoding="utf-8-sig", newline="") as handle:
                handle.write(self._csv_text())
            self.status.setText("Exported %d matches to %s" % (len(self.rows), os.path.basename(path)))

    def OnClose(self, form):
        global _explorer
        if _explorer is self:
            _explorer = None


def show_api_hash_explorer():
    global _explorer
    if _explorer is None:
        _explorer = APIHashExplorer()
    _explorer.Show("PseudoNote - API Hash Explorer", options=ida_kernwin.PluginForm.WOPN_PERSIST)


class APIHashExplorerHandler(idaapi.action_handler_t):
    def activate(self, ctx):
        show_api_hash_explorer()
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS
