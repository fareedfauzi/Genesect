# -*- coding: utf-8 -*-
"""Export an AI-readable workspace from the current IDB."""

from __future__ import annotations

import csv
import json
import os
import re
import time

import ida_funcs
import ida_hexrays
import ida_kernwin
import ida_lines
import ida_nalt
import ida_segment
import idaapi
import idautils
import idc

from genesect.qt_compat import QtCore, QtWidgets
from genesect.ai_skill_pack import write_skill_pack


def _plain(value):
    try:
        return ida_lines.tag_remove(str(value or ""))
    except Exception:
        return str(value or "")


def _hex(ea):
    return "0x%X" % int(ea)


def _safe_filename(value, fallback="item", limit=150):
    text = _plain(value).strip() or fallback
    text = re.sub(r"[<>:\"/\\|?*\x00-\x1f]+", "_", text)
    text = re.sub(r"\s+", "_", text)
    text = text.strip("._ ")
    if not text:
        text = fallback
    return text[:limit]


def _short_label(value, limit=90):
    text = _plain(value).strip()
    if len(text) <= limit:
        return text
    return text[: limit - 3] + "..."


def _ensure_dir(path):
    if not os.path.isdir(path):
        os.makedirs(path)


def _write_text(path, text):
    parent = os.path.dirname(path)
    if parent:
        _ensure_dir(parent)
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)


def _write_csv(path, headers, rows):
    parent = os.path.dirname(path)
    if parent:
        _ensure_dir(parent)
    with open(path, "w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.writer(handle, delimiter="\t" if path.lower().endswith(".tsv") else ",")
        writer.writerow(headers)
        writer.writerows(rows)


def _input_basename():
    name = ""
    try:
        name = idc.get_root_filename() or ""
    except Exception:
        pass
    if not name:
        try:
            name = os.path.basename(idc.get_input_file_path() or "")
        except Exception:
            pass
    return _safe_filename(name, "idb")


def _default_parent_dir():
    for getter in (
        lambda: os.path.dirname(idc.get_idb_path()),
        lambda: os.path.dirname(idc.get_input_file_path()),
        lambda: os.getcwd(),
    ):
        try:
            path = getter()
            if path and os.path.isdir(path):
                return path
        except Exception:
            continue
    return os.getcwd()


def _selected_output_root(parent=None):
    selected = QtWidgets.QFileDialog.getExistingDirectory(
        parent,
        "Choose AI Workspace Export Location",
        _default_parent_dir(),
    )
    if not selected:
        return ""
    base = os.path.basename(os.path.normpath(selected)).lower()
    if base.endswith("_genesect_ai_workspace") or base == "genesect_ai_workspace":
        return selected
    return os.path.join(selected, "%s_genesect_ai_workspace" % _input_basename())


def _function_rows():
    rows = []
    for ea in idautils.Functions():
        func = ida_funcs.get_func(ea)
        if not func:
            continue
        flags = int(getattr(func, "flags", 0))
        rows.append({
            "ea": int(func.start_ea),
            "end_ea": int(func.end_ea),
            "size": max(0, int(func.end_ea) - int(func.start_ea)),
            "name": ida_funcs.get_func_name(func.start_ea) or idc.get_func_name(func.start_ea) or "",
            "is_library": bool(flags & getattr(ida_funcs, "FUNC_LIB", 0)),
            "is_thunk": bool(flags & getattr(ida_funcs, "FUNC_THUNK", 0)),
            "comment": ida_funcs.get_func_cmt(func, True) or ida_funcs.get_func_cmt(func, False) or "",
        })
    return sorted(rows, key=lambda row: row["ea"])


def _xref_function(frm):
    func = ida_funcs.get_func(int(frm))
    return int(func.start_ea) if func else idaapi.BADADDR


def _callgraph_for_functions(functions, progress=None):
    function_eas = {row["ea"] for row in functions}
    names = {row["ea"]: row["name"] for row in functions}
    edges = set()
    callers = {row["ea"]: set() for row in functions}
    callees = {row["ea"]: set() for row in functions}
    total = len(functions)
    for index, row in enumerate(functions, 1):
        src = row["ea"]
        if progress is not None:
            progress.step("Collecting callgraph %d/%d: %s" % (index, total, _short_label(row["name"])))
        for item_ea in idautils.FuncItems(src):
            for xref in idautils.XrefsFrom(item_ea, 0):
                dst = _xref_function(xref.to)
                if dst == idaapi.BADADDR or dst not in function_eas or dst == src:
                    continue
                edge = (src, dst)
                if edge in edges:
                    continue
                edges.add(edge)
                callees[src].add(dst)
                callers[dst].add(src)
    edge_rows = [
        [_hex(src), names.get(src, ""), _hex(dst), names.get(dst, "")]
        for src, dst in sorted(edges)
    ]
    return callers, callees, edge_rows


def _disassembly_for_function(ea):
    lines = []
    for item_ea in idautils.FuncItems(ea):
        try:
            line = _plain(idc.generate_disasm_line(item_ea, 0))
        except Exception:
            line = ""
        if line:
            lines.append("%s  %s" % (_hex(item_ea), line))
    return "\n".join(lines) + ("\n" if lines else "")


def _decompile_function(ea):
    try:
        cfunc = ida_hexrays.decompile(ea)
        if cfunc:
            return _plain(str(cfunc))
    except Exception as exc:
        return "/* Hex-Rays decompilation failed for %s: %s */\n" % (_hex(ea), exc)
    return "/* Hex-Rays decompilation unavailable for %s */\n" % _hex(ea)


def _collect_strings():
    rows = []
    try:
        strings = idautils.Strings()
        strings.setup(strtypes=getattr(idautils.Strings, "STR_C", 0))
    except Exception:
        strings = idautils.Strings()
    for item in strings:
        try:
            rows.append([_hex(int(item.ea)), str(item)])
        except Exception:
            continue
    return rows


def _collect_imports():
    rows = []
    try:
        qty = int(idaapi.get_import_module_qty())
    except Exception:
        qty = 0
    for index in range(qty):
        module = str(idaapi.get_import_module_name(index) or "")

        def collect(ea, name, ordinal, module_name=module):
            rows.append([module_name, _hex(int(ea)), str(name or ""), str(ordinal or "")])
            return True

        try:
            idaapi.enum_import_names(index, collect)
        except Exception:
            continue
    return rows


def _collect_exports():
    rows = []
    try:
        for index, ordinal, ea, name in idautils.Entries():
            rows.append([str(index), str(ordinal), _hex(int(ea)), str(name or "")])
    except Exception:
        pass
    return rows


def _collect_segments():
    rows = []
    for start_ea in idautils.Segments():
        seg = ida_segment.getseg(start_ea)
        if not seg:
            continue
        rows.append([
            ida_segment.get_segm_name(seg) or "",
            _hex(int(seg.start_ea)),
            _hex(int(seg.end_ea)),
            str(int(seg.perm)),
            str(int(seg.type)),
        ])
    return rows


def _collect_named_addresses():
    rows = []
    try:
        names = idautils.Names()
    except Exception:
        names = []
    for ea, name in names:
        rows.append([_hex(int(ea)), _plain(name)])
    return rows


def _database_metadata():
    input_path = ""
    idb_path = ""
    md5 = ""
    sha256 = ""
    try:
        input_path = idc.get_input_file_path() or ""
    except Exception:
        pass
    try:
        idb_path = idc.get_idb_path() or ""
    except Exception:
        pass
    try:
        md5 = ida_nalt.retrieve_input_file_md5().hex()
    except Exception:
        try:
            md5 = idc.retrieve_input_file_md5().hex()
        except Exception:
            md5 = ""
    try:
        sha256 = ida_nalt.retrieve_input_file_sha256().hex()
    except Exception:
        sha256 = ""
    info = {}
    try:
        inf = idaapi.get_inf_structure()
        info = {
            "processor": str(getattr(inf, "procname", "") or ""),
            "is_64bit": bool(inf.is_64bit()),
            "is_32bit": bool(inf.is_32bit()),
        }
    except Exception:
        pass
    try:
        imagebase = idaapi.get_imagebase()
    except Exception:
        try:
            imagebase = ida_nalt.get_imagebase()
        except Exception:
            imagebase = 0
    return {
        "tool": "Genesect",
        "exported_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "input_file": input_path,
        "idb_file": idb_path,
        "root_filename": _input_basename(),
        "imagebase": _hex(imagebase),
        "md5": md5,
        "sha256": sha256,
        "ida": {
            "version": idaapi.get_kernel_version(),
        },
        "database": info,
    }


class _Progress:
    def __init__(self, parent, maximum):
        self.dialog = QtWidgets.QProgressDialog(
            "Preparing AI workspace export...",
            "Cancel",
            0,
            max(1, int(maximum)),
            parent,
        )
        self.dialog.setWindowTitle("Export AI Workspace")
        self.dialog.setWindowModality(QtCore.Qt.ApplicationModal)
        self.dialog.setMinimumDuration(0)
        self.value = 0
        self.maximum = max(1, int(maximum))

    def step(self, label, amount=1):
        self.value = min(self.maximum, self.value + int(amount))
        self.dialog.setLabelText(label)
        self.dialog.setValue(self.value)
        QtWidgets.QApplication.processEvents()
        if self.dialog.wasCanceled() or ida_kernwin.user_cancelled():
            raise RuntimeError("Export cancelled")

    def close(self):
        self.dialog.setValue(self.maximum)
        self.dialog.close()


def export_ai_workspace(output_root, parent=None):
    metadata = _database_metadata()
    functions = _function_rows()
    total_steps = 12 + (len(functions) * 3)
    progress = _Progress(parent, total_steps)
    counts = {"functions": len(functions)}
    try:
        progress.step("Creating folders...")
        _ensure_dir(output_root)
        _ensure_dir(os.path.join(output_root, "functions"))
        _ensure_dir(os.path.join(output_root, "functions", "decompiled"))
        _ensure_dir(os.path.join(output_root, "functions", "disassembly"))

        callers, callees, edge_rows = _callgraph_for_functions(functions, progress)
        progress.step("Writing callgraph...")
        _write_csv(
            os.path.join(output_root, "functions", "callgraph.tsv"),
            ["caller_ea", "caller_name", "callee_ea", "callee_name"],
            edge_rows,
        )
        counts["call_edges"] = len(edge_rows)

        decompiled_paths = {}
        disassembly_paths = {}
        hexrays_ready = False
        try:
            hexrays_ready = bool(ida_hexrays.init_hexrays_plugin())
        except Exception:
            hexrays_ready = False

        for index, row in enumerate(functions, 1):
            prefix = "%08X_%s" % (row["ea"], _safe_filename(row["name"], "sub"))
            rel_disasm = os.path.join("functions", "disassembly", prefix + ".asm")
            progress.step("Writing disassembly %d/%d: %s" % (index, len(functions), _short_label(row["name"])))
            _write_text(os.path.join(output_root, rel_disasm), _disassembly_for_function(row["ea"]))
            disassembly_paths[row["ea"]] = rel_disasm.replace("\\", "/")

            rel_decomp = os.path.join("functions", "decompiled", prefix + ".c")
            progress.step("Writing decompilation %d/%d: %s" % (index, len(functions), _short_label(row["name"])))
            if hexrays_ready:
                text = _decompile_function(row["ea"])
            else:
                text = "/* Hex-Rays decompiler is not available in this IDA session. */\n"
            _write_text(os.path.join(output_root, rel_decomp), text)
            decompiled_paths[row["ea"]] = rel_decomp.replace("\\", "/")

        index_rows = []
        for row in functions:
            src = row["ea"]
            index_rows.append([
                _hex(src),
                _hex(row["end_ea"]),
                str(row["size"]),
                row["name"],
                "1" if row["is_library"] else "0",
                "1" if row["is_thunk"] else "0",
                ";".join(_hex(ea) for ea in sorted(callers.get(src, set()))),
                ";".join(_hex(ea) for ea in sorted(callees.get(src, set()))),
                decompiled_paths.get(src, ""),
                disassembly_paths.get(src, ""),
                _plain(row["comment"]).replace("\n", " "),
            ])
        progress.step("Writing function index...")
        _write_csv(
            os.path.join(output_root, "functions", "index.tsv"),
            [
                "ea", "end_ea", "size", "name", "is_library", "is_thunk",
                "callers", "callees", "decompiled_path", "disassembly_path", "comment",
            ],
            index_rows,
        )

        progress.step("Writing strings...")
        string_rows = _collect_strings()
        counts["strings"] = len(string_rows)
        _write_csv(os.path.join(output_root, "strings.tsv"), ["ea", "text"], string_rows)

        progress.step("Writing imports...")
        import_rows = _collect_imports()
        counts["imports"] = len(import_rows)
        _write_csv(os.path.join(output_root, "imports.tsv"), ["module", "ea", "name", "ordinal"], import_rows)

        progress.step("Writing exports...")
        export_rows = _collect_exports()
        counts["exports"] = len(export_rows)
        _write_csv(os.path.join(output_root, "exports.tsv"), ["index", "ordinal", "ea", "name"], export_rows)

        progress.step("Writing segments and names...")
        segment_rows = _collect_segments()
        name_rows = _collect_named_addresses()
        counts["segments"] = len(segment_rows)
        counts["names"] = len(name_rows)
        _write_csv(os.path.join(output_root, "segments.tsv"), ["name", "start_ea", "end_ea", "perm", "type"], segment_rows)
        _write_csv(os.path.join(output_root, "names.tsv"), ["ea", "name"], name_rows)

        progress.step("Writing Go/Rust map...")
        try:
            from genesect.go_rust_user_code_map import collect_language_map
            from genesect.go_rust_user_code_map import _hex as gr_hex
            rows, groups = collect_language_map()
            counts["go_rust_functions"] = len(rows)
            counts["go_rust_groups"] = len(groups)
            _write_csv(
                os.path.join(output_root, "go_rust_user_code_map.csv"),
                ["Address", "Language", "Category", "Group", "Function", "Original Name", "Strings", "Imports", "Size"],
                [
                    [
                        gr_hex(row["ea"]), row["language"], row["category"], row["group"],
                        row["display_name"], row["name"], len(row["strings"]),
                        len(row["imports"]), row["size"],
                    ]
                    for row in rows
                ],
            )
        except Exception as exc:
            counts["go_rust_error"] = str(exc)
            _write_text(os.path.join(output_root, "go_rust_user_code_map.error.txt"), str(exc) + "\n")

        progress.step("Writing virtual-class report...")
        try:
            from genesect.virtual_class_explorer import VirtualClassExplorer, recover_virtual_classes
            classes = recover_virtual_classes()
            helper = VirtualClassExplorer()
            helper.classes = classes
            counts["virtual_classes"] = len(classes)
            counts["virtual_vtables"] = sum(len(record["tables"]) for record in classes)
            _write_text(os.path.join(output_root, "virtual_classes.txt"), helper._all_report_text())
        except Exception as exc:
            counts["virtual_class_error"] = str(exc)
            _write_text(os.path.join(output_root, "virtual_classes.error.txt"), str(exc) + "\n")

        progress.step("Writing manifest...")
        metadata["counts"] = counts
        _write_text(os.path.join(output_root, "manifest.json"), json.dumps(metadata, indent=2, sort_keys=True))
        write_skill_pack(output_root, metadata)
        return {"path": output_root, "counts": counts}
    finally:
        progress.close()


class ExportAIWorkspaceHandler(idaapi.action_handler_t):
    def activate(self, ctx):
        if not QtWidgets:
            ida_kernwin.warning("Qt is not available; cannot open the export location picker.")
            return 0
        try:
            parent = QtWidgets.QApplication.activeWindow()
        except Exception:
            parent = None
        output_root = _selected_output_root(parent)
        if not output_root:
            return 0
        try:
            result = export_ai_workspace(output_root, parent)
        except RuntimeError as exc:
            ida_kernwin.warning(str(exc))
            return 0
        except Exception as exc:
            ida_kernwin.warning("Export AI Workspace failed:\n%s" % exc)
            return 0
        counts = result.get("counts", {})
        ida_kernwin.info(
            "AI workspace exported.\n\n"
            "Location: %s\n"
            "Functions: %d\n"
            "Call edges: %d\n"
            "Strings: %d"
            % (
                result.get("path", output_root),
                counts.get("functions", 0),
                counts.get("call_edges", 0),
                counts.get("strings", 0),
            )
        )
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS
