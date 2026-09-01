"""Small semantic SVG icon family for IDA actions."""

COLORS = {
    "workspace": "#3978D6", "inspect": "#0F9F95", "analysis": "#7456D8",
    "change": "#E58A00", "bulk": "#5B62D6", "utility": "#5F6F83",
    "external": "#168AC2", "copy": "#219653", "settings": "#738296",
}

_LOADED = []


def _brand_svg(action):
    """Return an embedded, menu-sized brand mark for external pivots."""
    overlay = ""
    if action.endswith("bytes_vt") or action.endswith("bytes_cyberchef"):
        overlay = '<path d="M11.4 11.2h3v3h-3z" fill="#FFFFFF" stroke="#172B4D" stroke-width=".45"/>'
    elif action.endswith("str_vt") or action.endswith("str_cyberchef"):
        overlay = '<path d="M11.2 11.2h3.2v1h-1.1v2h-1v-2h-1.1z" fill="#FFFFFF" stroke="#172B4D" stroke-width=".35"/>'

    if action in ("search_bytes_vt", "search_str_vt"):
        body = '''<circle cx="8" cy="8" r="7" fill="#394EFF"/>
<path d="M3.5 4.1h5.2l3.8 3.9-3.8 3.9H3.5L7.3 8z" fill="#FFFFFF"/>''' + overlay
    elif action == "search_str_google":
        body = '''<path d="M13.7 8.2c0-.5-.1-1-.2-1.4H8v2.7h3.1a2.7 2.7 0 0 1-1.2 1.7v1.8h2.3c1.3-1.2 2.1-2.9 2.1-4.8z" fill="#4285F4"/>
<path d="M8 14c1.9 0 3.4-.6 4.6-1.7l-2.3-1.8c-.6.4-1.4.7-2.3.7-1.8 0-3.3-1.2-3.8-2.8H1.9v1.8A7 7 0 0 0 8 14z" fill="#34A853"/>
<path d="M4.2 8.4A4.2 4.2 0 0 1 4 7.2c0-.4.1-.8.2-1.2V4.2H1.9A7 7 0 0 0 1 7.2c0 1.1.3 2.1.9 3z" fill="#FBBC05"/>
<path d="M8 3.2c1 0 2 .4 2.7 1.1l2-2A6.8 6.8 0 0 0 8 .5 7 7 0 0 0 1.9 4.2L4.2 6C4.7 4.4 6.2 3.2 8 3.2z" fill="#EA4335"/>'''
    elif action == "search_str_github":
        body = '''<circle cx="8" cy="8" r="7.2" fill="#181717"/>
<path d="M8 3.1a4.9 4.9 0 0 0-1.6 9.5v-1.1c-1.3.3-1.6-.6-1.6-.6-.2-.6-.6-.8-.6-.8-.5-.4 0-.4 0-.4.6 0 .9.6.9.6.5.9 1.2.6 1.4.5 0-.4.2-.7.4-.8-1.1-.1-2.2-.5-2.2-2.4 0-.5.2-1 .5-1.3-.1-.1-.2-.6 0-1.3 0 0 .4-.1 1.4.5a4.8 4.8 0 0 1 2.6 0c1-.6 1.4-.5 1.4-.5.2.7.1 1.2 0 1.3.3.3.5.8.5 1.3 0 1.9-1.1 2.3-2.2 2.4.2.2.4.5.4 1v2.1A4.9 4.9 0 0 0 8 3.1z" fill="#FFFFFF"/>'''
    elif action == "search_str_msdn":
        body = '''<rect x="1" y="1" width="6.4" height="6.4" fill="#F25022"/><rect x="8.6" y="1" width="6.4" height="6.4" fill="#7FBA00"/><rect x="1" y="8.6" width="6.4" height="6.4" fill="#00A4EF"/><rect x="8.6" y="8.6" width="6.4" height="6.4" fill="#FFB900"/>'''
    elif action in ("search_bytes_cyberchef", "search_str_cyberchef"):
        body = '''<rect x="1" y="1" width="14" height="14" rx="3" fill="#F08A24"/>
<path d="M4 7.1c0-1 .8-1.8 1.8-1.8.3-1.2 1.3-2 2.5-2s2.2.8 2.5 2c1 0 1.8.8 1.8 1.8 0 .8-.5 1.5-1.2 1.7v3H5.2v-3A1.8 1.8 0 0 1 4 7.1zM5.2 10h6.2" fill="#FFFFFF" stroke="#7A3E00" stroke-width=".7" stroke-linejoin="round"/>''' + overlay
    else:
        return None
    return ('''<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 16 16" shape-rendering="geometricPrecision">%s</svg>''' % body).encode("utf-8")


def _svg(color, glyph, variant=0):
    # Flat geometry remains legible in IDA's 16px menus. ``variant`` is retained
    # as non-visual metadata for stable per-action asset identity.
    return f'''<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 16 16" shape-rendering="geometricPrecision" data-variant="{variant}">
<rect x="0.75" y="0.75" width="14.5" height="14.5" rx="2.5" fill="{color}" stroke="#0F172A" stroke-opacity="0.22" stroke-width="0.5"/>
<path d="{glyph}" fill="none" stroke="#FFFFFF" stroke-width="1.32" stroke-linecap="round" stroke-linejoin="round"/>
</svg>'''.encode("utf-8")


GLYPHS = {
    "workspace": "M4 4.5h8M4 7.5h8M4 10.5h5",
    "inspect": "M6.5 4a3 3 0 1 0 0 6 3 3 0 0 0 0-6m2.2 5.2L12 12.5",
    "analysis": "M4 11l2.2-3 2 1.5L12 4M10 4h2v2",
    "change": "M4 11.5l.5-2.5L10 3.5l2.5 2.5L7 11.5z",
    "bulk": "M4 4h3v3H4zM9 4h3v3H9zM4 9h3v3H4zM9 9h3v3H9z",
    "utility": "M5 4h6v8H5zM7 6h2M7 8h2M7 10h2",
    "external": "M4 5v7h7M8 4h4v4M7 9l5-5",
    "copy": "M5 5h6v7H5zM3.5 10V3.5H9",
    "settings": "M8 5.2a2.8 2.8 0 1 0 0 5.6 2.8 2.8 0 0 0 0-5.6M8 3v2M8 11v2M3 8h2M11 8h2",
    "document": "M4 2.8h5l3 3V13H4zM9 3v3h3M6 8h4M6 10h4",
    "note": "M3.5 3h9v8h-6l-3 2zM5.5 6h5M5.5 8h4",
    "archive": "M3 4h10v2H3zM4 6h8v7H4zM6.5 8h3",
    "chat": "M3 3.5h10v7H7l-3 2v-2H3zM5.5 6.5h5",
    "chain": "M6.5 5H5a2 2 0 0 0 0 4h2M9.5 5H11a2 2 0 0 1 0 4H9M6.5 7h3",
    "summary": "M3.5 4h9M3.5 7h6M3.5 10h8M3.5 13h5",
    "agent": "M5 5h6v6H5zM7 2.5v2M5.5 8h.1M10.5 8h.1M7 10h2",
    "rename": "M3 11l5-7 4 4-7 5H3zM9.5 3.5l3 3",
    "variable": "M3 4h3l2 8 2-8h3M5 8h6",
    "prototype": "M3 4h4M3 8h7M3 12h4M9 3l4 5-4 5",
    "structure": "M3 3h10v10H3zM3 7h10M7 3v10M7 10h6",
    "comment": "M3 3.5h10v7H7l-3 2v-2H3zM5 6h6M5 8h4",
    "trash": "M4 5h8M6 5V3h4v2M5 5l.7 8h4.6l.7-8M7 7v4M9 7v4",
    "terminal": "M3 3h10v10H3zM5 6l2 2-2 2M8.5 10h2.5",
    "hex": "M5 3h6l3 5-3 5H5L2 8zM6 6v4M10 6v4M5 8h6",
    "highlight": "M3 12l3-8h4l3 8M4.5 9.5h7",
    "indent": "M3 3v10M6 5h7M6 8h5M6 11h7",
    "zoom": "M6.5 3.5a3 3 0 1 0 0 6 3 3 0 0 0 0-6M8.7 8.7L13 13M6.5 5v3M5 6.5h3",
    "global": "M8 2.5a5.5 5.5 0 1 0 0 11 5.5 5.5 0 0 0 0-11M2.8 8h10.4M8 2.5c2 2.2 2 8.8 0 11M8 2.5c-2 2.2-2 8.8 0 11",
    "tree": "M8 3v3M4 9V7h8v2M3 9h3v3H3zM7 9h3v3H7zM11 9h3v3h-3z",
    "class": "M3 3h10v10H3zM3 6h10M6 8h4M6 10h4",
    "callback": "M3 4h5v4H3zM8 6h3a2 2 0 0 1 0 4h-1M9 8l2 2-2 2",
    "thread": "M3 4h6M3 8h10M3 12h6M10 3l3 1-3 1M10 11l3 1-3 1",
    "exception": "M8 2.5l6 11H2zM8 6v3M8 11h.1",
    "kernel": "M8 2.5l5 2v3.5c0 3-2 4.5-5 5.5C5 12.5 3 11 3 8V4.5zM6 8h4",
    "entry": "M3 3h7v10H3zM7 8h6M10 5l3 3-3 3",
    "quality": "M3 12l3-8 3 5 2-3 2 6M5 12h8",
    "anti": "M8 2.5l5 2v3.5c0 3-2 4.5-5 5.5C5 12.5 3 11 3 8V4.5zM5.5 10.5l5-5",
    "injection": "M3 8h7M8 5l3 3-3 3M12 3v10",
    "network": "M3 5h4v3H3zM9 8h4v3H9zM7 6.5h3v3",
    "api": "M3 4h10v8H3zM5 7h2M9 7h2M5 10h6",
    "crypto": "M4 7h8v6H4zM6 7V5a2 2 0 0 1 4 0v2M8 9v2",
    "config": "M3 4h10M3 8h10M3 12h10M6 3v2M10 7v2M7 11v2",
    "key": "M5.5 8a3 3 0 1 0 0-6 3 3 0 0 0 0 6M8 8h5M11 8v2M13 8v2",
    "regex": "M3 5h10M5 3v10M3.5 11l9-6",
    "floss": "M3 4h10M4 7h8M5 10h6M6 13h4",
    "dump": "M3 3h10v8H3zM5 5h6M8 8v6M5.5 11.5L8 14l2.5-2.5",
    "enum": "M3 4h2M7 4h6M3 8h2M7 8h6M3 12h2M7 12h6",
    "history": "M8 3a5 5 0 1 1-4.2 2.3M3 3v3h3M8 5.5V8l2 1.5",
    "yara": "M3 3h10v10H3zM5 5l6 6M11 5l-6 6",
    "python": "M5 3h5v4H4v3h3M11 13H6V9h6V6H9",
    "carray": "M5 3H3v10h2M11 3h2v10h-2M7 5h2M7 8h2M7 11h2",
    "disasm": "M3 3h10v10H3zM5 5h3M5 8h6M5 11h4",
    "virus": "M8 4V2M8 14v-2M4 8H2M14 8h-2M4.5 4.5L3 3M13 13l-1.5-1.5M11.5 4.5L13 3M3 13l1.5-1.5M8 5a3 3 0 1 0 0 6 3 3 0 0 0 0-6",
    "chef": "M4 7h8v6H4zM5 7a3 3 0 0 1 6 0M6 10h4",
    "search": "M6.5 3a3.5 3.5 0 1 0 0 7 3.5 3.5 0 0 0 0-7M9 9l4 4",
    "deep": "M3 4h10M4.5 7h7M6 10h4M8 12.5v-5",
    "xrefs": "M3 4h4v3H3zM9 9h4v3H9zM7 5.5h3v5M10 10.5H9",
    "copytree": "M3 3h6v6H3zM7 11h6M10 8v6M8 13h4",
    "gvarcopy": "M6 3a4 4 0 1 0 0 8M2 7h8M6 3c1.4 1.5 1.4 6.5 0 8M10 9h3v4h-3z",
    "vtable": "M3 3h10v10H3zM3 6h10M7 6v7M5 8h1M9 8h2M9 10h2",
    "classes": "M3 4h6v5H3zM7 11h6M10 8v6M8 13h4",
    "comment_add": "M3 3.5h10v7H7l-3 2v-2H3zM8 5.5v3M6.5 7h3",
    "comment_remove": "M3 3.5h10v7H7l-3 2v-2H3zM6 7h4",
    "comment_list": "M3 3.5h10v8H5l-2 2zM5 6h6M5 8h5M5 10h4",
    "malware": "M8 4V2M5 5L3.5 3.5M11 5l1.5-1.5M4 8H2M14 8h-2M5 11l-1.5 1.5M11 11l1.5 1.5M8 5a3 3 0 1 0 0 6 3 3 0 0 0 0-6",
    "struct_infer": "M3 3h7v10H3zM3 7h7M6 3v10M11 5h2M12 4v2M11 10h2",
    "struct_recover": "M3 3h10v10H3zM3 7h10M7 3v10M10 10h3M11.5 8.5v3",
    "decrypt": "M3 7h8v6H3zM5 7V5a2.5 2.5 0 0 1 4.8-1M11 4l2 2-2 2",
    "hash": "M5 3L3.5 13M10 3L8.5 13M3 6h9M2.5 10h9",
    "bytes": "M3 4h10v8H3zM5 6h2M9 6h2M5 9h2M9 9h2",
    "mask_target": "M3 4h10v8H3zM5 6h2M9 6h2M5 9h6M8 4v8",
    "mask_imm": "M3 4h10v8H3zM5 6h6M5 9h2M9 9h2M4 3l8 10",
    "opcodes": "M3 3h10v10H3zM5 6l2 2-2 2M8.5 10H11M9 5h2",
    "asm_add": "M3 3h10v10H3zM5 6h4M5 9h3M11 7v4M9 9h4",
    "asm_remove": "M3 3h10v10H3zM5 6h6M5 9h3M9.5 10.5l3-3M9.5 7.5l3 3",
    "copy_asm": "M5 5h7v8H5zM3 3h7v2M7 8h3M7 10h3",
    "vt_bytes": "M8 4V2M4 8H2M14 8h-2M8 12v2M8 5a3 3 0 1 0 0 6 3 3 0 0 0 0-6M5 3l1 2M11 3l-1 2",
    "vt_text": "M8 4V2M4 8H2M14 8h-2M8 12v2M8 5a3 3 0 1 0 0 6 3 3 0 0 0 0-6M5.5 8h5",
    "chef_bytes": "M4 7h8v6H4zM5 7a3 3 0 0 1 6 0M6 10h1M9 10h1",
    "chef_text": "M4 7h8v6H4zM5 7a3 3 0 0 1 6 0M6 10h4",
    "web_search": "M7 3a4 4 0 1 0 0 8 4 4 0 0 0 0-8M3 7h8M7 3c1.4 1.5 1.4 6.5 0 8M10 10l3 3",
    "code_search": "M5 4L2 8l3 4M10 4l3 4-3 4M8.5 3L7 13",
    "book": "M3 3.5h4.5a2 2 0 0 1 2 2v7A2 2 0 0 0 7.5 11H3zM13 3.5H9.5M9.5 5.5A2 2 0 0 1 13 3.5v7.5H9.5",
    "migrate": "M3 4h7M8 2l2 2-2 2M13 12H6M8 10l-2 2 2 2",
    "bulk_variable": "M3 3h4v4H3zM9 3h4v4H9zM3 9h4v4H3zM10 9l2 4M12 9l-2 4",
    "bookmark_empty": "M5 3h6v10L8 11l-3 2zM7 6h2M8 5v2",
}

# Every context-menu action gets its own SVG asset. Values select the semantic
# base shape/color; the loader adds a stable per-action detail to keep icons
# visually distinct even within the same family.
ACTION_FAMILIES = {
    "settings": "settings", "bookmarks_empty": "settings", "readable_code": "workspace", "analyst_notes": "workspace",
    "ui_preview": "workspace", "migrate_legacy": "change",
    "list": "workspace", "ask_chat": "analysis", "ask_chat_chain": "analysis",
    "summarizer": "analysis", "agentic_analysis": "analysis",
    "bulk_rename": "bulk", "bulk_var_rename": "bulk", "bulk_analyze": "bulk",
    "deep_analyzer": "bulk", "rename_function": "change",
    "rename_function_malware": "change", "rename_variables": "change",
    "suggest_function_prototype": "change", "analyze_struct": "change",
    "add_comments": "change", "delete_comments": "change",
    "add_asm_comments": "change", "delete_asm_comments": "change",
    "shellcode_analyst": "analysis", "dnspy_xrefs": "inspect",
    "copy_function_tree": "copy", "copy_global_xref_tree": "copy",
    "global_variable_explorer": "inspect",
    "hex_viewer": "inspect", "vftable_list": "inspect",
    "virtual_class_explorer": "analysis",
    "callback_dispatch_resolver": "inspect",
    "thread_sync_explorer": "analysis",
    "exception_unwind_explorer": "inspect",
    "syscall_kernel_mapper": "analysis",
    "entry_point_explorer": "inspect",
    "regex_idb_search": "utility",
    "change_history_explorer": "change",
    "auto_enum_explorer": "inspect",
    "comment_explorer": "change",
    "crypto_encoding_explorer": "analysis",
    "protocol_packet_explorer": "analysis",
    "process_injection_explorer": "analysis",
    "config_ioc_extractor": "analysis",
    "string_decryption_workbench": "analysis",
    "structure_recovery_explorer": "analysis",
    "anti_analysis_explorer": "analysis",
    "dynamic_api_resolution_explorer": "analysis",
    "decompiler_quality_inspector": "inspect",
    "api_hash_explorer": "analysis",
    "toggle_highlight": "inspect", "toggle_disasm_highlight": "inspect",
    "toggle_indent_guides": "inspect", "zoom_all_views": "inspect",
    "floss_strings": "utility", "dump_bytes": "utility",
    "copy_yara_raw": "copy", "copy_yara_mask": "copy", "copy_yara_no_imm": "copy",
    "copy_yara_opcodes": "copy", "copy_yara_rule": "copy", "copy_python": "copy",
    "copy_c_array": "copy", "copy_disasm": "copy",
    "search_bytes_vt": "external", "search_bytes_cyberchef": "external",
    "search_str_vt": "external", "search_str_google": "external",
    "search_str_github": "external", "search_str_msdn": "external",
    "search_str_cyberchef": "external",
}

# Feature-specific primary symbols. ACTION_FAMILIES continues to define the
# coherent color system; this mapping prevents a whole category from appearing
# as one repeated icon in IDA's context menu.
ACTION_GLYPHS = {
    "settings": "settings", "bookmarks_empty": "bookmark_empty", "readable_code": "document", "analyst_notes": "note",
    "ui_preview": "workspace", "migrate_legacy": "migrate", "list": "archive",
    "ask_chat": "chat", "ask_chat_chain": "chain", "summarizer": "summary",
    "agentic_analysis": "agent", "bulk_rename": "bulk", "bulk_var_rename": "bulk_variable",
    "bulk_analyze": "analysis", "deep_analyzer": "deep", "rename_function": "rename",
    "rename_function_malware": "malware", "rename_variables": "variable",
    "suggest_function_prototype": "prototype", "analyze_struct": "struct_infer",
    "add_comments": "comment_add", "delete_comments": "comment_remove", "add_asm_comments": "asm_add",
    "delete_asm_comments": "asm_remove", "shellcode_analyst": "terminal", "dnspy_xrefs": "xrefs",
    "copy_function_tree": "copytree", "copy_global_xref_tree": "gvarcopy",
    "global_variable_explorer": "global", "hex_viewer": "hex",
    "vftable_list": "vtable", "virtual_class_explorer": "classes",
    "callback_dispatch_resolver": "callback", "thread_sync_explorer": "thread",
    "exception_unwind_explorer": "exception", "syscall_kernel_mapper": "kernel",
    "entry_point_explorer": "entry", "regex_idb_search": "regex",
    "change_history_explorer": "history", "auto_enum_explorer": "enum",
    "comment_explorer": "comment_list", "crypto_encoding_explorer": "crypto",
    "protocol_packet_explorer": "network", "process_injection_explorer": "injection",
    "config_ioc_extractor": "config", "string_decryption_workbench": "decrypt",
    "structure_recovery_explorer": "struct_recover", "anti_analysis_explorer": "anti",
    "dynamic_api_resolution_explorer": "api", "decompiler_quality_inspector": "quality",
    "api_hash_explorer": "hash", "toggle_highlight": "highlight",
    "toggle_disasm_highlight": "disasm", "toggle_indent_guides": "indent",
    "zoom_all_views": "zoom", "floss_strings": "floss", "dump_bytes": "dump",
    "copy_yara_raw": "bytes", "copy_yara_mask": "mask_target", "copy_yara_no_imm": "mask_imm",
    "copy_yara_opcodes": "opcodes", "copy_yara_rule": "yara", "copy_python": "python",
    "copy_c_array": "carray", "copy_disasm": "copy_asm", "search_bytes_vt": "vt_bytes",
    "search_bytes_cyberchef": "chef_bytes", "search_str_vt": "vt_text",
    "search_str_google": "web_search", "search_str_github": "code_search",
    "search_str_msdn": "book", "search_str_cyberchef": "chef_text",
}


def load_menu_icons():
    import ida_kernwin
    icons = {}
    for name, color in COLORS.items():
        try:
            icon_id = ida_kernwin.load_custom_icon(data=_svg(color, GLYPHS[name]), format="svg")
            if icon_id and icon_id > 0:
                icons[name] = icon_id
                _LOADED.append(icon_id)
        except Exception:
            pass
    for variant, (action, family) in enumerate(ACTION_FAMILIES.items(), 1):
        try:
            brand_svg = _brand_svg(action)
            icon_id = ida_kernwin.load_custom_icon(
                data=brand_svg or _svg(COLORS[family], GLYPHS[ACTION_GLYPHS[action]], variant), format="svg"
            )
            if icon_id and icon_id > 0:
                icons[action] = icon_id
                _LOADED.append(icon_id)
        except Exception:
            pass
    return icons


def free_menu_icons():
    import ida_kernwin
    while _LOADED:
        icon_id = _LOADED.pop()
        try:
            ida_kernwin.free_custom_icon(icon_id)
        except Exception:
            pass
