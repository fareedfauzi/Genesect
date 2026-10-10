"""Declarative right-click menu organized around reverse-engineering tasks."""

ROOT = "Genesect/"

COMMON_GROUPS = (
    ("", ("genesect:settings",)),
    ("AI Assistant/Analyst Notes", (
        "genesect:readable_code", "genesect:analyst_notes",
        "genesect:list",
    )),
    ("AI Assistant/Chat, Summarizer, && Agentic", (
        "genesect:ask_chat", "genesect:ask_chat_chain", "-",
        "genesect:summarizer", "-", "genesect:agentic_analysis",
    )),
    ("AI Assistant/Bulk Analysis && Workflow", (
        "genesect:bulk_rename", "genesect:bulk_var_rename", "-",
        "genesect:bulk_analyze", "genesect:deep_analyzer",
    )),
    ("Utilities/Navigation && Views", (
        "genesect:hex_viewer", "-",
        "genesect:toggle_highlight", "genesect:toggle_disasm_highlight",
        "genesect:toggle_indent_guides", "genesect:zoom_all_views",
    )),
    ("Utilities/Program Structure", (
        "genesect:global_variable_explorer", "genesect:dnspy_xrefs", "-",
        "genesect:vftable_list", "genesect:virtual_class_explorer",
        "genesect:com_explorer",
        "genesect:callback_dispatch_resolver",
        "genesect:callback_shellcode_explorer", "genesect:call_ranking_explorer", "-",
        "genesect:thread_explorer", "-",
        "genesect:entry_point_explorer", "-",
    )),
    ("Utilities/Malware Analysis", (
        "genesect:findcrypt_explorer", "genesect:anti_analysis_explorer",
        "genesect:process_injection_explorer", "genesect:protocol_packet_explorer",
        "genesect:api_sequence_explorer", "genesect:evidence_graph", "-",
        "genesect:config_ioc_extractor",
    )),
    ("Utilities/Search && Data", (
        "genesect:regex_idb_search", "-",
        "genesect:floss_strings", "genesect:dump_bytes",
    )),
    ("Utilities/Go && Rust", (
        "genesect:go_rust_user_code_map",
        "genesect:go_rust_mark_idb",
    )),
    ("Utilities/GoLang", (
        "genesect:goresym", "-",
        "genesect:go_package_organizer",
    )),
    ("Utilities/Rust", (
        "genesect:rust_triage", "genesect:rust_string_fixups", "-",
        "genesect:rust_demangle", "genesect:rift_library_recognition",
    )),
    ("Utilities/IDB Maintenance", (
        "genesect:comment_explorer", "-",
    )),
)

PSEUDOCODE_GROUPS = (
    ("Utilities/Navigation && Views", (
        "genesect:toggle_pseudocode_block",
        "genesect:argument_name_hints",
    )),
    ("AI Assistant/Rename && Comments (Current Function)", (
        "genesect:rename_function", "genesect:rename_function_malware",
        "genesect:rename_variables", "-",
        "genesect:suggest_function_prototype", "genesect:analyze_struct", "-",
        "genesect:add_comments", "genesect:delete_comments",
    )),
)

DISASSEMBLY_GROUPS = (
    ("AI Assistant/Rename && Comments (Current Function)", (
        "genesect:rename_function", "genesect:rename_function_malware",
        "genesect:rename_variables", "-",
        "genesect:add_asm_comments", "genesect:delete_asm_comments",
        "-", "genesect:shellcode_analyst",
    )),
)

EXTERNAL_TEXT_SEARCH = (
    "genesect:search_str_vt", "genesect:search_str_google",
    "genesect:search_str_github", "genesect:search_str_msdn",
    "genesect:search_str_cyberchef",
)


def menu_groups(pseudocode=False, bookmarks=None):
    additions = PSEUDOCODE_GROUPS if pseudocode else DISASSEMBLY_GROUPS
    groups = [(name, list(actions)) for name, actions in COMMON_GROUPS]
    for name, actions in additions:
        existing = next((items for group, items in groups if group == name), None)
        if existing is None:
            if name.startswith("AI Assistant/"):
                insert_at = next(
                    (i for i, (group, _) in enumerate(groups) if group.startswith("Utilities/")),
                    len(groups),
                )
                groups.insert(insert_at, (name, list(actions)))
            else:
                groups.append((name, list(actions)))
        else:
            existing.extend(actions)
    groups.append(("Utilities/Copy && Export", [
        "genesect:export_ai_workspace", "-",
        "genesect:copy_function_tree", "genesect:copy_global_xref_tree", "-",
        "genesect:copy_yara_raw", "genesect:copy_yara_mask",
        "genesect:copy_yara_no_imm", "genesect:copy_yara_opcodes",
        "genesect:copy_yara_rule", "-", "genesect:copy_python",
        "genesect:copy_c_array", "genesect:copy_disasm",
    ]))
    pivots = list(EXTERNAL_TEXT_SEARCH)
    if not pseudocode:
        pivots = [
            "genesect:search_bytes_vt",
            "genesect:search_bytes_cyberchef", "-",
        ] + pivots
    groups.append(("Utilities/External Pivot Search", pivots))

    if bookmarks is None:
        bookmarks = []
    available = {
        action_id for _group, actions in groups for action_id in actions
        if action_id not in ("-", "genesect:settings")
    }
    bookmarked = [action_id for action_id in bookmarks if action_id in available]
    groups.append(("Bookmarks", bookmarked or ["genesect:bookmarks_empty"]))
    return groups


def bookmark_candidates():
    """Return every bookmarkable feature once, across both IDA view types."""
    candidates = []
    seen = set()
    for pseudocode in (True, False):
        for group, actions in menu_groups(pseudocode, bookmarks=[]):
            if group in ("", "Bookmarks"):
                continue
            category = group.split("/", 1)[0]
            for action_id in actions:
                if action_id in ("-", "genesect:bookmarks_empty") or action_id in seen:
                    continue
                seen.add(action_id)
                candidates.append((category, action_id))
    return candidates
