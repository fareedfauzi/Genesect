"""Declarative right-click menu organized around reverse-engineering tasks."""

ROOT = "PseudoNote/"

COMMON_GROUPS = (
    ("", ("pseudonote_extended:settings",)),
    ("AI Assistant/Analyst Notes", (
        "pseudonote_extended:readable_code", "pseudonote_extended:analyst_notes",
        "pseudonote_extended:list",
    )),
    ("AI Assistant/Chat, Summarizer, && Agentic", (
        "pseudonote_extended:ask_chat", "pseudonote_extended:ask_chat_chain", "-",
        "pseudonote_extended:summarizer", "-", "pseudonote_extended:agentic_analysis",
    )),
    ("AI Assistant/Bulk Analysis && Workflow", (
        "pseudonote_extended:bulk_rename", "pseudonote_extended:bulk_var_rename", "-",
        "pseudonote_extended:bulk_analyze", "pseudonote_extended:deep_analyzer",
    )),
    ("Utilities/Navigation && Views", (
        "pseudonote_extended:hex_viewer", "-",
        "pseudonote_extended:toggle_highlight", "pseudonote_extended:toggle_disasm_highlight",
        "pseudonote_extended:toggle_indent_guides", "pseudonote_extended:zoom_all_views",
    )),
    ("Utilities/Program Structure", (
        "pseudonote_extended:global_variable_explorer", "pseudonote_extended:dnspy_xrefs", "-",
        "pseudonote_extended:vftable_list", "pseudonote_extended:virtual_class_explorer",
        "pseudonote_extended:com_explorer",
        "pseudonote_extended:callback_dispatch_resolver",
        "pseudonote_extended:callback_shellcode_explorer", "pseudonote_extended:call_ranking_explorer", "-",
        "pseudonote_extended:thread_explorer", "-",
        "pseudonote_extended:entry_point_explorer", "-",
    )),
    ("Utilities/Malware Analysis", (
        "pseudonote_extended:findcrypt_explorer", "pseudonote_extended:anti_analysis_explorer",
        "pseudonote_extended:process_injection_explorer", "pseudonote_extended:protocol_packet_explorer",
        "pseudonote_extended:api_sequence_explorer", "pseudonote_extended:evidence_graph", "-",
        "pseudonote_extended:config_ioc_extractor",
    )),
    ("Utilities/Search && Data", (
        "pseudonote_extended:regex_idb_search", "-",
        "pseudonote_extended:floss_strings", "pseudonote_extended:dump_bytes",
    )),
    ("Utilities/GoLang", (
        "pseudonote_extended:goresym", "-",
        "pseudonote_extended:go_package_organizer",
    )),
    ("Utilities/Rust", (
        "pseudonote_extended:rust_triage", "pseudonote_extended:rust_string_fixups", "-",
        "pseudonote_extended:rust_demangle", "pseudonote_extended:rift_library_recognition",
    )),
    ("Utilities/IDB Maintenance", (
        "pseudonote_extended:comment_explorer", "-",
    )),
)

PSEUDOCODE_GROUPS = (
    ("Utilities/Navigation && Views", (
        "pseudonote_extended:toggle_pseudocode_block",
        "pseudonote_extended:argument_name_hints",
    )),
    ("AI Assistant/Rename && Comments (Current Function)", (
        "pseudonote_extended:rename_function", "pseudonote_extended:rename_function_malware",
        "pseudonote_extended:rename_variables", "-",
        "pseudonote_extended:suggest_function_prototype", "pseudonote_extended:analyze_struct", "-",
        "pseudonote_extended:add_comments", "pseudonote_extended:delete_comments",
    )),
)

DISASSEMBLY_GROUPS = (
    ("AI Assistant/Rename && Comments (Current Function)", (
        "pseudonote_extended:rename_function", "pseudonote_extended:rename_function_malware",
        "pseudonote_extended:rename_variables", "-",
        "pseudonote_extended:add_asm_comments", "pseudonote_extended:delete_asm_comments",
        "-", "pseudonote_extended:shellcode_analyst",
    )),
)

EXTERNAL_TEXT_SEARCH = (
    "pseudonote_extended:search_str_vt", "pseudonote_extended:search_str_google",
    "pseudonote_extended:search_str_github", "pseudonote_extended:search_str_msdn",
    "pseudonote_extended:search_str_cyberchef",
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
        "pseudonote_extended:copy_function_tree", "pseudonote_extended:copy_global_xref_tree", "-",
        "pseudonote_extended:copy_yara_raw", "pseudonote_extended:copy_yara_mask",
        "pseudonote_extended:copy_yara_no_imm", "pseudonote_extended:copy_yara_opcodes",
        "pseudonote_extended:copy_yara_rule", "-", "pseudonote_extended:copy_python",
        "pseudonote_extended:copy_c_array", "pseudonote_extended:copy_disasm",
    ]))
    pivots = list(EXTERNAL_TEXT_SEARCH)
    if not pseudocode:
        pivots = [
            "pseudonote_extended:search_bytes_vt",
            "pseudonote_extended:search_bytes_cyberchef", "-",
        ] + pivots
    groups.append(("Utilities/External Pivot Search", pivots))

    if bookmarks is None:
        bookmarks = []
    available = {
        action_id for _group, actions in groups for action_id in actions
        if action_id not in ("-", "pseudonote_extended:settings")
    }
    bookmarked = [action_id for action_id in bookmarks if action_id in available]
    groups.append(("Bookmarks", bookmarked or ["pseudonote_extended:bookmarks_empty"]))
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
                if action_id in ("-", "pseudonote_extended:bookmarks_empty") or action_id in seen:
                    continue
                seen.add(action_id)
                candidates.append((category, action_id))
    return candidates
