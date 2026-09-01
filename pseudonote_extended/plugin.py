# -*- coding: utf-8 -*-
"""
PseudoNotePlugin — the main IDA plugin_t subclass.
"""
import idaapi
import ida_hexrays

from pseudonote_extended.qt_compat import QT_BINDING, QT_MAJOR, QtCore, QtWidgets
from pseudonote_extended.config import CONFIG
from pseudonote_extended.ai_client import SimpleAI
import pseudonote_extended.ai_client as _ai_mod
from pseudonote_extended.highlight import (
    _create_highlight_hooks,
    destroy_highlight_hooks,
    toggle_highlight_handler,
    toggle_disasm_highlight_handler,
)
from pseudonote_extended.indent import create_indent_guide_hooks, destroy_indent_guide_hooks, ToggleIndentGuidesHandler
from pseudonote_extended.default_visuals import create_default_visual_hooks, destroy_default_visual_hooks
from pseudonote_extended.zoom import (
    ToggleZoomAllViewsHandler, initialize_zoom_all_views, shutdown_zoom_all_views,
)
from pseudonote_extended.xrefs import DnspyXrefsHandler
from pseudonote_extended.handlers import (
    RenameVariablesHandler,
    RenameFunctionHandler,
    RenameMalwareFunctionHandler,
    SuggestFunctionPrototypeHandler,
    CommentHandler,
    DeleteCommentsHandler,
    AsmCommentHandler,
    DeleteAsmCommentsHandler,
    StructAnalysisHandler,
    BulkRenameHandler,
    SettingsHandler,
    AskAIHandler,
    ShellcodeAnalystHandler,
    BulkVarRenameHandler,
    BulkAnalyzeHandler,
    SearchBytesVTHandler,
    SearchStringHandler,
    SearchBytesCyberChefHandler,
    FlossStringsHandler,
    AdvancedCopyHandler,
    DumpBytesHandler,
    CopyFunctionTreeHandler,
    CopyGlobalXrefTreeHandler,
)
from pseudonote_extended.deep_analyzer import DeepAnalyzerHandler
from pseudonote_extended.summarizer import SummarizerHandler
from pseudonote_extended.chat_chain import ChatChainHandler
from pseudonote_extended.hexview import OpenHexViewHandler
from pseudonote_extended.vftable import VftableListHandler
from pseudonote_extended.global_explorer import GlobalVariableExplorerHandler
from pseudonote_extended.virtual_class_explorer import VirtualClassExplorerHandler
from pseudonote_extended.callback_resolver import CallbackDispatchResolverHandler
from pseudonote_extended.thread_sync_explorer import ThreadSynchronizationExplorerHandler
from pseudonote_extended.exception_unwind_explorer import ExceptionUnwindExplorerHandler
from pseudonote_extended.syscall_kernel_mapper import SyscallKernelInterfaceMapperHandler
from pseudonote_extended.entry_point_explorer import EntryPointExplorerHandler
from pseudonote_extended.regex_idb_search import RegexIDBSearchHandler
from pseudonote_extended.change_history import ChangeHistoryExplorerHandler, start_change_history_hooks, stop_change_history_hooks
from pseudonote_extended.crypto_encoding_explorer import CryptoEncodingExplorerHandler
from pseudonote_extended.protocol_packet_explorer import ProtocolPacketExplorerHandler
from pseudonote_extended.process_injection_explorer import ProcessInjectionExplorerHandler
from pseudonote_extended.config_ioc_extractor import ConfigurationIOCExtractorHandler
from pseudonote_extended.string_decryption_workbench import StringDecryptionWorkbenchHandler
from pseudonote_extended.structure_recovery_explorer import StructureRecoveryExplorerHandler
from pseudonote_extended.anti_analysis_explorer import AntiAnalysisExplorerHandler
from pseudonote_extended.dynamic_api_resolution_explorer import DynamicAPIResolutionExplorerHandler
from pseudonote_extended.decompiler_quality_inspector import DecompilerQualityInspectorHandler
from pseudonote_extended.api_hash_explorer import APIHashExplorerHandler
from pseudonote_extended.auto_enum_explorer import AutoEnumExplorerHandler
from pseudonote_extended.comment_explorer import CommentExplorerHandler
from pseudonote_extended.agentic_analyzer import AgenticAnalysisHandler
from pseudonote_extended.metadata import PLUGIN_DISPLAY_NAME, __version__
from pseudonote_extended.ui.preview import UIPreviewHandler
from pseudonote_extended.migration import LegacyMigrationHandler
from pseudonote_extended.idb_storage import ensure_storage_schema
from pseudonote_extended.ui.icons import free_menu_icons, load_menu_icons

# These will be imported lazily to avoid circular imports
_view_module = None


class EmptyBookmarksHandler(idaapi.action_handler_t):
    def activate(self, ctx):
        return 0

    def update(self, ctx):
        return getattr(idaapi, "AST_DISABLE_ALWAYS", getattr(idaapi, "AST_DISABLE", 0))

def _get_view_module():
    global _view_module
    if _view_module is None:
        import pseudonote_extended.view as _vm
        _view_module = _vm
    return _view_module


class PseudoNotePlugin(idaapi.plugin_t):
    # PLUGIN_HIDE suppresses IDA's automatic Edit > Plugins entry. PseudoNote
    # remains resident (PLUGIN_FIX), keeps its hotkey, and exposes its complete
    # command tree exclusively through the Disassembly/Pseudocode context menu.
    flags = idaapi.PLUGIN_FIX | idaapi.PLUGIN_HIDE
    comment = "PseudoNote Extended: AI-assisted reverse engineering for IDA Pro"
    help = "AI-assisted analysis, annotation, renaming, and malware research utilities"
    wanted_name = PLUGIN_DISPLAY_NAME
    wanted_hotkey = "Ctrl-Shift-G"

    def __init__(self):
        super(PseudoNotePlugin, self).__init__()
        self.view = None
        self.code_view = None
        self.notes_view = None
        self.hooks = None
        self.config = CONFIG
        self.ctx_hooks = None
        self.highlight_hooks = None
        self.indent_guide_hooks = None
        self.default_visual_hooks = None

    def init(self):
        if not QtWidgets:
            return idaapi.PLUGIN_SKIP

        vm = _get_view_module()
        vm.plugin_instance = self
        ensure_storage_schema()
        self.change_history_hooks = start_change_history_hooks()
        self.menu_icons = load_menu_icons()
        icon = lambda name, fallback: self.menu_icons.get(name, fallback)

        _ai_mod.AI_CLIENT = SimpleAI(self.config)

        # Register Highlighter Actions (Pseudocode)
        # Register Highlighter Actions (Pseudocode)
        idaapi.register_action(idaapi.action_desc_t(
            "pseudonote_extended:toggle_highlight", "Toggle Call Highlight (Pseudocode)",
            toggle_highlight_handler(), "Ctrl+Alt+H",
            "Toggle function call highlighting in pseudocode", icon("toggle_highlight", 48)
        ))
        # Register Highlighter Actions (Disasm)
        idaapi.register_action(idaapi.action_desc_t(
            "pseudonote_extended:toggle_disasm_highlight", "Toggle Call Highlight (Assembly)",
            toggle_disasm_highlight_handler(), "Ctrl+Shift+H",
            "Toggle function call highlighting in Graph/Linear view", icon("toggle_disasm_highlight", 48)
        ))

        idaapi.register_action(idaapi.action_desc_t(
            "pseudonote_extended:toggle_indent_guides", "Toggle Indent Marks",
            ToggleIndentGuidesHandler(), "Ctrl+Alt+I",
            "Toggle colorful nesting-level indent marks in Hex-Rays pseudocode", icon("toggle_indent_guides", 48)
        ))

        idaapi.register_action(idaapi.action_desc_t(
            "pseudonote_extended:bookmarks_empty", "No bookmarks configured",
            EmptyBookmarksHandler(), "",
            "Choose bookmarked features in PseudoNote Settings", icon("bookmarks_empty", 48)
        ))

        idaapi.register_action(idaapi.action_desc_t(
            "pseudonote_extended:zoom_all_views", "Zoom Views (Ctrl+Wheel)",
            ToggleZoomAllViewsHandler(), "",
            "Toggle Ctrl+wheel font zoom for scrollable IDA and PseudoNote views",
            icon("zoom_all_views", 48), getattr(idaapi, "ADF_CHECKABLE", 0)
        ))
        initialize_zoom_all_views()

        if ida_hexrays.init_hexrays_plugin():
            self.highlight_hooks = _create_highlight_hooks()
            self.indent_guide_hooks = create_indent_guide_hooks()
        else:
            print("[PseudoNote] Hex-Rays not available at init time, hooks will be installed on first enable")
            self.highlight_hooks = None

        self.default_visual_hooks = create_default_visual_hooks()

        print("-" * 60)
        print(f"{PLUGIN_DISPLAY_NAME} {__version__} initialized.")
        print(f"Qt backend: {QT_BINDING or 'unknown'} (Qt {QT_MAJOR or 'unknown'}).")
        print("Use Ctrl+Shift+G, or right-click in Disassembly/Pseudocode and open PseudoNote.")
        print("-" * 60)

        # Register Readable Code Action
        readable_code_desc = idaapi.action_desc_t(
            "pseudonote_extended:readable_code",
            "Open Readable Code",
            vm.PseudoNoteHandler("code"),
            "Ctrl+Alt+G",
            "Open Readable Code View",
            icon("readable_code", 109)
        )
        idaapi.register_action(readable_code_desc)

        # Register Analyst Notes Action
        analyst_notes_desc = idaapi.action_desc_t(
            "pseudonote_extended:analyst_notes",
            "Open Analyst Notes",
            vm.PseudoNoteHandler("notes"),
            "Ctrl+Alt+Shift+G",
            "Open Analyst Notes View",
            icon("analyst_notes", 109)
        )
        idaapi.register_action(analyst_notes_desc)
        # Main menu entry removed - focusing on right-click menu

        list_action_desc = idaapi.action_desc_t(
            "pseudonote_extended:list",
            "Browse Saved Artifacts",
            vm.SavedNotesHandler(),
            "Ctrl+Alt+L",
            "List all functions with saved PseudoNotes",
            icon("list", 58)
        )
        idaapi.register_action(list_action_desc)

        # Register Settings Action
        idaapi.register_action(idaapi.action_desc_t(
            "pseudonote_extended:settings",
            "Settings...",
            SettingsHandler(),
            "Ctrl+Alt+P",
            "Configure AI Provider and Performance settings",
            icon("settings", 147)
        ))

        idaapi.register_action(idaapi.action_desc_t(
            "pseudonote_extended:ui_preview",
            "UI Component Preview...",
            UIPreviewHandler(),
            "",
            "Review the PseudoNote Extended interface foundation",
            icon("ui_preview", 147)
        ))

        idaapi.register_action(idaapi.action_desc_t(
            "pseudonote_extended:migrate_legacy",
            "Migrate Classic PseudoNote Data...",
            LegacyMigrationHandler.create(),
            "",
            "Non-destructively copy missing classic PseudoNote IDB and configuration data",
            icon("migrate_legacy", 147),
        ))

        rename_func_desc = idaapi.action_desc_t(
            "pseudonote_extended:rename_function",
            "Suggest Function Name (Code Context)",
            RenameFunctionHandler(),
            "Ctrl+Alt+N",
            "Use AI to rename the current function based on its code logic",
            icon("rename_function", 204)
        )
        idaapi.register_action(rename_func_desc)

        rename_malware_desc = idaapi.action_desc_t(
            "pseudonote_extended:rename_function_malware",
            "Suggest Function Name (Malware Context)",
            RenameMalwareFunctionHandler(),
            "Ctrl+Alt+M",
            "Use AI to rename the current function in a malware analysis context",
            icon("rename_function_malware", 204)
        )
        idaapi.register_action(rename_malware_desc)

        rename_vars_desc = idaapi.action_desc_t(
            "pseudonote_extended:rename_variables",
            "Suggest Variable Name",
            RenameVariablesHandler(),
            "Ctrl+Alt+R",
            "Use AI to rename variables in the current function",
            icon("rename_variables", 203)
        )
        idaapi.register_action(rename_vars_desc)

        # Suggest Function Prototype Action
        sugg_sig_desc = idaapi.action_desc_t(
            "pseudonote_extended:suggest_function_prototype",
            "Suggest Function Prototype",
            SuggestFunctionPrototypeHandler(),
            "Ctrl+Alt+S",
            "Ask AI to infer and apply a function prototype",
            icon("suggest_function_prototype", 138)
        )
        idaapi.register_action(sugg_sig_desc)

        comment_handler_desc = idaapi.action_desc_t(
            "pseudonote_extended:add_comments",
            "Generate Pseudocode Comments",
            CommentHandler(),
            "Ctrl+Alt+C",
            "Ask AI to add helpful comments to the current function",
            icon("add_comments", 109)
        )
        idaapi.register_action(comment_handler_desc)

        asm_comment_handler_desc = idaapi.action_desc_t(
            "pseudonote_extended:add_asm_comments",
            "Generate Disassembly Comments",
            AsmCommentHandler(),
            "Ctrl+Shift+C",
            "Ask AI to add concise section comments to the disassembly",
            icon("add_asm_comments", 109)
        )
        idaapi.register_action(asm_comment_handler_desc)

        del_asm_comments_desc = idaapi.action_desc_t(
            "pseudonote_extended:delete_asm_comments",
            "Remove Disassembly Comments...",
            DeleteAsmCommentsHandler(),
            "Ctrl+Shift+D",
            "Remove PseudoNote-generated comments while preserving analyst notes",
            icon("delete_asm_comments", 109)
        )
        idaapi.register_action(del_asm_comments_desc)

        # Bytes/Instructions/Shellcode Analysis
        shell_analyst_desc = idaapi.action_desc_t(
            "pseudonote_extended:shellcode_analyst",
            "Analyze Selected Bytes / Shellcode",
            ShellcodeAnalystHandler(),
            "Ctrl+Shift+E",
            "Open the static shellcode analysis window",
            icon("shellcode_analyst", 124)
        )
        idaapi.register_action(shell_analyst_desc)

        delete_comments_desc = idaapi.action_desc_t(
            "pseudonote_extended:delete_comments",
            "Remove Pseudocode Comments...",
            DeleteCommentsHandler(),
            "Ctrl+Alt+D",
            "Remove PseudoNote-generated comments while preserving analyst notes",
            icon("delete_comments", 109)
        )
        idaapi.register_action(delete_comments_desc)

        xrefs_desc = idaapi.action_desc_t(
            "pseudonote_extended:dnspy_xrefs",
            "Call Tree",
            DnspyXrefsHandler(),
            "Ctrl+Alt+X",
            "View interactive dnSpy style call hierarchy",
            icon("dnspy_xrefs", 73)
        )
        idaapi.register_action(xrefs_desc)
        # (Call Tree attached in the tools separator group above)

        # Structure Analysis Action
        struct_action_desc = idaapi.action_desc_t(
            "pseudonote_extended:analyze_struct", "Infer / Edit Structure",
            StructAnalysisHandler(), "Ctrl+Alt+E",
            "Analyze variable usage to infer structure", icon("analyze_struct", 101)
        )
        idaapi.register_action(struct_action_desc)

        # Bulk Rename Functions Action
        bulk_rename_desc = idaapi.action_desc_t(
            "pseudonote_extended:bulk_rename",
            "Bulk Function Renamer",
            BulkRenameHandler(),
            "Ctrl+Shift+R",
            "Rename multiple functions using AI strategies",
            icon("bulk_rename", 205)
        )
        idaapi.register_action(bulk_rename_desc)
        
        # Bulk Function Analyzer Action
        bulk_analyze_desc = idaapi.action_desc_t(
            "pseudonote_extended:bulk_analyze",
            "Bulk Function Analysis",
            BulkAnalyzeHandler(),
            "Ctrl+Shift+A",
            "Open the AI bulk function analysis and tagging window",
            icon("bulk_analyze", 110)
        )
        idaapi.register_action(bulk_analyze_desc)

        # Deep Analyzer Action
        deep_analyzer_desc = idaapi.action_desc_t(
            "pseudonote_extended:deep_analyzer",
            "Deep Analyzer with Report",
            DeepAnalyzerHandler(),
            "Ctrl+Shift+S",
            "Automated bottom-up recursive function analysis and summarization",
            icon("deep_analyzer", 122)
        )
        idaapi.register_action(deep_analyzer_desc)

        # Summarizer Action
        summarizer_desc = idaapi.action_desc_t(
            "pseudonote_extended:summarizer",
            "Function Chain Summarizer",
            SummarizerHandler(),
            "Ctrl+Alt+Z",
            "A light version of Deep Analyzer to summarize the entire function chain",
            icon("summarizer", 122)
        )
        idaapi.register_action(summarizer_desc)

        # Bulk Variable Renamer Action
        bulk_var_rename_desc = idaapi.action_desc_t(
            "pseudonote_extended:bulk_var_rename",
            "Bulk Variable Renamer",
            BulkVarRenameHandler(),
            "Ctrl+Shift+V",
            "Rename local variables in bulk using AI",
            icon("bulk_var_rename", 206)
        )
        idaapi.register_action(bulk_var_rename_desc)
        
        # FLOSS Strings Discovery Action
        floss_strings_desc = idaapi.action_desc_t(
            "pseudonote_extended:floss_strings",
            "Discover Strings with FLOSS",
            FlossStringsHandler(),
            "Ctrl+Shift+F",
            "Discover strings built dynamically (Stack, Tight, Decoded) using FLOSS",
            icon("floss_strings", 183)
        )
        idaapi.register_action(floss_strings_desc)
        

        ask_chat_desc = idaapi.action_desc_t(
            "pseudonote_extended:ask_chat",
            "Chat About This Function",
            AskAIHandler(),
            "Ctrl+Alt+A",
            "Open a chat to ask AI about the current function",
            icon("ask_chat", 124)
        )
        idaapi.register_action(ask_chat_desc)

        ask_chat_chain_desc = idaapi.action_desc_t(
            "pseudonote_extended:ask_chat_chain",
            "Chat About a Function Chain",
            ChatChainHandler(),
            "Ctrl+Alt+Shift+A",
            "Open a chat to ask AI about multiple functions in a chain",
            icon("ask_chat_chain", 124)
        )
        idaapi.register_action(ask_chat_chain_desc)

        agentic_desc = idaapi.action_desc_t(
            "pseudonote_extended:agentic_analysis",
            "Autonomous Investigation",
            AgenticAnalysisHandler(),
            "Ctrl+Alt+Shift+M",
            "Run autonomous agentic loop to reverse engineer the current function",
            icon("agentic_analysis", 204)
        )
        idaapi.register_action(agentic_desc)

        # Register Search Utils Actions
        idaapi.register_action(idaapi.action_desc_t(
            "pseudonote_extended:search_bytes_vt", "Search Selected Bytes on VirusTotal...",
            SearchBytesVTHandler(), "",
            "Search highlighted bytes in VirusTotal", icon("search_bytes_vt", 128)
        ))
        idaapi.register_action(idaapi.action_desc_t(
            "pseudonote_extended:search_bytes_cyberchef", "Open Selected Bytes in CyberChef...",
            SearchBytesCyberChefHandler(), "",
            "Add highlighted bytes to CyberChef input", icon("search_bytes_cyberchef", 128)
        ))
        idaapi.register_action(idaapi.action_desc_t(
            "pseudonote_extended:search_str_vt", "Search Text on VirusTotal...",
            SearchStringHandler("vt"), "",
            "Search string in VirusTotal", icon("search_str_vt", 128)
        ))
        idaapi.register_action(idaapi.action_desc_t(
            "pseudonote_extended:search_str_google", "Search Text on Google...",
            SearchStringHandler("google"), "",
            "Search string in Google", icon("search_str_google", 128)
        ))
        idaapi.register_action(idaapi.action_desc_t(
            "pseudonote_extended:search_str_github", "Search Text on GitHub...",
            SearchStringHandler("github"), "",
            "Search string in GitHub", icon("search_str_github", 128)
        ))
        idaapi.register_action(idaapi.action_desc_t(
            "pseudonote_extended:search_str_msdn", "Search WinAPI Documentation...",
            SearchStringHandler("msdn"), "",
            "Search string (WinAPI) in MSDN Documentation", icon("search_str_msdn", 128)
        ))
        idaapi.register_action(idaapi.action_desc_t(
            "pseudonote_extended:search_str_cyberchef", "Open Text in CyberChef...",
            SearchStringHandler("cyberchef"), "",
            "Add string to CyberChef input", icon("search_str_cyberchef", 128)
        ))
        
        # Advanced Copy Actions
        idaapi.register_action(idaapi.action_desc_t("pseudonote_extended:copy_yara_raw", "Copy Hex Bytes", AdvancedCopyHandler("yara_raw"), "", "Copy selected bytes as hex string", icon("copy_yara_raw", 31)))
        idaapi.register_action(idaapi.action_desc_t("pseudonote_extended:copy_yara_rule", "Generate YARA Rule...", AdvancedCopyHandler("yara_rule"), "", "Generate a simple YARA rule from selected bytes", icon("copy_yara_rule", 31)))
        idaapi.register_action(idaapi.action_desc_t("pseudonote_extended:copy_yara_mask", "Copy Hex (Mask Targets/Relocs)", AdvancedCopyHandler("yara_mask"), "", "Copy selected bytes masking jumps and memory references", icon("copy_yara_mask", 31)))
        idaapi.register_action(idaapi.action_desc_t("pseudonote_extended:copy_yara_no_imm", "Copy Hex (Mask Immediates)", AdvancedCopyHandler("yara_no_imm"), "", "Copy selected bytes masking immediates and addresses", icon("copy_yara_no_imm", 31)))
        idaapi.register_action(idaapi.action_desc_t("pseudonote_extended:copy_yara_opcodes", "Copy Hex (Opcodes Only)", AdvancedCopyHandler("yara_opcodes"), "", "Copy selected bytes masking everything but opcodes", icon("copy_yara_opcodes", 31)))
        idaapi.register_action(idaapi.action_desc_t("pseudonote_extended:copy_python", "Copy Python Byte Literal", AdvancedCopyHandler("python"), "", 'Copy selected bytes as python string', icon("copy_python", 31)))
        idaapi.register_action(idaapi.action_desc_t("pseudonote_extended:copy_c_array", "Copy C/C++ Byte Array", AdvancedCopyHandler("c_array"), "", "Copy selected bytes as a C array", icon("copy_c_array", 31)))
        idaapi.register_action(idaapi.action_desc_t("pseudonote_extended:copy_disasm", "Copy Disassembly Text", AdvancedCopyHandler("disasm"), "", "Copy selected disassembly lines", icon("copy_disasm", 31)))

        # Dump Bytes Action
        idaapi.register_action(idaapi.action_desc_t(
            "pseudonote_extended:dump_bytes",
            "Dump Selected Bytes...",
            DumpBytesHandler(),
            "",
            "Dump a range of bytes or a global variable to a file",
            icon("dump_bytes", 31)
        ))

        # Hex Viewer Action (attached in the tools separator group above)
        idaapi.register_action(idaapi.action_desc_t(
            "pseudonote_extended:hex_viewer",
            "Hex Viewer",
            OpenHexViewHandler(),
            "Ctrl+Alt+B",
            "Open the PseudoNote Hex Viewer (synced with current function)",
            icon("hex_viewer", 80)
        ))

        # Vftable method browser
        idaapi.register_action(idaapi.action_desc_t(
            "pseudonote_extended:vftable_list",
            "Browse Virtual Tables",
            VftableListHandler(),
            "",
            "Scan vftables and browse their functions, callers, and users",
            icon("vftable_list", 73)
        ))

        # Copy Function Tree Action
        idaapi.register_action(idaapi.action_desc_t(
            "pseudonote_extended:copy_function_tree",
            "Copy Function Tree",
            CopyFunctionTreeHandler(),
            "Ctrl+Alt+T",
            "Recursively copy decompiled sub-functions called by the current function",
            icon("copy_function_tree", 31)
        ))

        # Copy Global Variable Xref Tree Action
        idaapi.register_action(idaapi.action_desc_t(
            "pseudonote_extended:copy_global_xref_tree",
            "Copy Global Xref Tree",
            CopyGlobalXrefTreeHandler(),
            "",
            "Recursively copy functions and their callers that use the selected global variable",
            icon("copy_global_xref_tree", 31)
        ))

        idaapi.register_action(idaapi.action_desc_t(
            "pseudonote_extended:global_variable_explorer",
            "Global Variable Explorer",
            GlobalVariableExplorerHandler(),
            "",
            "Explore global reads, writes, initialization, inferred types, aliases, and affected functions",
            icon("global_variable_explorer", 73)
        ))

        idaapi.register_action(idaapi.action_desc_t(
            "pseudonote_extended:virtual_class_explorer",
            "Virtual-Class Explorer",
            VirtualClassExplorerHandler(),
            "",
            "Recover virtual tables, class hierarchies, constructors, destructors, methods, RTTI, and inheritance",
            icon("virtual_class_explorer", 73)
        ))

        idaapi.register_action(idaapi.action_desc_t(
            "pseudonote_extended:callback_dispatch_resolver",
            "Callback and Dispatch Resolver",
            CallbackDispatchResolverHandler(),
            "",
            "Identify function pointers, callback registrations, handlers, jump tables, and indirect-call targets",
            icon("callback_dispatch_resolver", 73)
        ))

        idaapi.register_action(idaapi.action_desc_t(
            "pseudonote_extended:thread_sync_explorer",
            "Thread and Synchronization Explorer",
            ThreadSynchronizationExplorerHandler(),
            "",
            "Map thread entries, locks, events, queues, shared state, and possible races or deadlocks",
            icon("thread_sync_explorer", 73)
        ))

        idaapi.register_action(idaapi.action_desc_t(
            "pseudonote_extended:exception_unwind_explorer",
            "Exception and Unwind Explorer",
            ExceptionUnwindExplorerHandler(),
            "",
            "Visualize exception handlers, SEH chains, cleanup paths, landing pads, and compiler unwind behavior",
            icon("exception_unwind_explorer", 73)
        ))

        idaapi.register_action(idaapi.action_desc_t(
            "pseudonote_extended:syscall_kernel_mapper",
            "Syscall and Kernel Interface Mapper",
            SyscallKernelInterfaceMapperHandler(),
            "",
            "Identify direct syscalls, IOCTLs, devices, kernel callbacks, and user/kernel trust boundaries",
            icon("syscall_kernel_mapper", 73)
        ))

        idaapi.register_action(idaapi.action_desc_t(
            "pseudonote_extended:entry_point_explorer",
            "Entry-Point Explorer",
            EntryPointExplorerHandler(),
            "",
            "Show executable entry points, exports, TLS callbacks, constructors, initialization arrays, and thread entries",
            icon("entry_point_explorer", 73)
        ))

        idaapi.register_action(idaapi.action_desc_t(
            "pseudonote_extended:regex_idb_search",
            "Regex Search Across IDB",
            RegexIDBSearchHandler(),
            "",
            "Search decompilation, disassembly, strings, names, and comments using regular expressions",
            icon("regex_idb_search", 73)
        ))

        idaapi.register_action(idaapi.action_desc_t(
            "pseudonote_extended:change_history_explorer",
            "Change History and Undo Explorer",
            ChangeHistoryExplorerHandler(),
            "",
            "Display journaled IDB modifications with before/after values and verified selective rollback",
            icon("change_history_explorer", 73)
        ))

        idaapi.register_action(idaapi.action_desc_t(
            "pseudonote_extended:auto_enum_explorer",
            "Automatic Enum Recovery",
            AutoEnumExplorerHandler(),
            "",
            "Detect standard API enum arguments and selectively apply reviewed enum types",
            icon("auto_enum_explorer", 73)
        ))

        idaapi.register_action(idaapi.action_desc_t(
            "pseudonote_extended:comment_explorer",
            "Comment Explorer",
            CommentExplorerHandler(),
            "",
            "Search, navigate, edit, delete, and export disassembly and Hex-Rays comments",
            icon("comment_explorer", 73)
        ))

        idaapi.register_action(idaapi.action_desc_t(
            "pseudonote_extended:crypto_encoding_explorer",
            "Crypto and Encoding Explorer",
            CryptoEncodingExplorerHandler(),
            "",
            "Detect cryptographic constants, algorithms, XOR loops, hashing, Base64, compression, and custom decoders",
            icon("crypto_encoding_explorer", 73)
        ))

        idaapi.register_action(idaapi.action_desc_t(
            "pseudonote_extended:protocol_packet_explorer",
            "C2, Protocol and Packet Explorer",
            ProtocolPacketExplorerHandler(),
            "",
            "Recover C2 endpoints, message structures, command IDs, packet fields, serialization, and handlers",
            icon("protocol_packet_explorer", 73)
        ))

        idaapi.register_action(idaapi.action_desc_t(
            "pseudonote_extended:process_injection_explorer",
            "Process Injection Explorer",
            ProcessInjectionExplorerHandler(),
            "",
            "Map allocation, cross-process writes, remote threads, APC injection, section mapping, hollowing, and execution transitions",
            icon("process_injection_explorer", 73)
        ))

        idaapi.register_action(idaapi.action_desc_t(
            "pseudonote_extended:config_ioc_extractor",
            "Configuration and IOC Extractor",
            ConfigurationIOCExtractorHandler(),
            "",
            "Identify configuration structures and extract domains, IPs, paths, mutexes, keys, campaign IDs, and encoded configuration",
            icon("config_ioc_extractor", 73)
        ))

        idaapi.register_action(idaapi.action_desc_t(
            "pseudonote_extended:string_decryption_workbench",
            "String Decryption Workbench",
            StringDecryptionWorkbenchHandler(),
            "",
            "Detect decoder functions, safely preview decoded strings, and annotate references",
            icon("string_decryption_workbench", 73)
        ))

        idaapi.register_action(idaapi.action_desc_t(
            "pseudonote_extended:structure_recovery_explorer",
            "Structure Recovery Explorer",
            StructureRecoveryExplorerHandler(),
            "",
            "Cluster pointer offsets, infer fields and nested structures, compare layouts, and import reviewed types",
            icon("structure_recovery_explorer", 73)
        ))

        idaapi.register_action(idaapi.action_desc_t(
            "pseudonote_extended:anti_analysis_explorer",
            "Anti-Analysis Explorer",
            AntiAnalysisExplorerHandler(),
            "",
            "Detect debugger checks, VM and sandbox probes, timing checks, environment fingerprinting, opaque predicates, and control-flow tricks",
            icon("anti_analysis_explorer", 73)
        ))

        idaapi.register_action(idaapi.action_desc_t(
            "pseudonote_extended:dynamic_api_resolution_explorer",
            "Dynamic API Resolution Explorer",
            DynamicAPIResolutionExplorerHandler(),
            "",
            "Recover APIs resolved through runtime resolvers, hashes, export walking, syscall tables, and custom loaders",
            icon("dynamic_api_resolution_explorer", 73)
        ))

        idaapi.register_action(idaapi.action_desc_t(
            "pseudonote_extended:decompiler_quality_inspector",
            "Decompiler Quality Inspector",
            DecompilerQualityInspectorHandler(),
            "",
            "Find failed decompilations, bad prototypes, stack inconsistencies, suspicious casts, unresolved calls, and variables needing types",
            icon("decompiler_quality_inspector", 73)
        ))

        idaapi.register_action(idaapi.action_desc_t(
            "pseudonote_extended:api_hash_explorer",
            "API Hash Explorer",
            APIHashExplorerHandler(),
            "",
            "Resolve API hash constants using common algorithms and the bundled apilist.txt corpus",
            icon("api_hash_explorer", 73)
        ))

        self.ctx_hooks = vm.ContextMenuHooks()
        self.ctx_hooks.hook()

        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        self.open_code_view()

    def term(self):
        stop_change_history_hooks()
        self.change_history_hooks = None
        destroy_default_visual_hooks()
        self.default_visual_hooks = None
        destroy_highlight_hooks()
        self.highlight_hooks = None
        destroy_indent_guide_hooks()
        self.indent_guide_hooks = None
        shutdown_zoom_all_views()
        if self.ctx_hooks:
            self.ctx_hooks.unhook()
            self.ctx_hooks = None

        # Unregister all actions
        for action_id in [
            "pseudonote_extended:readable_code", "pseudonote_extended:analyst_notes", "pseudonote_extended:list",
            "pseudonote_extended:settings",
            "pseudonote_extended:ui_preview",
            "pseudonote_extended:migrate_legacy",
            "pseudonote_extended:rename_variables", "pseudonote_extended:rename_function",
            "pseudonote_extended:rename_function_malware", "pseudonote_extended:suggest_function_prototype",
            "pseudonote_extended:add_comments", "pseudonote_extended:delete_comments",
            "pseudonote_extended:add_asm_comments", "pseudonote_extended:delete_asm_comments",
            "pseudonote_extended:shellcode_analyst",
            "pseudonote_extended:analyze_struct", "pseudonote_extended:bulk_rename",
            "pseudonote_extended:bulk_var_rename",
            "pseudonote_extended:toggle_highlight", "pseudonote_extended:toggle_disasm_highlight",
            "pseudonote_extended:toggle_indent_guides",
            "pseudonote_extended:bookmarks_empty",
            "pseudonote_extended:zoom_all_views",
            "pseudonote_extended:ask_chat", "pseudonote_extended:ask_chat_chain", "pseudonote_extended:agentic_analysis", "pseudonote_extended:deep_analyzer", "pseudonote_extended:summarizer", "pseudonote_extended:floss_strings",
            "pseudonote_extended:bulk_analyze", "pseudonote_extended:dnspy_xrefs",
            "pseudonote_extended:search_bytes_vt", "pseudonote_extended:search_str_vt",
            "pseudonote_extended:search_str_google", "pseudonote_extended:search_str_github",
            "pseudonote_extended:search_str_msdn", "pseudonote_extended:search_bytes_cyberchef",
            "pseudonote_extended:search_str_cyberchef", "pseudonote_extended:copy_yara_raw",
            "pseudonote_extended:copy_yara_rule", "pseudonote_extended:copy_yara_mask",
            "pseudonote_extended:copy_yara_no_imm", "pseudonote_extended:copy_yara_opcodes",
            "pseudonote_extended:copy_python", "pseudonote_extended:copy_c_array", "pseudonote_extended:copy_disasm",
            "pseudonote_extended:dump_bytes", "pseudonote_extended:hex_viewer",
            "pseudonote_extended:vftable_list",
            "pseudonote_extended:copy_function_tree",
            "pseudonote_extended:copy_global_xref_tree",
            "pseudonote_extended:global_variable_explorer",
            "pseudonote_extended:virtual_class_explorer",
            "pseudonote_extended:callback_dispatch_resolver",
            "pseudonote_extended:thread_sync_explorer",
            "pseudonote_extended:exception_unwind_explorer",
            "pseudonote_extended:syscall_kernel_mapper",
            "pseudonote_extended:entry_point_explorer",
            "pseudonote_extended:regex_idb_search",
            "pseudonote_extended:change_history_explorer",
            "pseudonote_extended:crypto_encoding_explorer",
            "pseudonote_extended:protocol_packet_explorer",
            "pseudonote_extended:process_injection_explorer",
            "pseudonote_extended:config_ioc_extractor",
            "pseudonote_extended:string_decryption_workbench",
            "pseudonote_extended:structure_recovery_explorer",
            "pseudonote_extended:anti_analysis_explorer",
            "pseudonote_extended:dynamic_api_resolution_explorer",
            "pseudonote_extended:decompiler_quality_inspector",
            "pseudonote_extended:api_hash_explorer",
            "pseudonote_extended:auto_enum_explorer",
            "pseudonote_extended:comment_explorer",
        ]:
            idaapi.unregister_action(action_id)
        free_menu_icons()

    def open_view(self, ea=idaapi.BADADDR):
        self.open_code_view(ea)

    def open_code_view(self, ea=idaapi.BADADDR):
        vm = _get_view_module()
        if not self.code_view:
            self.code_view = vm.PseudoNoteView(self.config, mode="code")
        self.code_view._target_ea = ea if ea != idaapi.BADADDR else idaapi.get_screen_ea()
        self.code_view.Show("PseudoNote - Readable Code")
        if ea != idaapi.BADADDR:
            self.code_view.refresh_ui(force=True, target_ea=ea)

    def open_notes_view(self, ea=idaapi.BADADDR):
        vm = _get_view_module()
        if not self.notes_view:
            self.notes_view = vm.PseudoNoteView(self.config, mode="notes")
        self.notes_view._target_ea = ea if ea != idaapi.BADADDR else idaapi.get_screen_ea()
        self.notes_view.Show("PseudoNote - Analyst Notes")
        if ea != idaapi.BADADDR:
            self.notes_view.refresh_ui(force=True, target_ea=ea)

    def Unregister(self):
        if self.view:
            self.view.Close()
            self.view = None
        if self.code_view:
            self.code_view.Close()
            self.code_view = None
        if self.notes_view:
            self.notes_view.Close()
            self.notes_view = None
