# -*- coding: utf-8 -*-
"""
PseudoNote - AI Assistant for IDA Pro
Package initializer. Imports all submodules so they are accessible from the package.
"""

from pseudonote_extended.metadata import PLUGIN_DISPLAY_NAME, PLUGIN_ID, __version__
from pseudonote_extended.qt_compat import *
from pseudonote_extended.config import CONFIG, LOGGER
from pseudonote_extended.ai_client import SimpleAI, AI_CLIENT
from pseudonote_extended.highlight import (
    enable_highlighting, disable_highlighting,
    enable_disasm_highlighting, disable_disasm_highlighting,
    toggle_highlight_handler,
    toggle_disasm_highlight_handler,
    _create_highlight_hooks,
)
from pseudonote_extended.idb_storage import (
    get_netnode, save_to_idb, load_from_idb,
    gather_function_context, format_context_for_prompt, format_context_for_display,
)
from pseudonote_extended.handlers import (
    RenameVariablesHandler, RenameFunctionHandler,
    RenameMalwareFunctionHandler, SuggestFunctionPrototypeHandler,
    CommentHandler, DeleteCommentsHandler,
    StructAnalysisHandler, StructAnalysisDialog,
    BulkRenameHandler,
)
from pseudonote_extended.plugin import PseudoNotePlugin
