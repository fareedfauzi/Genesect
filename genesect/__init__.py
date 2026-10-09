# -*- coding: utf-8 -*-
"""
Genesect - AI Assistant for IDA Pro
Package initializer. Imports all submodules so they are accessible from the package.
"""

from genesect.metadata import PLUGIN_DISPLAY_NAME, PLUGIN_ID, __version__
from genesect.qt_compat import *
from genesect.config import CONFIG, LOGGER
from genesect.ai_client import SimpleAI, AI_CLIENT
from genesect.highlight import (
    enable_highlighting, disable_highlighting,
    enable_disasm_highlighting, disable_disasm_highlighting,
    toggle_highlight_handler,
    toggle_disasm_highlight_handler,
    _create_highlight_hooks,
)
from genesect.idb_storage import (
    get_netnode, save_to_idb, load_from_idb,
    gather_function_context, format_context_for_prompt, format_context_for_display,
)
from genesect.handlers import (
    RenameVariablesHandler, RenameFunctionHandler,
    RenameMalwareFunctionHandler, SuggestFunctionPrototypeHandler,
    CommentHandler, DeleteCommentsHandler,
    StructAnalysisHandler, StructAnalysisDialog,
    BulkRenameHandler,
)
from genesect.plugin import GenesectPlugin
