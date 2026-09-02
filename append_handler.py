import os

text_to_append = """

class DecryptionWorkbenchHandler(idaapi.action_handler_t):
    def __init__(self, action_id, title="Decryption Workbench"):
        idaapi.action_handler_t.__init__(self)
        self.action_id = action_id
        self.title = title

    def activate(self, ctx):
        import ida_kernwin
        try:
            import ida_hexrays
        except ImportError:
            ida_hexrays = None
            
        from pseudonote_extended.decryption_extractor import DecryptionExtractor
        from pseudonote_extended.ui.decryption_workbench import DecryptionWorkbenchUI
        
        vu = None
        if ida_hexrays and ctx.widget_type == ida_kernwin.BWN_PSEUDOCODE:
            vu = ida_hexrays.get_widget_vdui(ctx.widget)
            
        target = DecryptionExtractor.extract_from_ui(vu)
        if not target:
            ida_kernwin.warning("Could not extract a valid decryption target from the current selection.\\nSelect some data, string or hex item.")
            return 0
            
        dlg = DecryptionWorkbenchUI(target, None)
        dlg.exec_()
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS
"""

with open(r"d:\DEV\PseudoNote-Extended\pseudonote_extended\handlers.py", "a", encoding="utf-8") as f:
    f.write(text_to_append)
print("Appended.")
