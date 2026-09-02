# -*- coding: utf-8 -*-
import idaapi
import ida_bytes
import ida_name
import ida_typeinf
import ida_kernwin
try:
    import ida_hexrays
except ImportError:
    ida_hexrays = None

from pseudonote_extended.decryption_models import DecryptionTarget

class DecryptionExtractor:
    @staticmethod
    def extract_from_ui(vu=None) -> DecryptionTarget:
        """
        Extracts a decryption target based on the current UI selection or cursor position.
        Uses IDA's execute_sync to safely interact with the database.
        """
        class UIExtractorTask:
            def __init__(self, vu_):
                self.vu = vu_
                self.target = None

            def __call__(self):
                widget = ida_kernwin.get_current_widget()
                widget_type = ida_kernwin.get_widget_type(widget)

                # Check for explicit selection first
                selection, start_ea, end_ea = ida_kernwin.read_range_selection(None)
                if selection and start_ea != idaapi.BADADDR and end_ea != idaapi.BADADDR:
                    if end_ea > start_ea:
                        self._extract_selection(start_ea, end_ea)
                        return 1

                # If pseudocode view
                if widget_type == ida_kernwin.BWN_PSEUDOCODE or self.vu:
                    vu = self.vu or ida_hexrays.get_widget_vdui(widget)
                    if vu:
                        self._extract_pseudocode(vu)
                        if self.target:
                            return 1

                # If disassembly or hex view, try current item
                ea = ida_kernwin.get_screen_ea()
                if ea != idaapi.BADADDR:
                    self._extract_disassembly_item(ea)

                return 1
            
            def _extract_selection(self, start_ea, end_ea):
                length = end_ea - start_ea
                if length > 1024 * 1024:
                    length = 1024 * 1024  # Max 1MB
                raw = ida_bytes.get_bytes(start_ea, length)
                if not raw:
                    return
                self.target = DecryptionTarget(
                    source_kind="selection",
                    view_kind="disassembly",
                    start_ea=start_ea,
                    end_ea=end_ea,
                    function_ea=None,
                    expression_ea=None,
                    item_width=1,
                    count=length,
                    raw_bytes=raw,
                    original_value=None,
                    signed=False,
                    byte_order="little",
                    ida_type="byte",
                    display_name=f"Selection {hex(start_ea)}-{hex(end_ea)}",
                    patchability="exact",
                    patch_reason="Explicit address range selected",
                    selection_text="",
                    provenance=["Explicit selection"]
                )
                
            def _extract_pseudocode(self, vu):
                citem = vu.item.it
                if not citem:
                    return
                if citem.op == ida_hexrays.cot_num:
                    self._extract_number(citem.cn, vu.cfunc.entry_ea)
                elif citem.op == ida_hexrays.cot_obj:
                    self._extract_disassembly_item(citem.obj_ea, vu.cfunc.entry_ea)
                elif citem.op == ida_hexrays.cot_var:
                    # Synthetic local variable
                    self.target = DecryptionTarget(
                        source_kind="local",
                        view_kind="pseudocode",
                        start_ea=None, end_ea=None,
                        function_ea=vu.cfunc.entry_ea,
                        expression_ea=citem.ea,
                        item_width=citem.type.get_size() or 1,
                        count=1,
                        raw_bytes=b"",
                        original_value=None, signed=None, byte_order="little",
                        ida_type="local_var",
                        display_name="Local Variable",
                        patchability="comment_only",
                        patch_reason="Local variables exist on the stack or in registers and cannot be patched statically.",
                        selection_text="local",
                        provenance=["Selected cot_var in pseudocode"]
                    )
            
            def _extract_number(self, cot_num, func_ea):
                val = cot_num.value()
                width = cot_num.type.get_size()
                if width <= 0 or width > 8:
                    width = 4
                raw = val.to_bytes(width, 'little', signed=False)
                self.target = DecryptionTarget(
                    source_kind="immediate",
                    view_kind="pseudocode",
                    start_ea=None, end_ea=None,
                    function_ea=func_ea,
                    expression_ea=cot_num.ea, # Not actual EA of the instruction operand, just the expression
                    item_width=width,
                    count=1,
                    raw_bytes=raw,
                    original_value=val,
                    signed=False,
                    byte_order="little",
                    ida_type="int",
                    display_name=f"Constant {hex(val)}",
                    patchability="comment_only",
                    patch_reason="Immediate constants in pseudocode are not safely mapped to instruction operands yet.",
                    selection_text=hex(val),
                    provenance=["Selected cot_num in pseudocode"]
                )

            def _extract_disassembly_item(self, ea, func_ea=None):
                item_size = ida_bytes.get_item_size(ea)
                if item_size <= 0:
                    item_size = 1
                start_ea = ea
                end_ea = ea + item_size
                raw = ida_bytes.get_bytes(start_ea, item_size)
                if not raw:
                    return
                name = ida_name.get_short_name(start_ea)
                if not name:
                    name = f"Data at {hex(start_ea)}"
                
                self.target = DecryptionTarget(
                    source_kind="data",
                    view_kind="disassembly",
                    start_ea=start_ea,
                    end_ea=end_ea,
                    function_ea=func_ea,
                    expression_ea=None,
                    item_width=1,
                    count=item_size,
                    raw_bytes=raw,
                    original_value=None,
                    signed=False,
                    byte_order="little",
                    ida_type="unknown",
                    display_name=name,
                    patchability="exact",
                    patch_reason="Static data item selected",
                    selection_text="",
                    provenance=[f"Inferred item at {hex(start_ea)}"]
                )

        task = UIExtractorTask(vu)
        idaapi.execute_sync(task, idaapi.MFF_READ)
        return task.target
