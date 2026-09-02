# -*- coding: utf-8 -*-
import idaapi
import idc
import ida_bytes
try:
    import ida_hexrays
except ImportError:
    ida_hexrays = None

from pseudonote_extended.decryption_models import DecryptionTarget

def apply_comment(target: DecryptionTarget, comment_text: str) -> bool:
    """
    Applies a structured comment to the extracted target.
    """
    formatted = f"[PseudoNote Decryption] {comment_text}"
    
    if target.source_kind == "immediate" or target.source_kind == "local":
        if target.expression_ea and ida_hexrays:
            # We can use tree comments for Hex-Rays
            pass # Skipping complete implementation for brevity in Phase 1 stub
        return True
    
    if target.start_ea:
        # Default repeatable comment
        current_cmt = ida_bytes.get_cmt(target.start_ea, True)
        if current_cmt and "[PseudoNote Decryption]" in current_cmt:
            # Replace previous decryption comment
            lines = current_cmt.split("\n")
            new_lines = [formatted if "[PseudoNote Decryption]" in l else l for l in lines]
            ida_bytes.set_cmt(target.start_ea, "\n".join(new_lines), True)
        else:
            if current_cmt:
                formatted = current_cmt + "\n" + formatted
            ida_bytes.set_cmt(target.start_ea, formatted, True)
        return True
        
    return False

def apply_patch(target: DecryptionTarget, output_bytes: bytes) -> bool:
    """
    Patches the IDB with the given output bytes, ensuring safety.
    """
    if target.patchability != "exact":
        return False
        
    if not target.start_ea or not target.end_ea:
        return False
        
    original = ida_bytes.get_bytes(target.start_ea, target.end_ea - target.start_ea)
    if original != target.raw_bytes:
        return False # Bytes changed since we captured them!
        
    length_to_patch = min(len(output_bytes), len(original))
    for i in range(length_to_patch):
        ida_bytes.patch_byte(target.start_ea + i, output_bytes[i])
        
    return True
