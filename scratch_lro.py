import ida_kernwin
import ida_pro
with open(r'd:\DEV\PseudoNote-Extended\scratch_lro.txt', 'w', encoding='utf-8') as f:
    f.write("---- LRO DUMP ----\n")
    for k in dir(ida_kernwin.line_rendering_output_entry_t):
        if not k.startswith("__"):
            f.write(f"{k}\n")
ida_pro.qexit(0)
