import ida_kernwin
import ida_pro
with open(r'd:\DEV\PseudoNote-Extended\scratch_lroef.txt', 'w', encoding='utf-8') as f:
    f.write("---- LROEF DUMP ----\n")
    for k in dir(ida_kernwin):
        if k.startswith("LROEF_"):
            f.write(f"{k} = {getattr(ida_kernwin, k)}\n")
ida_pro.qexit(0)
