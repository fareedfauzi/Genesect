import sys

with open(r"d:\DEV\PseudoNote-Extended\pseudonote_extended\plugin.py", "r", encoding="utf-8") as f:
    text = f.read()

# 1. Import
import_find = "    CopyGlobalXrefTreeHandler,\n"
if import_find in text:
    text = text.replace(import_find, import_find + "    DecryptionWorkbenchHandler,\n")

# 2. Register
register_find = """        idaapi.register_action(idaapi.action_desc_t(
            "pseudonote_extended:findcrypt_explorer",
            "Find Crypt Explorer",
            FindCryptExplorerHandler(),
            "",
            "Detect crypto, hash, compression, and encoding constants and API usage",
            icon("findcrypt_explorer", 73)
        ))"""
register_add = """

        idaapi.register_action(idaapi.action_desc_t(
            "pseudonote_extended:decryption_workbench",
            "Decryption Workbench",
            DecryptionWorkbenchHandler("pseudonote_extended:decryption_workbench"),
            "",
            "Analyze and decrypt selected strings, data, or constants",
            icon("decryption_workbench", 73)
        ))"""
if register_find in text:
    text = text.replace(register_find, register_find + register_add)

# 3. Unregister
unregister_find = '            "pseudonote_extended:evidence_graph",\n'
if unregister_find in text:
    text = text.replace(unregister_find, unregister_find + '            "pseudonote_extended:decryption_workbench",\n')

with open(r"d:\DEV\PseudoNote-Extended\pseudonote_extended\plugin.py", "w", encoding="utf-8") as f:
    f.write(text)

print("Updated plugin.py")
