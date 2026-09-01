import ast
import pathlib
import unittest


CHAT_CHAIN = pathlib.Path(__file__).resolve().parents[1] / "pseudonote_extended" / "chat_chain.py"


class ChatChainCompatibilityTests(unittest.TestCase):
    def test_ida_kernwin_is_imported_for_navigation(self):
        tree = ast.parse(CHAT_CHAIN.read_text(encoding="utf-8-sig"))
        imported = {
            alias.name
            for node in tree.body if isinstance(node, ast.Import)
            for alias in node.names
        }
        self.assertIn("ida_kernwin", imported)


if __name__ == "__main__":
    unittest.main()
