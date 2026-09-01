import ast
import builtins
import collections
import pathlib
import re
import symtable
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "pseudonote_extended"


class RuntimeIntegrityTests(unittest.TestCase):
    def test_no_unresolved_global_names(self):
        builtins_and_runtime = set(dir(builtins)) | {"__file__", "__name__", "__package__"}
        failures = []
        for path in PACKAGE.rglob("*.py"):
            table = symtable.symtable(path.read_text(encoding="utf-8-sig"), str(path), "exec")
            defined = builtins_and_runtime | {
                symbol.get_name() for symbol in table.get_symbols()
                if symbol.is_assigned() or symbol.is_imported() or symbol.is_namespace()
            }
            unresolved = set()

            def inspect(scope):
                for symbol in scope.get_symbols():
                    if symbol.is_referenced() and symbol.is_global() and symbol.get_name() not in defined:
                        unresolved.add(symbol.get_name())
                for child in scope.get_children():
                    inspect(child)

            inspect(table)
            if unresolved:
                failures.append(f"{path.name}: {', '.join(sorted(unresolved))}")
        self.assertEqual(failures, [])

    def test_classes_and_modules_do_not_silently_replace_duplicate_methods(self):
        failures = []
        for path in PACKAGE.rglob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8-sig"), filename=str(path))
            scopes = [tree] + [node for node in ast.walk(tree) if isinstance(node, ast.ClassDef)]
            for scope in scopes:
                names = [
                    node.name for node in scope.body
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                ]
                duplicates = sorted(name for name, count in collections.Counter(names).items() if count > 1)
                if duplicates:
                    failures.append(f"{path.name}:{getattr(scope, 'name', '<module>')}: {duplicates}")
        self.assertEqual(failures, [])

    def test_context_actions_are_registered_once_and_unregistered(self):
        plugin = (PACKAGE / "plugin.py").read_text(encoding="utf-8")
        context = (PACKAGE / "ui" / "context_menu.py").read_text(encoding="utf-8")
        registered = re.findall(r'action_desc_t\(\s*[\r\n ]*"([^"]+)"', plugin)
        context_actions = re.findall(r'"(pseudonote_extended:[^"]+)"', context)
        teardown = plugin[plugin.index("# Unregister all actions"):]
        unregistered = re.findall(r'"(pseudonote_extended:[^"]+)"', teardown)
        self.assertEqual(len(registered), len(set(registered)))
        self.assertEqual(set(context_actions) - set(registered), set())
        self.assertEqual(set(registered) - set(unregistered), set())

    def test_report_taxonomy_fallback_is_complete(self):
        source = (PACKAGE / "report_generator.py").read_text(encoding="utf-8")
        fallback = source[source.index("except ImportError:"):source.index("# Import IDA-specific helpers")]
        self.assertIn("def get_api_tags_for_function", fallback)
        self.assertIn("def get_category_severity", fallback)


if __name__ == "__main__":
    unittest.main()
