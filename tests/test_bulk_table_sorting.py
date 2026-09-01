import ast
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODEL_FILES = tuple(ROOT / "pseudonote_extended" / name for name in (
    "renamer.py", "var_renamer.py", "analyzer.py",
))


class BulkTableSortingTests(unittest.TestCase):
    def test_custom_models_do_not_nest_resets_when_sorting(self):
        for path in MODEL_FILES:
            source = path.read_text(encoding="utf-8")
            tree = ast.parse(source)
            model = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "VirtualFuncModel")
            method = next(node for node in model.body if isinstance(node, ast.FunctionDef) and node.name == "sort")
            section = ast.get_source_segment(source, method)
            with self.subTest(path=path.name):
                self.assertNotIn("beginResetModel", section)
                self.assertNotIn("endResetModel", section)
                self.assertIn("layoutAboutToBeChanged.emit()", section)
                self.assertIn("layoutChanged.emit()", section)
                self.assertIn("self._sort_filtered(col, ord)", section)

    def test_filtering_uses_signal_free_internal_sort(self):
        for path in MODEL_FILES:
            source = path.read_text(encoding="utf-8")
            tree = ast.parse(source)
            model = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "VirtualFuncModel")
            method = next(node for node in model.body if isinstance(node, ast.FunctionDef) and node.name == "_apply_filter")
            section = ast.get_source_segment(source, method)
            with self.subTest(path=path.name):
                self.assertIn("_sort_filtered", section)
                self.assertNotIn("self.sort(", section)

    def test_every_bulk_view_enables_clickable_header_sorting(self):
        for path in MODEL_FILES:
            self.assertIn("self.table.setSortingEnabled(True)", path.read_text(encoding="utf-8"))
        summary = (ROOT / "pseudonote_extended" / "summarizer.py").read_text(encoding="utf-8")
        self.assertIn("self.function_list.setSortingEnabled(True)", summary)
        self.assertIn("class SortableFunctionPreviewItem", summary)
        deep = (ROOT / "pseudonote_extended" / "deep_analyzer.py").read_text(encoding="utf-8")
        self.assertIn("self.tree.setSortingEnabled(True)", deep)
        self.assertIn("class SortableTreeItem", deep)


if __name__ == "__main__":
    unittest.main()
