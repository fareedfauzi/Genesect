import pathlib
import unittest


ROOT = pathlib.Path(__file__).parents[1]
RENAMER = (ROOT / "pseudonote_extended" / "renamer.py").read_text(encoding="utf-8")
HANDLERS = (ROOT / "pseudonote_extended" / "handlers.py").read_text(encoding="utf-8")
DEEP = (ROOT / "pseudonote_extended" / "deep_analyzer.py").read_text(encoding="utf-8")


class BulkRenamerWindowTests(unittest.TestCase):
    def test_function_renamer_uses_shared_workspace_theme(self):
        start = RENAMER.index("    def setup_ui(self):")
        setup = RENAMER[start:RENAMER.index("    def on_table_context_menu", start)]
        self.assertIn("apply_mac_workspace(self)", setup)

    def test_handler_opens_standalone_taskbar_dialog(self):
        section = HANDLERS[
            HANDLERS.index("class BulkRenameHandler"):
            HANDLERS.index("# Bulk Function Analyzer Handler")
        ]
        self.assertIn("renamer.BulkRenamer(CONFIG, parent=None)", section)
        self.assertIn("self.dlg.show()", section)
        self.assertIn("self.dlg.showNormal()", section)
        self.assertNotIn("QtCore.Qt.WA_DeleteOnClose", section)
        self.assertNotIn("PluginFormWrapper", section)

    def test_bulk_analyzer_opens_as_standalone_dialog(self):
        section = HANDLERS[
            HANDLERS.index("class BulkAnalyzeHandler"):
            HANDLERS.index("# Bulk Variable Renamer Handler")
        ]
        self.assertIn("analyzer.BulkAnalyzer(parent=None)", section)
        self.assertIn("self.dlg.show()", section)
        self.assertIn("self.dlg.showNormal()", section)
        self.assertNotIn("QtCore.Qt.WA_DeleteOnClose", section)
        self.assertNotIn("PluginFormWrapper", section)

    def test_bulk_variable_renamer_opens_as_standalone_dialog(self):
        section = HANDLERS[
            HANDLERS.index("class BulkVarRenameHandler"):
            HANDLERS.index("# Ask AI (Chat) Handler")
        ]
        self.assertIn("var_renamer.BulkVariableRenamer(parent=None)", section)
        self.assertIn("self.dlg.show()", section)
        self.assertIn("self.dlg.showNormal()", section)
        self.assertNotIn("QtCore.Qt.WA_DeleteOnClose", section)
        self.assertNotIn("destroyed.connect", section)
        self.assertNotIn("PluginFormWrapper", section)

    def test_deep_analyzer_opens_as_standalone_dialog(self):
        section = DEEP[DEEP.index("class DeepAnalyzerHandler"):]
        self.assertIn("DeepAnalyzerDialog(parent=None)", section)
        self.assertIn("self.dlg.show()", section)
        self.assertIn("self.dlg.showNormal()", section)
        self.assertNotIn("QtCore.Qt.WA_DeleteOnClose", section)
        self.assertNotIn("PluginFormWrapper", section)

    def test_standalone_workbenches_request_real_window_flags(self):
        sources = {
            "renamer.py": RENAMER,
            "analyzer.py": (ROOT / "pseudonote_extended" / "analyzer.py").read_text(encoding="utf-8"),
            "var_renamer.py": (ROOT / "pseudonote_extended" / "var_renamer.py").read_text(encoding="utf-8"),
            "deep_analyzer.py": DEEP,
            "xrefs.py": (ROOT / "pseudonote_extended" / "xrefs.py").read_text(encoding="utf-8"),
        }
        for name, source in sources.items():
            self.assertIn("Qt.Window", source, name)


if __name__ == "__main__":
    unittest.main()
