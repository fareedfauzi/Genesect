import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "pseudonote_extended" / "summarizer.py").read_text(encoding="utf-8")


class SummarizerFunctionSidebarTests(unittest.TestCase):
    def test_loading_current_function_builds_sidebar_graph(self):
        self.assertIn("class FunctionPreviewWorker(QThread)", SOURCE)
        self.assertIn("self.load_function_preview()", SOURCE)
        self.assertIn('QGroupBox("Loaded Functions")', SOURCE)
        self.assertIn("self.function_list = QtWidgets.QTreeWidget()", SOURCE)
        self.assertIn('setHeaderLabels(["Address", "Function", "Depth"])', SOURCE)

    def test_sidebar_supports_ida_navigation(self):
        self.assertIn("itemDoubleClicked.connect(self.navigate_to_function)", SOURCE)
        self.assertIn("ida_kernwin.jumpto(int(ea))", SOURCE)

    def test_report_tabs_do_not_elide_or_truncate(self):
        self.assertIn("configure_content_tabs(self.tabs)", SOURCE)
        self.assertIn('self.tabs.setObjectName("summarizerTabs")', SOURCE)
        self.assertNotIn("self.tabs.tabBar().setExpanding(True)", SOURCE)
        self.assertNotIn("self.tabs.tabBar().setUsesScrollButtons(False)", SOURCE)
        self.assertIn("self.tabs.setMinimumWidth(420)", SOURCE)

    def test_preview_worker_is_stopped_when_dialog_closes(self):
        self.assertIn("self.preview_worker.stop()", SOURCE)
        self.assertIn("self.preview_worker.wait(1500)", SOURCE)


if __name__ == "__main__":
    unittest.main()
