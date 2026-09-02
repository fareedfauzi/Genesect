import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
README = (ROOT / "README.md").read_text(encoding="utf-8-sig")
DOCS_INDEX = (ROOT / "docs" / "README.md").read_text(encoding="utf-8-sig")
GETTING_STARTED = (ROOT / "docs" / "getting-started.md").read_text(encoding="utf-8-sig")
AI = (ROOT / "docs" / "ai-assistant.md").read_text(encoding="utf-8-sig")
UTILITIES = (ROOT / "docs" / "utilities.md").read_text(encoding="utf-8-sig")
BUILDER = (ROOT / "tools" / "build_release.py").read_text(encoding="utf-8-sig")


class PublicDocumentationTests(unittest.TestCase):
    def test_root_readme_links_all_tutorial_guides(self):
        for relative in (
            "docs/README.md",
            "docs/getting-started.md",
            "docs/ai-assistant.md",
            "docs/utilities.md",
        ):
            self.assertIn(relative, README)
            self.assertTrue((ROOT / relative).is_file())

    def test_docs_index_links_guides(self):
        for name in ("getting-started.md", "ai-assistant.md", "utilities.md"):
            self.assertIn(name, DOCS_INDEX)

    def test_ai_workflows_have_tutorial_sections(self):
        required = (
            "Chat About This Function", "Chat About a Function Chain",
            "Function Chain Summarizer", "Autonomous Investigation",
            "Bulk Function Renamer", "Bulk Variable Renamer",
            "Bulk Function Analysis", "Deep Analyzer with Report",
            "Suggest Function Prototype", "Infer / Edit Structure",
            "Generate Pseudocode Comments", "Generate Disassembly Comments",
            "Analyze Selected Bytes / Shellcode",
        )
        for title in required:
            self.assertIn(title, AI)

    def test_workspace_and_utility_features_are_documented(self):
        for title in ("Settings", "Open Readable Code", "Open Analyst Notes", "Browse Saved Artifacts"):
            self.assertIn(title, GETTING_STARTED)
        required_utilities = (
            "Hex Viewer", "Indent Marks",
            "Global Variable Explorer", "Call Tree", "Virtual-Class Explorer",
            "Callback Explorer", "Thread Explorer", "Entry-Point Explorer",
            "Find Crypt Explorer", "Anti-Analysis Explorer", "Process Injection Explorer",
            "C2, Protocol and Packet Explorer", "API Sequence Explorer",
            "API Classification Explorer", "Configuration and IOC Extractor",
            "Regex Search Across IDB", "FLOSS Integration", "Dump Selected Bytes",
            "Comment Explorer",
        )
        for title in required_utilities:
            self.assertIn(title, UTILITIES)

    def test_release_builder_includes_docs_tree(self):
        self.assertIn('ROOT / "docs"', BUILDER)


if __name__ == "__main__":
    unittest.main()
