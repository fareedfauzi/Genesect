import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]


def source(name):
    return (ROOT / "pseudonote_extended" / name).read_text(encoding="utf-8")


class FeatureTitleTests(unittest.TestCase):
    def test_primary_ai_feature_titles_are_consistent(self):
        expected = {
            "chat.py": "PseudoNote - Chat About This Function",
            "chat_chain.py": "PseudoNote - Chat About a Function Chain",
            "agentic_analyzer.py": "PseudoNote - Autonomous Investigation",
            "summarizer.py": "PseudoNote - Function Chain Summarizer",
            "renamer.py": "PseudoNote - Bulk Function Renamer",
            "var_renamer.py": "PseudoNote - Bulk Variable Renamer",
            "analyzer.py": "PseudoNote - Bulk Function Analysis",
            "deep_analyzer.py": "PseudoNote - Deep Analyzer with Report",
        }
        for filename, title in expected.items():
            self.assertIn(title, source(filename), filename)

    def test_primary_utility_titles_use_standard_prefix(self):
        expected = {
            "hexview.py": "PseudoNote - Hex Viewer",
            "vftable.py": "PseudoNote - VTable Explorer",
            "xrefs.py": "PseudoNote - Call Tree",
            "floss_strings.py": "PseudoNote - Discover Strings with FLOSS",
            "findcrypt_explorer.py": "PseudoNote - Find Crypt Explorer",
        }
        for filename, title in expected.items():
            self.assertIn(title, source(filename), filename)

    def test_workspace_titles_use_standard_prefix(self):
        plugin = source("plugin.py")
        view = source("view.py")
        for title in ("PseudoNote - Readable Code", "PseudoNote - Analyst Notes"):
            self.assertIn(title, plugin)
            self.assertIn(title, view)
        self.assertIn("PseudoNote - Settings", view)

    def test_legacy_feature_title_separators_are_gone(self):
        combined = "\n".join(path.read_text(encoding="utf-8") for path in (ROOT / "pseudonote_extended").glob("*.py"))
        for legacy in ("PseudoNote —", "PseudoNote: Bulk", "PseudoNote Extended —"):
            self.assertNotIn(legacy, combined)


if __name__ == "__main__":
    unittest.main()
