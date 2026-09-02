import ast
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
FEATURES = (
    "api_sequence_explorer",
    "evidence_graph",
)


class SemanticExplorerTests(unittest.TestCase):
    def test_modules_compile(self):
        for feature in FEATURES:
            ast.parse((ROOT / "pseudonote_extended" / (feature + ".py")).read_text(encoding="utf-8"))

    def test_actions_are_registered_menued_and_unregistered(self):
        plugin = (ROOT / "pseudonote_extended" / "plugin.py").read_text(encoding="utf-8")
        menu = (ROOT / "pseudonote_extended" / "ui" / "context_menu.py").read_text(encoding="utf-8")
        for feature in FEATURES:
            action = "pseudonote_extended:" + feature
            self.assertGreaterEqual(plugin.count('"%s"' % action), 2)
            self.assertIn('"%s"' % action, menu)

    def test_noise_controls_are_explicit(self):
        sequence = (ROOT / "pseudonote_extended" / "api_sequence_explorer.py").read_text(encoding="utf-8")
        self.assertIn('knowledge"].get("ignored")', sequence)


if __name__ == "__main__":
    unittest.main()
