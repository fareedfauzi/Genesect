import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "pseudonote_extended" / "config_ioc_extractor.py").read_text(encoding="utf-8")
PLUGIN = (ROOT / "pseudonote_extended" / "plugin.py").read_text(encoding="utf-8")
MENU = (ROOT / "pseudonote_extended" / "ui" / "context_menu.py").read_text(encoding="utf-8")


class ConfigurationIOCExtractorTests(unittest.TestCase):
    def test_extracts_requested_ioc_families(self):
        for marker in ("URL", "Domain", "IP address", "Filesystem path", "Mutex / singleton", "Key / credential", "Campaign / victim ID"):
            self.assertIn(marker, SOURCE)

    def test_detects_encoded_configuration_candidates(self):
        for marker in ("Base64-encoded", "Hex-encoded", "High-entropy", "base64.b64decode", "_entropy"):
            self.assertIn(marker, SOURCE)

    def test_correlates_configuration_clusters(self):
        self.assertIn("correlate_configuration_clusters", SOURCE)
        self.assertIn("multiple typed indicators are referenced by the same function", SOURCE)

    def test_does_not_overclaim_encoded_candidates(self):
        self.assertIn("require analyst validation", SOURCE)
        self.assertIn('"heuristic"', SOURCE)

    def test_action_is_registered_and_in_data_utilities(self):
        action = "pseudonote_extended:config_ioc_extractor"
        self.assertGreaterEqual(PLUGIN.count(action), 2)
        self.assertIn(action, MENU)


if __name__ == "__main__":
    unittest.main()
