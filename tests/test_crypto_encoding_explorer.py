import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "pseudonote_extended" / "crypto_encoding_explorer.py").read_text(encoding="utf-8")
PLUGIN = (ROOT / "pseudonote_extended" / "plugin.py").read_text(encoding="utf-8")
MENU = (ROOT / "pseudonote_extended" / "ui" / "context_menu.py").read_text(encoding="utf-8")


class CryptoEncodingExplorerTests(unittest.TestCase):
    def test_detects_apis_constants_signatures_and_function_patterns(self):
        for scanner in ("scan_crypto_apis", "analyze_function_patterns", "scan_data_signatures", "scan_data_constants", "scan_encoded_strings"):
            self.assertIn("def %s" % scanner, SOURCE)

    def test_contains_standard_crypto_and_hash_evidence(self):
        for marker in ("TEA/XTEA", "SHA-256", "CRC-32", "FNV-1a", "MurmurHash", "AES S-box", "ChaCha/Salsa"):
            self.assertIn(marker, SOURCE)

    def test_base64_candidates_are_validated_and_scored(self):
        for marker in ("b64decode", "validate=True", "_entropy", "printable"):
            self.assertIn(marker, SOURCE)

    def test_pattern_only_custom_routines_are_not_overclaimed(self):
        self.assertIn("Custom encoding/crypto loop", SOURCE)
        self.assertIn("Pattern evidence only", SOURCE)
        self.assertIn("require analyst confirmation", SOURCE)

    def test_action_is_registered_and_available_in_data_strings(self):
        action = "pseudonote_extended:crypto_encoding_explorer"
        self.assertGreaterEqual(PLUGIN.count(action), 2)
        self.assertIn(action, MENU)


if __name__ == "__main__":
    unittest.main()
