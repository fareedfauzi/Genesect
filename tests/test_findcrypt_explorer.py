import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "pseudonote_extended" / "findcrypt_explorer.py").read_text(encoding="utf-8")
PLUGIN = (ROOT / "pseudonote_extended" / "plugin.py").read_text(encoding="utf-8")
MENU = (ROOT / "pseudonote_extended" / "ui" / "context_menu.py").read_text(encoding="utf-8")


class FindCryptExplorerTests(unittest.TestCase):
    def test_scans_constants_without_silent_idb_mutation(self):
        scan_body = SOURCE.split("def scan(self):", 1)[1].split("def OnCreate", 1)[0]
        self.assertNotIn("set_name", scan_body)
        self.assertNotIn("set_cmt", scan_body)
        self.assertIn("_load_signatures", scan_body)

    def test_annotation_is_explicit_and_preserves_analyst_names(self):
        self.assertIn("Annotate Selected...", SOURCE)
        self.assertIn("ask_yn", SOURCE)
        self.assertIn("analyst-defined name", SOURCE)
        self.assertIn("SN_CHECK", SOURCE)

    def test_covers_windows_crypto_apis(self):
        for marker in ("CryptAcquireContext", "CryptEncrypt", "BCrypt", "NCrypt", "CryptProtectData", "EncryptMessage"):
            self.assertIn(marker, SOURCE)

    def test_covers_hash_compression_and_encoding_families(self):
        for marker in ("BLAKE", "KECCAK", "HMAC", "ZSTD", "Brotli", "LZ4", "Base64", "Ascii85", "WideCharToMultiByte"):
            self.assertIn(marker, SOURCE)

    def test_covers_additional_and_modern_crypto(self):
        for marker in ("ChaCha", "Poly1305", "Twofish", "Argon2", "GOST", "Ascon", "Kyber", "MLKEM", "Dilithium", "SPHINCS"):
            self.assertIn(marker, SOURCE)

    def test_covers_windows_certificates_and_serialized_encodings(self):
        for marker in ("CryptMsg", "Cert(?:Open", "WinVerifyTrust", "AcquireCredentialsHandle", "protobuf", "msgpack", "CBOR", "ASN1"):
            self.assertIn(marker, SOURCE)

    def test_action_remains_registered_and_menued(self):
        action = "pseudonote_extended:findcrypt_explorer"
        self.assertGreaterEqual(PLUGIN.count(action), 2)
        self.assertIn(action, MENU)


if __name__ == "__main__":
    unittest.main()
