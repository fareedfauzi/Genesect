import importlib.util
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
PATH = ROOT / "pseudonote_extended" / "metadata.py"
SPEC = importlib.util.spec_from_file_location("pseudonote_extended_metadata", PATH)
metadata = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = metadata
SPEC.loader.exec_module(metadata)


class MetadataTests(unittest.TestCase):
    def test_extended_identity_is_independent(self):
        self.assertEqual(metadata.PLUGIN_ID, "pseudonote_extended")
        self.assertEqual(metadata.PLUGIN_ENTRY_FILE, "PseudoNoteExtended.py")
        self.assertNotEqual(metadata.CONFIG_FILE_NAME, "PseudoNote.ini")

    def test_supported_python(self):
        self.assertTrue(metadata.check_python_compatibility((3, 11, 0)).supported)

    def test_unsupported_python(self):
        result = metadata.check_python_compatibility((3, 8, 10))
        self.assertFalse(result.supported)
        self.assertIn("unsupported", result.message)


if __name__ == "__main__":
    unittest.main()
