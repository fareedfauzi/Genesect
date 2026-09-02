import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]


class VersionedWindowsInstallerTests(unittest.TestCase):
    def test_ida_installers_mirror_current_package_and_clear_bytecode(self):
        for version in ("83", "93"):
            source = (ROOT / f"install_pseudonote_extended_ida{version}.bat").read_text(encoding="utf-8")
            self.assertIn('robocopy "%SOURCE_DIR%pseudonote_extended" "%TARGET_PACKAGE%" /MIR', source)
            self.assertIn("__pycache__", source)
            self.assertIn("'*.pyc','*.pyo'", source)
            self.assertIn("$env:TARGET_PACKAGE", source)

    def test_source_is_validated_before_destructive_mirroring(self):
        for version in ("83", "93"):
            source = (ROOT / f"install_pseudonote_extended_ida{version}.bat").read_text(encoding="utf-8")
            validation = source.index('if not exist "%SOURCE_DIR%pseudonote_extended\\"')
            mirror = source.index(" /MIR ")
            self.assertLess(validation, mirror)
            self.assertIn('if not exist "%SOURCE_DIR%PseudoNoteExtended.py"', source)


if __name__ == "__main__":
    unittest.main()
