import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
WINDOWS = (ROOT / "install.bat").read_text(encoding="utf-8")
UNIX = (ROOT / "install.sh").read_text(encoding="utf-8")


class PortableInstallerTests(unittest.TestCase):
    def test_windows_uses_user_plugins_and_supports_override(self):
        self.assertIn("%IDAUSR%\\plugins", WINDOWS)
        self.assertIn("%APPDATA%\\Hex-Rays\\IDA Pro\\plugins", WINDOWS)
        self.assertIn('set "IDA_PLUGINS=%~f1"', WINDOWS)
        self.assertNotIn("IDA Pro 8.3", WINDOWS)
        self.assertNotIn("IDA Professional 9.3", WINDOWS)

    def test_unix_supports_linux_macos_idausr_and_override(self):
        self.assertIn('IDA_PLUGINS=$1', UNIX)
        self.assertIn('$IDAUSR/plugins', UNIX)
        self.assertIn('Library/Application Support/Hex-Rays/IDA Pro/plugins', UNIX)
        self.assertIn('$HOME/.idapro/plugins', UNIX)

    def test_both_copy_entry_point_and_package(self):
        for source in (WINDOWS, UNIX):
            self.assertIn("PseudoNoteExtended.py", source)
            self.assertIn("pseudonote_extended", source)


if __name__ == "__main__":
    unittest.main()
