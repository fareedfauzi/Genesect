import pathlib
import unittest


SOURCE = (pathlib.Path(__file__).parents[1] / "pseudonote_extended" / "floss_strings.py").read_text(encoding="utf-8")


class FlossWorkflowTests(unittest.TestCase):
    def test_linux_macos_and_windows_executable_resolution(self):
        self.assertIn("def resolve_floss_executable", SOURCE)
        self.assertIn("shutil.which", SOURCE)
        self.assertIn("os.access(path, os.X_OK)", SOURCE)
        self.assertIn('("FormToPyQtWidget", "FormToPySideWidget")', SOURCE)

    def test_new_scan_choice_is_not_treated_as_cancel(self):
        section = SOURCE[SOURCE.index("def show_floss_strings_ui"):]
        self.assertIn("elif choice == -1", section)
        self.assertNotIn("choice == -1 or choice == 0", section)

    def test_elf_and_macho_are_not_forced_into_shellcode_mode(self):
        self.assertIn("is_elf =", SOURCE)
        self.assertIn("is_macho =", SOURCE)
        self.assertIn("if not (is_pe or is_elf or is_macho):", SOURCE)

    def test_posix_and_windows_input_extensions_are_supported(self):
        for extension in ('".exe"', '".elf"', '".so"', '".dylib"'):
            self.assertIn(extension, SOURCE)

    def test_worker_has_timeout_cancellation_and_output_limits(self):
        self.assertIn("FLOSS_TIMEOUT_SECONDS = 30 * 60", SOURCE)
        self.assertIn("def cancel(self):", SOURCE)
        self.assertIn("MAX_FLOSS_OUTPUT_BYTES = 256 * 1024 * 1024", SOURCE)
        self.assertIn("MAX_FLOSS_ENTRIES = 200000", SOURCE)
        self.assertIn("os.killpg(proc.pid, signal.SIGTERM)", SOURCE)

    def test_selected_tool_is_validated_and_empty_json_is_diagnostic(self):
        self.assertIn("def validate_floss_executable", SOURCE)
        self.assertIn('[path, "-h"]', SOURCE)
        self.assertIn("not Mandiant FLARE-FLOSS", SOURCE)
        self.assertIn("def decode_floss_json", SOURCE)
        self.assertIn("returned no JSON output", SOURCE)
        self.assertIn("decode_floss_json(stdout, stderr)", SOURCE)

    def test_uses_official_json_form_and_supports_legacy_text_output(self):
        self.assertIn('cmd = [floss_path, "--json"]', SOURCE)
        self.assertNotIn('cmd = [floss_path, "-j"]', SOURCE)
        self.assertIn("def decode_floss_text", SOURCE)
        self.assertIn("raw_entries = decode_floss_text(stdout)", SOURCE)
        self.assertIn("find_ida_string_address", SOURCE)

    def test_addresses_accept_decimal_and_hex_strings(self):
        self.assertIn("def _coerce_address", SOURCE)
        self.assertIn("int(value, 0)", SOURCE)

    def test_overlapping_scans_are_prevented_and_thread_is_released(self):
        self.assertIn("floss_thread.isRunning()", SOURCE)
        self.assertIn("floss_thread.finished.connect(_clear_floss_thread)", SOURCE)
        self.assertIn("if floss_strings_chooser is self:", SOURCE)


if __name__ == "__main__":
    unittest.main()
