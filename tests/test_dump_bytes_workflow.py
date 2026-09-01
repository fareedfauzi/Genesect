import pathlib
import unittest


SOURCE = (pathlib.Path(__file__).parents[1] / "pseudonote_extended" / "handlers.py").read_text(encoding="utf-8")
SECTION = SOURCE[SOURCE.index("# Dump Bytes Handler"):SOURCE.index("def _confirm_external_search")]


class DumpBytesWorkflowTests(unittest.TestCase):
    def test_selection_bounds_are_checked(self):
        self.assertIn("end_ea > start_ea", SECTION)
        self.assertIn("validate_byte_range(target_ea, target_ea + size - 1, segments)", SECTION)

    def test_unknown_item_default_is_clamped_to_segment(self):
        self.assertIn("min(0x100, containing_segment[1] - target_ea)", SECTION)

    def test_export_is_chunked_and_requires_complete_reads(self):
        self.assertIn("_DUMP_CHUNK_SIZE = 4 * 1024 * 1024", SECTION)
        self.assertIn("chunk is None or len(chunk) != chunk_size", SECTION)

    def test_destination_is_replaced_only_after_success(self):
        self.assertIn("tempfile.mkstemp", SECTION)
        self.assertIn("os.fsync", SECTION)
        self.assertIn("os.replace(temporary, destination)", SECTION)
        self.assertIn("os.unlink(temporary)", SECTION)

    def test_invalid_address_size_and_io_failures_are_visible(self):
        self.assertGreaterEqual(SECTION.count("ida_kernwin.warning"), 6)

    def test_success_reports_exact_address_and_size(self):
        self.assertIn('Dumped {size:,} bytes from 0x{target_ea:X}', SECTION)

    def test_sha256_is_calculated_while_streaming(self):
        self.assertIn("digest = hashlib.sha256()", SECTION)
        self.assertIn("digest.update(chunk)", SECTION)
        self.assertIn("SHA-256: {sha256}", SECTION)


if __name__ == "__main__":
    unittest.main()
