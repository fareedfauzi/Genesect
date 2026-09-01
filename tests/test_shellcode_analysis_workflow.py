from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
HANDLERS = (ROOT / "pseudonote_extended" / "handlers.py").read_text(encoding="utf-8")
VIEW = (ROOT / "pseudonote_extended" / "view.py").read_text(encoding="utf-8")


class ShellcodeAnalysisWorkflowTests(unittest.TestCase):
    def test_selection_uses_active_widget_and_bounded_mapped_range(self):
        self.assertIn("read_range_selection(ctx.widget)", HANDLERS)
        self.assertIn("end_ea - 1, _loaded_segments(), max_bytes=64 * 1024", HANDLERS)
        self.assertIn("blob is None or len(blob) != byte_count", HANDLERS)

    def test_evidence_keeps_exact_bytes_and_only_complete_code_items(self):
        self.assertIn('evidence.append("[Raw bytes]\\n" + hex_data)', VIEW)
        self.assertIn("not ida_bytes.is_code(flags) or ea + item_size > end_ea", HANDLERS)
        self.assertIn('asm_lines.append(f"0x{ea:X}: {line}")', HANDLERS)

    def test_architecture_uses_processor_family_not_address_width_alone(self):
        self.assertIn("def _detected_shellcode_architecture():", VIEW)
        self.assertIn("inf_get_procname", VIEW)
        self.assertIn('if "arm" in procname or "aarch" in procname', VIEW)
        self.assertNotIn("idaapi.BADADDR == 0xFFFFFFFFFFFFFFFF", VIEW)

    def test_request_is_bounded_cancellable_and_stale_safe(self):
        self.assertIn('additional_options={"max_completion_tokens": 8192}', VIEW)
        self.assertIn("client.cancel_request(request_id)", VIEW)
        self.assertIn("generation != self._request_generation", VIEW)
        self.assertIn("self.chunk_received.emit(generation", VIEW)
        self.assertIn("self.request_finished.emit(generation", VIEW)
        self.assertIn("len(input_content) > 300000", VIEW)

    def test_dialog_does_not_auto_open_model_links_and_releases_instances(self):
        self.assertIn("self.result_viewer.setOpenExternalLinks(False)", VIEW)
        self.assertIn("dialog.setAttribute(QtCore.Qt.WA_DeleteOnClose, True)", HANDLERS)
        self.assertIn("dialog.destroyed.connect(_release_dialog)", HANDLERS)
