import importlib.util
import pathlib
import unittest

PATH = pathlib.Path(__file__).resolve().parents[1] / "pseudonote_extended" / "chat_state.py"
SPEC = importlib.util.spec_from_file_location("pseudonote_extended_chat_state", PATH)
state = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(state)
selection_signature = state.selection_signature
split_context_blocks = state.split_context_blocks
normalize_chat_history = state.normalize_chat_history
build_context_snapshot = state.build_context_snapshot


class ChatStateTests(unittest.TestCase):
    def test_oversized_block_is_bounded(self):
        chunks = split_context_blocks(["A" * 6100], limit=2000)
        self.assertEqual("".join(chunks), "A" * 6100)
        self.assertTrue(all(len(chunk) <= 2000 for chunk in chunks))

    def test_line_split_preserves_content(self):
        original = ("line one\n" * 400) + "tail"
        chunks = split_context_blocks([original], limit=1000)
        self.assertEqual("".join(chunks), original)

    def test_blocks_are_packed_without_exceeding_limit(self):
        chunks = split_context_blocks(["A" * 700, "B" * 700, "C" * 700], limit=1500)
        self.assertEqual(len(chunks), 2)
        self.assertTrue(all(len(chunk) <= 1500 for chunk in chunks))

    def test_selection_signature_is_stable(self):
        self.assertEqual(selection_signature([3, 1, 3, 2]), (1, 2, 3))

    def test_malformed_history_is_safely_normalized(self):
        system = {"role": "system", "content": "context"}
        rows = normalize_chat_history({"bad": "shape"}, system)
        self.assertEqual(rows, [system])

    def test_context_snapshot_is_bounded_and_reports_omissions(self):
        snapshot, included, truncated = build_context_snapshot(
            ["A" * 700, "B" * 700, "C" * 700], max_chars=1200
        )
        self.assertLessEqual(len(snapshot), 1200)
        self.assertEqual(included, 2)
        self.assertEqual(truncated, 2)


if __name__ == "__main__":
    unittest.main()
