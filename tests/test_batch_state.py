import importlib.util
import pathlib
import sys
import unittest

PATH = pathlib.Path(__file__).resolve().parents[1] / "pseudonote_extended" / "batch" / "state.py"
SPEC = importlib.util.spec_from_file_location("pseudonote_extended_batch_state", PATH)
batch = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = batch
SPEC.loader.exec_module(batch)


class BatchStateTests(unittest.TestCase):
    def test_estimate_uses_selected_retryable_rows(self):
        items = [batch.BatchItem(str(i), str(i), context_chars=100) for i in range(5)]
        items[-1].selected = False
        session = batch.BatchSession("rename", items, batch_size=3)
        self.assertEqual(session.estimate(), {"items": 4, "requests": 2, "context_chars": 400})

    def test_only_selected_complete_results_are_applicable(self):
        done = batch.BatchItem("1", "one", status=batch.BatchStatus.COMPLETE, result="name")
        pending = batch.BatchItem("2", "two", result="other")
        self.assertEqual(batch.BatchSession("rename", [done, pending]).applicable(), [done])

    def test_failed_items_can_retry(self):
        item = batch.BatchItem("1", "one", status=batch.BatchStatus.FAILED, selected=False, reason="timeout")
        session = batch.BatchSession("rename", [item])
        session.retry_failed()
        self.assertEqual(item.status, batch.BatchStatus.PENDING)
        self.assertTrue(item.selected)
        self.assertEqual(item.reason, "")

    def test_invalid_transition_is_rejected(self):
        item = batch.BatchItem("1", "one")
        with self.assertRaises(ValueError):
            item.transition(batch.BatchStatus.COMPLETE)

    def test_session_round_trip(self):
        original = batch.BatchSession("analysis", [batch.BatchItem("401000", "start")], 4, 2)
        restored = batch.BatchSession.from_json(original.to_json())
        self.assertEqual(restored.workflow, "analysis")
        self.assertEqual(restored.items[0].status, batch.BatchStatus.PENDING)

    def test_duplicate_names_are_stable(self):
        result = batch.resolve_unique_names([("a", "parse"), ("b", "parse"), ("c", "parse")], {"parse_2"})
        self.assertEqual(result, {"a": "parse", "b": "parse_3", "c": "parse_4"})


if __name__ == "__main__":
    unittest.main()
