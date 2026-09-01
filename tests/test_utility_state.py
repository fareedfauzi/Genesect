import importlib.util
import pathlib
import sys
import unittest

PATH = pathlib.Path(__file__).resolve().parents[1] / "pseudonote_extended" / "utility_state.py"
SPEC = importlib.util.spec_from_file_location("pseudonote_extended_utility_state", PATH)
utility = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = utility
SPEC.loader.exec_module(utility)


class UtilityStateTests(unittest.TestCase):
    def test_valid_range(self):
        self.assertEqual(utility.validate_byte_range(0x1000, 0x10FF, [(0x1000, 0x2000)]), (True, "", 256))

    def test_gap_is_rejected(self):
        valid, message, _ = utility.validate_byte_range(0x1000, 0x30FF, [(0x1000, 0x2000), (0x3000, 0x4000)])
        self.assertFalse(valid)
        self.assertIn("unmapped gap", message)

    def test_large_range_is_rejected(self):
        self.assertFalse(utility.validate_byte_range(0, 1000, [(0, 2000)], max_bytes=100)[0])

    def test_search_history_is_unique_and_bounded(self):
        history = utility.SearchHistory(2)
        history.add("one")
        history.add("two")
        history.add("one")
        history.add("three")
        self.assertEqual(history.values, ["three", "one"])
        self.assertEqual(utility.SearchHistory.from_json(history.to_json(), 2).values, history.values)


if __name__ == "__main__":
    unittest.main()
