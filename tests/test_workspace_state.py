import importlib.util
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
PATH = ROOT / "pseudonote_extended" / "ui" / "workspace.py"
SPEC = importlib.util.spec_from_file_location("pseudonote_extended_ui_workspace", PATH)
workspace = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = workspace
SPEC.loader.exec_module(workspace)


class NavigationStackTests(unittest.TestCase):
    def test_back_forward_and_branching(self):
        nav = workspace.NavigationStack()
        for value in (1, 2, 3):
            nav.record(value)
        self.assertEqual(nav.back(), 2)
        self.assertEqual(nav.back(), 1)
        self.assertEqual(nav.forward(), 2)
        nav.record(4)
        self.assertEqual(nav.items, [1, 2, 4])
        self.assertFalse(nav.can_forward)

    def test_duplicate_current_value_is_ignored(self):
        nav = workspace.NavigationStack()
        self.assertTrue(nav.record(10))
        self.assertFalse(nav.record(10))


class RequestGateTests(unittest.TestCase):
    def test_old_request_is_rejected_after_owner_change(self):
        gate = workspace.RequestGate()
        token = gate.issue(0x401000)
        self.assertTrue(gate.accepts(token, 0x401000))
        gate.advance()
        self.assertFalse(gate.accepts(token, 0x401000))


if __name__ == "__main__":
    unittest.main()
