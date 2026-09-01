import importlib.util
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
PATH = ROOT / "pseudonote_extended" / "diagnostics.py"
SPEC = importlib.util.spec_from_file_location("pseudonote_extended_diagnostics", PATH)
diagnostics = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = diagnostics
SPEC.loader.exec_module(diagnostics)


class DiagnosticsTests(unittest.TestCase):
    def test_event_serializes_context(self):
        event = diagnostics.make_event("info", "tests", "ready", operation="baseline")
        self.assertEqual(event.to_dict()["level"], "INFO")

    def test_guarded_reports_exception_and_returns_fallback(self):
        events = []

        @diagnostics.guarded("tests", "explode", events.append, fallback=False)
        def explode():
            raise ValueError("expected")

        self.assertFalse(explode())
        self.assertEqual(events[0].exception_type, "ValueError")


if __name__ == "__main__":
    unittest.main()
