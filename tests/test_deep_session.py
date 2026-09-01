import importlib.util
import pathlib
import sys
import tempfile
import unittest

PATH = pathlib.Path(__file__).resolve().parents[1] / "pseudonote_extended" / "deep_session.py"
SPEC = importlib.util.spec_from_file_location("pseudonote_extended_deep_session", PATH)
session = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = session
SPEC.loader.exec_module(session)


class DeepSessionTests(unittest.TestCase):
    def test_atomic_round_trip_and_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            path = str(pathlib.Path(directory) / "graph.json")
            session.atomic_write_json(path, session.envelope(0x401000, "abc", [{"ea": 0x401000}]))
            restored = session.load_json_recover(path, 0x401000, "abc")
            self.assertEqual(restored["schema_version"], session.SCHEMA_VERSION)

    def test_rejects_different_entry(self):
        with tempfile.TemporaryDirectory() as directory:
            path = str(pathlib.Path(directory) / "graph.json")
            session.atomic_write_json(path, session.envelope(1, "abc", []))
            with self.assertRaises(session.SessionMismatch):
                session.load_json_recover(path, 2, "abc")

    def test_recovers_backup_after_partial_corruption(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "graph.json"
            session.atomic_write_json(str(path), session.envelope(1, "abc", [{"ea": 1}]))
            session.atomic_write_json(str(path), session.envelope(1, "abc", [{"ea": 2}]))
            path.write_text("{broken", encoding="utf-8")
            restored = session.load_json_recover(str(path), 1, "abc")
            self.assertTrue(restored["recovered_from_backup"])
            self.assertEqual(restored["nodes"][0]["ea"], 1)


if __name__ == "__main__":
    unittest.main()
