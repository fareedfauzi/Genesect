import importlib.util
import pathlib
import sys
import tempfile
import unittest

PATH = pathlib.Path(__file__).resolve().parents[1] / "pseudonote_extended" / "migration.py"
SPEC = importlib.util.spec_from_file_location("pseudonote_extended_migration", PATH)
migration = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = migration
SPEC.loader.exec_module(migration)


class MigrationTests(unittest.TestCase):
    def test_ini_merge_never_overwrites_target(self):
        with tempfile.TemporaryDirectory() as directory:
            source = pathlib.Path(directory) / "old.ini"
            target = pathlib.Path(directory) / "new.ini"
            source.write_text("[AI]\nmodel=old\nkey=secret\n", encoding="utf-8")
            target.write_text("[AI]\nmodel=new\n", encoding="utf-8")
            result = migration.merge_ini_non_destructive(str(source), str(target))
            text = target.read_text(encoding="utf-8")
            self.assertIn("model = new", text)
            self.assertIn("key = secret", text)
            self.assertEqual(result["copied"], 1)
            self.assertEqual(result["skipped"], 1)

    def test_missing_source_is_safe(self):
        result = migration.merge_ini_non_destructive("missing.ini", "unused.ini")
        self.assertTrue(result["source_missing"])


if __name__ == "__main__":
    unittest.main()
