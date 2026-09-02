import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "pseudonote_extended" / "api_knowledge.py").read_text(encoding="utf-8")


class ApiKnowledgeTests(unittest.TestCase):
    def test_combines_all_local_api_sources(self):
        for marker in ("malware_api_tags.json", "apilist.txt", 'os.path.join(_API_ROOT, "Windows")', "api_taxonomy.API_MAP"):
            self.assertIn(marker, SOURCE)

    def test_normalizes_common_ida_and_native_aliases(self):
        for marker in ("__imp_", "_imp__", "j_", 'normalized.startswith("Zw")', 'normalized.startswith("Nt")'):
            self.assertIn(marker, SOURCE)

    def test_exposes_semantics_callbacks_taxonomy_and_inventory(self):
        for marker in ("api_signature", "callback_parameters", "taxonomy_entry", "is_ignored_api", "known_api_name", "api_modules"):
            self.assertIn(marker, SOURCE)

    def test_large_xml_corpus_is_lazy_and_cached(self):
        self.assertIn("if _SIGNATURES is not None", SOURCE)
        self.assertNotIn("_load_signatures()\n", SOURCE.split("def api_signature", 1)[0])


if __name__ == "__main__":
    unittest.main()
