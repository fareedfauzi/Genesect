import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]


def source(name):
    return (ROOT / "pseudonote_extended" / name).read_text(encoding="utf-8")


class ApiKnowledgeIntegrationTests(unittest.TestCase):
    def test_program_structure_scanners_use_shared_semantics(self):
        callback = source("callback_resolver.py")
        threads = source("thread_sync_explorer.py")
        self.assertIn("callback_parameters", callback)
        self.assertIn("generic_name_match and not callback_params", callback)
        for value in (threads,):
            self.assertIn("normalize_api_name", value)

    def test_malware_scanners_use_taxonomy_inventory_or_normalization(self):
        expected = {
            "process_injection_explorer.py": "taxonomy_entry",
            "anti_analysis_explorer.py": "taxonomy_entry",
            "protocol_packet_explorer.py": "taxonomy_entry",
            "config_ioc_extractor.py": "normalize_api_name",
        }
        for filename, marker in expected.items():
            self.assertIn(marker, source(filename), filename)

    def test_known_noise_sources_require_corroboration(self):
        protocol = source("protocol_packet_explorer.py")
        config = source("config_ioc_extractor.py")
        anti = source("anti_analysis_explorer.py")
        self.assertNotIn("memcpy|copy_memory", protocol)
        self.assertIn("if dual_use and owner not in evidence_functions", config)
        self.assertIn("A timestamp source by itself is normal application behavior", anti)


if __name__ == "__main__":
    unittest.main()
