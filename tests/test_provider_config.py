import importlib.util
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
PATH = ROOT / "pseudonote_extended" / "provider_config.py"
SPEC = importlib.util.spec_from_file_location("pseudonote_extended_provider_config", PATH)
providers = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = providers
SPEC.loader.exec_module(providers)


class ProviderConfigTests(unittest.TestCase):
    def test_aliases_normalize(self):
        self.assertEqual(providers.normalize_provider("custom"), "OpenAICompatible")
        self.assertEqual(providers.normalize_provider("LMStudio"), "LMStudio")

    def test_hosted_provider_requires_key(self):
        profile = providers.ProviderProfile("OpenAI", "", "https://api.openai.com/v1", "gpt-4o")
        result = providers.validate_profile(profile)
        self.assertFalse(result.valid)
        self.assertIn("API key", result.errors[0])

    def test_profile_can_be_saved_without_api_key(self):
        profile = providers.ProviderProfile("OpenAI", "", "https://api.openai.com/v1", "gpt-4o")
        result = providers.validate_profile(profile, require_api_key=False)
        self.assertTrue(result.valid)
        self.assertTrue(any("settings can be saved" in warning for warning in result.warnings))

    def test_local_provider_does_not_require_key(self):
        profile = providers.ProviderProfile("Ollama", "", "http://localhost:11434/v1", "llama3")
        self.assertTrue(providers.validate_profile(profile).valid)

    def test_invalid_url_is_rejected(self):
        profile = providers.ProviderProfile("OpenAICompatible", "", "localhost:8000", "model")
        self.assertFalse(providers.validate_profile(profile).valid)

    def test_request_options_are_clamped(self):
        class Config:
            request_timeout_seconds = 1
            request_max_completion_tokens = 1
            request_temperature = 99
            request_retry_attempts = 99
            request_retry_backoff_seconds = -2

        options = providers.request_options_from_config(Config())
        self.assertEqual(options.timeout_seconds, 10)
        self.assertEqual(options.max_completion_tokens, 128)
        self.assertEqual(options.temperature, 2.0)
        self.assertEqual(options.retry_attempts, 5)
        self.assertEqual(options.retry_backoff_seconds, 0.0)


if __name__ == "__main__":
    unittest.main()
