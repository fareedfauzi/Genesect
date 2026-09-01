"""Provider profiles, validation, and normalized request options."""

from dataclasses import dataclass, field
from urllib.parse import urlparse


PROVIDER_NAMES = (
    "OpenAI", "Anthropic", "DeepSeek", "Gemini", "Ollama",
    "LMStudio", "OpenAICompatible",
)

ALIASES = {
    "openai": "OpenAI",
    "anthropic": "Anthropic",
    "deepseek": "DeepSeek",
    "gemini": "Gemini",
    "ollama": "Ollama",
    "lmstudio": "LMStudio",
    "custom": "OpenAICompatible",
    "openaicompatible": "OpenAICompatible",
}

DEFAULTS = {
    "OpenAI": {"key": "", "url": "https://api.openai.com/v1", "model": "gpt-4o"},
    "Anthropic": {"key": "", "url": "https://api.anthropic.com", "model": "claude-sonnet-4-5"},
    "DeepSeek": {"key": "", "url": "https://api.deepseek.com/v1", "model": "deepseek-chat"},
    "Gemini": {"key": "", "url": "", "model": "gemini-2.5-pro"},
    "Ollama": {"key": "", "url": "http://localhost:11434/v1", "model": "llama3"},
    "LMStudio": {"key": "lm-studio", "url": "http://localhost:1234/v1", "model": "local-model"},
    "OpenAICompatible": {"key": "", "url": "", "model": ""},
}

KEY_REQUIRED = {"OpenAI", "Anthropic", "DeepSeek", "Gemini"}
URL_REQUIRED = {"OpenAI", "Anthropic", "DeepSeek", "Ollama", "LMStudio", "OpenAICompatible"}


def normalize_provider(value):
    return ALIASES.get(str(value or "").replace("-", "").replace("_", "").lower(), "OpenAI")


@dataclass(frozen=True)
class ValidationResult:
    valid: bool
    errors: tuple = ()
    warnings: tuple = ()


@dataclass(frozen=True)
class ProviderProfile:
    name: str
    key: str
    url: str
    model: str

    @property
    def client_name(self):
        return "custom" if self.name == "OpenAICompatible" else self.name.lower()


@dataclass(frozen=True)
class RequestOptions:
    timeout_seconds: int = 120
    max_completion_tokens: int = 8192
    temperature: float = 0.2
    retry_attempts: int = 2
    retry_backoff_seconds: float = 1.5


def validate_profile(profile, require_api_key=True):
    errors = []
    warnings = []
    if require_api_key and profile.name in KEY_REQUIRED and not profile.key.strip():
        errors.append("API key is required for this provider.")
    elif profile.name in KEY_REQUIRED and not profile.key.strip():
        warnings.append("API key is empty; settings can be saved, but requests may fail until one is configured.")
    if not profile.model.strip():
        errors.append("Model name is required.")
    if profile.name in URL_REQUIRED:
        parsed = urlparse(profile.url.strip())
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            errors.append("Base URL must be a complete http:// or https:// URL.")
        elif parsed.scheme == "http" and profile.name not in {"Ollama", "LMStudio"}:
            warnings.append("This provider uses an unencrypted HTTP connection.")
    return ValidationResult(not errors, tuple(errors), tuple(warnings))


def profile_from_config(config):
    name = normalize_provider(getattr(config, "active_provider", "OpenAI"))
    mapping = {
        "OpenAI": ("openai_key", "openai_url", "openai_model"),
        "Anthropic": ("anthropic_key", "anthropic_url", "anthropic_model"),
        "DeepSeek": ("deepseek_key", "deepseek_url", "deepseek_model"),
        "Gemini": ("gemini_key", None, "gemini_model"),
        "Ollama": (None, "ollama_host", "ollama_model"),
        "LMStudio": ("lmstudio_key", "lmstudio_url", "lmstudio_model"),
        "OpenAICompatible": ("custom_key", "custom_url", "custom_model"),
    }
    key_attr, url_attr, model_attr = mapping[name]
    return ProviderProfile(
        name,
        getattr(config, key_attr, "") if key_attr else "",
        getattr(config, url_attr, "") if url_attr else "",
        getattr(config, model_attr, "") or getattr(config, "model", ""),
    )


def request_options_from_config(config):
    return RequestOptions(
        timeout_seconds=max(10, int(getattr(config, "request_timeout_seconds", 120))),
        max_completion_tokens=max(128, int(getattr(config, "request_max_completion_tokens", 8192))),
        temperature=max(0.0, min(2.0, float(getattr(config, "request_temperature", 0.2)))),
        retry_attempts=max(0, min(5, int(getattr(config, "request_retry_attempts", 2)))),
        retry_backoff_seconds=max(0.0, float(getattr(config, "request_retry_backoff_seconds", 1.5))),
    )
