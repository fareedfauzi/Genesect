import ast
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _load_budget_function():
    source = (ROOT / "pseudonote_extended" / "report_generator.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    node = next(
        item for item in tree.body
        if isinstance(item, ast.FunctionDef) and item.name == "_deep_request_budget"
    )
    module = ast.Module(body=[node], type_ignores=[])
    namespace = {}
    exec(compile(module, "report_generator.py", "exec"), namespace)
    return namespace["_deep_request_budget"]


def test_deep_request_budget_compacts_oversized_local_prompt():
    budget = _load_budget_function()
    prompt = "HEADER\n" + ("decompiled_code();\n" * 3000) + "\nJSON_SCHEMA_TAIL"
    compacted, output_tokens, changed = budget(
        {"context_window_tokens": 4096, "max_completion_tokens": 8192},
        prompt,
        "system instructions",
        10000,
    )

    assert changed is True
    assert output_tokens == 1024
    assert compacted.startswith("HEADER")
    assert compacted.endswith("JSON_SCHEMA_TAIL")
    assert "context compacted" in compacted
    assert len(compacted) < 7000


def test_deep_request_budget_leaves_small_prompt_unchanged():
    budget = _load_budget_function()
    prompt = "Analyze this function and return JSON."
    result, output_tokens, changed = budget(
        {"context_window_tokens": 4096, "max_completion_tokens": 2048},
        prompt,
        "system",
        600,
    )

    assert result == prompt
    assert output_tokens == 600
    assert changed is False


def test_local_deep_analyzer_has_safe_automatic_context_window():
    source = (ROOT / "pseudonote_extended" / "deep_analyzer.py").read_text(encoding="utf-8")
    assert '4096 if cfg["provider"] in ("lmstudio", "ollama") else 32768' in source
    assert "effective_batch = 1 if context_window <= 4096 else configured_batch" in source


def test_context_overflow_is_not_retried():
    renamer = (ROOT / "pseudonote_extended" / "renamer.py").read_text(encoding="utf-8")
    client = (ROOT / "pseudonote_extended" / "ai_client.py").read_text(encoding="utf-8")
    for marker in ("trying to keep the first", "context_length_exceeded", "prompt is too long"):
        assert marker in renamer
        assert marker in client
