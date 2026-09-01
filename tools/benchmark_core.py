"""Repeatable microbenchmarks for dependency-free release-critical primitives."""

import importlib.util
import pathlib
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


batch = load("benchmark_batch", "pseudonote_extended/batch/state.py")
utility = load("benchmark_utility", "pseudonote_extended/utility_state.py")


def measure(label, callback):
    start = time.perf_counter()
    callback()
    elapsed = (time.perf_counter() - start) * 1000
    print(f"{label}: {elapsed:.2f} ms")


def main():
    items = [batch.BatchItem(str(i), f"function_{i}", context_chars=8000) for i in range(100000)]
    session = batch.BatchSession("benchmark", items, batch_size=10)
    measure("100k-row estimate", lambda: session.estimate())
    measure("100k-row JSON serialization", lambda: session.to_json())
    history = utility.SearchHistory(20)
    measure("100k search-history updates", lambda: [history.add(f"query {i % 50}") for i in range(100000)])


if __name__ == "__main__":
    main()
