# Baseline Known Issues

This file records defects inherited from the original baseline. Entries are resolved in the phase that owns the affected subsystem.

## Resolved during the Extended implementation

- `report_generator.py` has an invalid escape sequence in one regular-expression replacement string and emits a `SyntaxWarning` during compilation.
- Several modules contain broad `except` blocks that suppress useful failure context.
- AI callbacks do not consistently carry request identities, so stale responses may update a newly selected function.
- Bulk-analysis modules duplicate queue, model, table, retry, and persistence logic.
- Some background workers mix IDA API access with worker-thread execution and require a UI-thread safety audit.
- Plugin action registration and cleanup are manually duplicated and can drift apart.
- Configuration and provider concerns are tightly coupled to UI behavior.

The report replacement warning, stale request ownership, provider lifecycle, bulk state duplication, configuration separation and migration path have been addressed in the Extended implementation.

## Validation required inside IDA

- Plugin unload/reload hook lifetime.
- Operation cancellation under streaming providers.
- Hex-Rays refresh behavior after partial rename failures.
- Deep Analyzer resume behavior after interruption or incomplete artifacts.
- Layout behavior under high-DPI scaling and different IDA themes.
