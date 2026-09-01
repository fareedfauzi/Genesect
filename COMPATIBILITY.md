# Compatibility Policy

PseudoNote Extended currently targets:

- IDA Pro 8.3 and newer, with validation planned for IDA 8.3, 8.4, and 9.x.
- Python 3.9 and newer.
- Qt bindings exposed by the IDA runtime through the compatibility layer.
- Hex-Rays for decompiler-backed features. Utilities that do not need Hex-Rays should remain available without it.

Optional AI provider SDKs fail gracefully when absent. Provider-specific compatibility is validated in Settings before requests are enabled.

Release validation targets IDA 8.3, 8.4 and IDA 9.x with Python 3.9–3.12. Hex-Rays-backed actions are unavailable without a decompiler; notes, settings, Hex Viewer, xrefs, vftables and other non-decompiler utilities remain loadable.
