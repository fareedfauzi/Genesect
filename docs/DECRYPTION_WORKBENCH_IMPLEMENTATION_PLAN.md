# PseudoNote String, Data, and Constant Decryption Workbench

## 1. Objective

Build a standalone **Decryption Workbench** inspired by HRTNG's string/data/constant workflow, with two complementary engines:

1. **Known Algorithms** — deterministic, offline transformations that do not invoke an AI provider.
2. **AI Analyze Algorithm** — evidence-driven algorithm recognition and generation of a reviewable decryption program.

The user selects a string, static data range, global object, or immediate constant in IDA View or Hex-Rays pseudocode and opens:

```text
PseudoNote > Decryption Workbench
```

The workbench captures the selected source, proposes or accepts a decoding method, previews the output, and lets the user explicitly choose:

- Add a comment only.
- Patch mapped source bytes when patching is structurally safe.
- Copy/export the result or generated script without changing the IDB.

No AI result or script may modify the IDB automatically.

---

## 2. Design principles

- **Selection-first:** operate on the exact user-selected object or range.
- **Deterministic first:** known algorithms run locally without AI.
- **AI is a proposal engine:** AI identifies a likely routine and produces a candidate transformation; host code validates and executes it.
- **Never run unrestricted AI code inside IDA:** do not call raw `exec()` with normal builtins in the IDA process.
- **Preview before mutation:** always show original bytes, output bytes/text, lengths, algorithm, parameters, and confidence before enabling Apply.
- **Comment and patch are separate actions:** users may document a result without altering bytes.
- **No silent resizing:** patching is exact-length by default and cannot overwrite adjacent items.
- **Preserve analyst work:** never replace unrelated comments or names.
- **Audit every operation:** retain source provenance, analysis evidence, script/spec hash, output hash, and apply outcome.
- **IDA compatibility:** support IDA 8.3 and 9.3 through existing compatibility helpers and PySide abstractions.

---

## 3. HRTNG behavior retained and extended

Retain the useful parts of HRTNG's model:

- Context actions for strings, data, and immediate constants.
- Item-size hints for byte, word, dword, and qword operations.
- Count and selected-range inference.
- Keys and IVs entered as numeric values, IDB addresses/names, quoted strings, or hex strings.
- Local transformations such as rotate/add/subtract/XOR/multiply, repeating-key XOR, substitution, RC4, TEA/XTEA, AES, DES, Salsa/ChaCha families where dependencies are available.
- Output as both hex and decoded text.
- Explicit choice between patching and commenting.

Extend it with:

- AI-based identification from pseudocode, disassembly, constants, APIs, loops, and nearby call relationships.
- Candidate ranking and deterministic output-quality scoring.
- Editable but validated Python script generation.
- Declarative transformation specifications for common algorithms.
- Multiple output candidates and encodings.
- Patch preview, verification, undo metadata, and audit export.

Reference behavior:

- HRTNG documentation: https://github.com/KasperskyLab/hrtng/blob/master/doc/decr.md
- HRTNG implementation: https://github.com/KasperskyLab/hrtng/blob/master/src/decr.cpp

The implementation must be original Python code and should not copy GPL source into PseudoNote unless the project intentionally adopts compatible licensing.

---

## 4. User workflows

### 4.1 Pseudocode string/global selection

1. User clicks or selects a string literal, global byte array, or global object.
2. Right-click **PseudoNote > Decryption Workbench**.
3. Host resolves the Hex-Rays expression to an address, inferred type, item width, and bounded length.
4. Workbench opens with source bytes and surrounding function evidence.
5. User chooses **Analyze Algorithm (AI)** or **Known Algorithms**.
6. Workbench displays candidate output and a short explanation.
7. User chooses Comment, Patch, Copy, Export Script, or Cancel.

### 4.2 Pseudocode immediate constant

1. User selects a `cot_num` expression.
2. Host captures the integer value, signedness, width, expression address, and containing function.
3. Workbench treats it as an in-memory byte representation for analysis.
4. Result may be added as a Hex-Rays expression comment.
5. **Patch is disabled by default** because a ctree number does not reliably identify an encoded instruction operand.
6. A later safe operand-patching phase may enable patching only when the exact instruction operand and encoding are verified.

### 4.3 Disassembly/static data selection

1. If a range is selected, its exact start/end addresses define the source.
2. Without a range, infer the current item bounds, string length, array length, or typed object size.
3. Read only mapped bytes and cap extraction at the configured maximum.
4. Exact-length patching is available after preview and confirmation.

### 4.4 Stack/local variable selection

1. Capture lvar name, type, size, ctree expression, and relevant assignment/use statements.
2. If no static bytes back the variable, mark the target **Synthetic / comment-only**.
3. AI may reconstruct a buffer from constant assignments when evidence is complete.
4. Never pretend runtime data exists in the IDB.
5. Result can be copied, exported, or attached as a local-variable/expression comment.

---

## 5. Source model and provenance

Create `pseudonote_extended/decryption_models.py` with typed dataclasses.

### `DecryptionTarget`

```python
@dataclass
class DecryptionTarget:
    source_kind: str              # string, data, global, immediate, local, selection
    view_kind: str                # pseudocode, disassembly, hex
    start_ea: int | None
    end_ea: int | None
    function_ea: int | None
    expression_ea: int | None
    item_width: int               # 1, 2, 4, or 8
    count: int
    raw_bytes: bytes
    original_value: int | None
    signed: bool | None
    byte_order: str               # little or big
    ida_type: str
    display_name: str
    patchability: str             # exact, comment_only, unsupported
    patch_reason: str
    selection_text: str
    provenance: list[str]
```

### `DecryptionParameters`

- Algorithm identifier and mode.
- Direction: decrypt/decode or inverse transform.
- Item width and byte order.
- Key bytes and key provenance.
- IV/nonce/counter and provenance.
- Round count, delta, rotation, arithmetic mask.
- Input offset/count and termination rule.
- Padding policy.
- Expected output encoding.

### `DecryptionCandidate`

- Engine: known or AI.
- Algorithm family and exact variant.
- Parameters.
- Generated script and script hash.
- Evidence list.
- Confidence.
- Output bytes.
- Decoded representations.
- Quality score and warnings.
- Execution duration and error.

### `DecryptionAuditRecord`

- Timestamp and target provenance.
- Original-byte SHA-256.
- Engine, algorithm, parameters, prompt/model metadata when applicable.
- Script/spec SHA-256.
- Output SHA-256 and length.
- Comment/patch/copy/export decision.
- Patch verification and original bytes needed for undo.
- Failure reason.

Do not render these models as raw JSON in the normal UI. JSON is acceptable only in explicit audit export.

---

## 6. Context extraction

Create `pseudonote_extended/decryption_extractor.py`.

### 6.1 Shared extraction rules

- Run all IDA reads through the main-thread read helper.
- Canonicalize a clicked address to the containing item where appropriate.
- Verify every byte is mapped before reading.
- Default maximum source size: 1 MiB; hard maximum: 16 MiB.
- Reject empty, inverted, or overflowed ranges.
- Preserve the exact selected range instead of silently expanding it.
- Record how length, width, and address were inferred.

### 6.2 Disassembly/hex views

Priority:

1. Explicit range selection.
2. Defined string literal length, including character width and terminator metadata.
3. Typed array/object size.
4. Current item bounds.
5. User-entered length when inference is ambiguous.

Use compatibility wrappers around `read_range_selection`, widget type detection, item bounds, string APIs, and mapped-byte reads.

### 6.3 Hex-Rays pseudocode

Resolve:

- `cot_obj`: global/static object address and type size.
- `cot_num`: value, width, signedness, and citem/expression locator.
- `cot_var`: lvar identity/type plus bounded def-use context.
- String helper/object expressions that resolve through xrefs or address constants.
- Selected ctree text when a single hover item is insufficient.

Store a stable Hex-Rays comment locator rather than retaining a transient SWIG object after the view refreshes.

### 6.4 Ambiguity dialog

If inference produces more than one plausible target, show a small chooser with:

- Address/range.
- Source type.
- Inferred length and item width.
- Preview.
- Reason for the inference.

Never guess between a pointer value and pointed-to data without showing the distinction.

---

## 7. Known-algorithm engine

Create `pseudonote_extended/decryption_algorithms.py` with a registry:

```python
AlgorithmDefinition(
    id, title, category, parameter_schema, availability,
    block_size, key_sizes, iv_sizes, transform
)
```

### 7.1 Always-available transforms

- ROL/ROR by constant or per-item key.
- ADD/SUB in both common directions with width masking.
- XOR constant.
- Repeating-key XOR.
- MUL and modular inverse when valid.
- NOT/NEG.
- Nibble swap and byte swap.
- Endian conversion by item width.
- Simple substitution table and inverse table.
- RC4.
- TEA/XTEA and common delta/round variants.
- Base16/Base32/Base64/Base64URL.
- URL percent, HTML entity, JSON/Unicode escape decoding.
- UTF-8/UTF-16LE/UTF-16BE/UTF-32 conversion.
- zlib/gzip/bz2/lzma decompression.
- Single-byte XOR and repeating-XOR candidate search.

### 7.2 Optional cryptographic providers

Expose AES, DES/3DES, ChaCha20, Salsa20, and other block/stream ciphers only when a vetted installed provider is available. The UI must show **Unavailable: dependency missing** rather than silently using AI or an unreviewed implementation.

### 7.3 Parameter parsing

Support:

- Decimal, hexadecimal, octal, and binary integers.
- IDB name or address, with an explicit byte length.
- Quoted UTF-8/UTF-16 strings.
- Whitespace-separated or compact hex bytes.
- Key/IV extraction from a selected second IDB object.

Every parser returns bytes plus provenance and validation errors. Never interpret ambiguous plain text as both an IDB symbol and literal without asking.

### 7.4 Candidate search

For cheap algorithms, provide **Try Common Rules**:

- Brute-force single-byte XOR.
- Common ADD/SUB/ROL/ROR widths.
- Repeating-key XOR when a likely key is selected or found nearby.
- Layered common encodings with a strict depth and candidate limit.

Rank using printable ratio, Unicode validity, language/identifier likelihood, entropy change, known file signatures, URL/path/registry patterns, and null-termination consistency. Label scores as heuristics, not proof.

---

## 8. AI algorithm analysis

Create `pseudonote_extended/decryption_agent.py`.

### 8.1 Evidence bundle

Send only bounded, relevant context:

- Target provenance and full source length.
- A bounded byte sample plus SHA-256; include complete bytes only within provider context limits.
- Decompiled containing function, paginated when required.
- Bounded disassembly only for decompiler ambiguity.
- Direct data xrefs and relevant caller/callee names.
- Nearby constants, loops, shifts/rotates, tables, imports, and crypto/API knowledge from `pseudonote_extended/API` when useful.
- Known-algorithm trial results and quality scores.

Do not send unrelated whole-IDB content.

### 8.2 Structured AI response

Require one JSON object internally:

```json
{
  "algorithm": "xor_repeating",
  "variant": "byte-wise repeating key",
  "parameters": {
    "key_hex": "2A 19 7F",
    "item_width": 1,
    "byte_order": "little"
  },
  "confidence": 86,
  "evidence": [
    "0x140012340 loads key byte by index modulo 3",
    "0x14001235A XORs each input byte"
  ],
  "script": "def decrypt(data: bytes) -> bytes:\n    ...",
  "requires_more_context": false,
  "warnings": []
}
```

Host validation must confirm:

- Algorithm is known or explicitly marked custom.
- Parameters have correct types and bounded sizes.
- Evidence addresses exist in supplied context.
- Script defines exactly the required entry point.
- Confidence is numeric and bounded.
- No unsupported claim is presented as fact.

### 8.3 Two-stage AI workflow

1. **Identify:** classify algorithm/variant, locate key/IV/counter, cite evidence, request a specific missing context if needed.
2. **Generate:** prefer a host-known algorithm specification. Generate Python only for a genuinely custom transformation.

This avoids asking the model to rewrite standard RC4/AES/TEA implementations and reduces hallucinated scripts.

### 8.4 Context-limit handling

- Estimate request size before submission.
- Use byte samples, function slices, and relevant loop blocks.
- Analyze an identified helper routine separately when required.
- Return provider/model context errors to IDA Output and the workbench error panel.
- Never silently truncate key evidence and claim successful analysis.

---

## 9. Script contract and safe execution

### 9.1 Required interface

```python
def decrypt(data: bytes) -> bytes:
    """Return transformed bytes without side effects."""
```

Optional structured parameters should be embedded as immutable byte/int literals or passed through a host wrapper. The result must be `bytes` or `bytearray` and is converted to immutable bytes.

### 9.2 Static validation

Create `pseudonote_extended/decryption_sandbox.py` and parse scripts with `ast`.

Reject:

- Imports unless explicitly allowlisted for an isolated runner.
- Attribute access to dunder names.
- `exec`, `eval`, `compile`, `open`, `input`, `globals`, `locals`, `vars`, `getattr`, `setattr`, `delattr`, or `__import__`.
- File, process, shell, socket, environment, registry, ctypes, marshal, pickle, reflection, or IDA APIs.
- Global/nonlocal statements.
- Infinite unbounded loops.
- Excessive literals, source length, nesting, or output allocation.

Do not treat a reduced `__builtins__` dictionary as a complete sandbox by itself.

### 9.3 Execution isolation

Preferred order:

1. Execute known/declarative algorithms entirely in trusted host code.
2. For custom scripts, execute in a separate helper process using the same bundled Python runtime.
3. Pass input/output through bounded binary files or length-prefixed stdin/stdout in a temporary directory.
4. Apply a strict timeout, input/output size limit, clean environment, no inherited handles, and no network-dependent behavior.
5. Terminate the helper on timeout or protocol violation.
6. Never provide the helper with IDB paths, API keys, provider configuration, or write access to plugin files.

On platforms where strong isolation cannot be established, show a warning and require explicit **Run Reviewed Script** confirmation. The default remains deterministic specs only.

### 9.4 Reproducibility

Display and export:

- Script text.
- Script SHA-256.
- Input SHA-256.
- Output SHA-256.
- Runtime and timeout.
- Exact parameters.

Re-running an unchanged script on unchanged input should produce the same output before Apply is enabled.

---

## 10. Workbench UI

Create a standalone modeless window using the same theme/lifecycle pattern as the existing standalone bulk tools.

### 10.1 Header

- Title: **Decryption Workbench**.
- Source badge: String, Data, Constant, Global, Local, or Selection.
- Address/range and containing function.
- Patchability badge.
- Buttons: Refresh Source, Audit, Export Session.

### 10.2 Source card

- Hex/ASCII preview with offsets.
- Text interpretations: ASCII, UTF-8, UTF-16LE/BE.
- Length, item width, type, entropy, and source inference.
- Editable bounded offset/count fields.
- **Use current IDB bytes** refresh control.

### 10.3 Engine tabs

#### Known Algorithms

- Category and algorithm comboboxes.
- Dynamic parameter form from the registry schema.
- Key/IV source pickers.
- Try Common Rules.
- Run button.

#### AI Analyze Algorithm

- Analyze button.
- Context Preview.
- Identified algorithm, confidence, and short evidence list.
- Parameters table.
- Generated script editor with Python highlighting.
- Validate Script and Run Reviewed Script buttons.
- Provider errors shown as actionable messages.

### 10.4 Results card

- Candidate selector when more than one result exists.
- Side-by-side original and output hex views.
- Decoded text views.
- Input/output lengths and hashes.
- Quality score with reasons.
- Warnings for padding, truncation, non-printable output, or block alignment.
- Short explanation: algorithm, key source, and why the result is plausible.

### 10.5 Actions

- **Add Comment...**
- **Patch Data...** only when patchability is `exact`.
- Copy Text.
- Copy Bytes.
- Export Script.
- Export Result.
- Close.

Disable comment/patch until a result was successfully executed and remains current for the unchanged input.

---

## 11. Comment application

Create `pseudonote_extended/decryption_apply.py`.

Default comment format:

```text
[PseudoNote Decryption] RC4, key from key_table: "decoded text"
```

Rules:

- Show an editable comment preview.
- Escape/control the maximum length; do not paste megabytes into a comment.
- Preserve unrelated analyst comments.
- Replace only a prior `[PseudoNote Decryption]` managed line for the same target/result slot.
- For disassembly/global data, use an appropriate repeatable IDA comment.
- For Hex-Rays expressions/constants, use stable citem/treeloc user comments and save/refresh the cfunc.
- For local variables, attach to the selected expression or relevant assignment, not an invalid raw address.
- Verify the comment after applying and record the outcome.

---

## 12. Patch application and safety

Patching is a distinct, confirmed IDB mutation.

### 12.1 Preconditions

- Target has a mapped static address and exact original range.
- Current IDB bytes still match the captured original bytes.
- Output is non-empty and within configured limits.
- Default output length equals source length.
- No relocation/fixup or instruction operand is overwritten unknowingly.
- User sees original/output bytes and confirms the exact range.

### 12.2 Length policy

- **Exact length:** default and safest.
- **Shorter output:** user may explicitly choose zero padding, preserve trailing original bytes, or cancel.
- **Longer output:** disabled by default. Never overwrite adjacent items. Future support requires an explicitly selected larger destination range.
- String terminators are included only through an explicit option and only if they fit inside the selected range.

### 12.3 Transaction

1. Re-read and verify original bytes.
2. Save original bytes and metadata in the audit/session record.
3. Patch with IDA patch APIs on the main thread.
4. Read back and verify every output byte.
5. Refresh affected views and invalidate Hex-Rays cache where relevant.
6. If verification fails, restore original bytes and report the failure.
7. Offer **Restore Original Bytes** for the current workbench session.

Immediate constants remain comment-only until a dedicated instruction-operand patcher proves the encoding and preserves instruction size/fixups.

---

## 13. Registration and menus

Files:

- `pseudonote_extended/plugin.py`
- `pseudonote_extended/handlers.py`
- `pseudonote_extended/ui/context_menu.py`
- `pseudonote_extended/ui/icons.py`

Action:

```text
ID: pseudonote_extended:decryption_workbench
Label: Decryption Workbench
Tooltip: Analyze and decrypt selected strings, data, or constants
```

Placement:

```text
PseudoNote
└── Program Structure and Malware Analysis
    └── Decryption Workbench
```

Attach contextually in IDA View, Hex View, and Pseudocode. Enable only when extraction finds a supported target. Avoid overriding IDA's standard `D`/`Shift-D` behavior; use no shortcut initially or a conflict-checked configurable shortcut.

Use a clean colorful Font-Awesome-inspired icon consistent with the current PseudoNote icon family.

---

## 14. State, audit, and export

- Workbench session state stays in memory unless explicitly saved.
- Store recent recipes without raw sensitive plaintext only if the user opts in.
- Audit Log contains internal target metadata, AI envelopes, tool decisions, validation failures, scripts, hashes, and apply outcomes.
- Export Session produces a human-readable Markdown report plus optional `.py` script and binary result.
- Normal UI never displays raw model JSON.
- Do not write API keys, proxy credentials, or complete provider configuration to audit files.

---

## 15. Error handling

Use message boxes for actionable selection/apply errors and a workbench diagnostics panel for detailed failures.

Cover:

- No valid selection.
- Unmapped/partially mapped range.
- Ambiguous pointer versus pointed-to data.
- Unsupported stack/runtime-only value.
- Invalid key/IV syntax or size.
- Block-size/padding mismatch.
- Missing optional crypto dependency.
- AI context overflow/provider error.
- Invalid or unsafe generated script.
- Script timeout, crash, or oversized output.
- Source bytes changed before patch.
- Comment locator became stale after decompilation refresh.
- Patch verification/rollback failure.

Return provider errors to IDA Output so the user can distinguish model errors from plugin errors.

---

## 16. Testing and acceptance criteria

### Extraction tests

- Pseudocode string/global/constant/local selections.
- Disassembly range, string, typed array, and current item.
- Wide strings, big/little endian values, zero-length and unmapped ranges.
- IDA 8.3 and 9.3 compatibility paths.

### Algorithm tests

- Golden vectors for every known transform.
- Width masking and signed/unsigned behavior.
- RC4, TEA/XTEA, optional provider algorithms.
- Encoding/decompression success and malformed inputs.
- Key/IV parser formats and IDB references.
- Candidate ranking limits and deterministic ordering.

### AI tests

- Structured-response validation.
- Unsupported evidence rejection.
- Known algorithm routed to trusted host implementation.
- Custom script validation and isolation.
- Context overflow and provider failure reporting.
- Malicious generated scripts attempting filesystem, imports, reflection, process, network, or IDA access.

### Apply tests

- Comment preservation/replacement.
- Exact patch and read-back verification.
- Changed-source race detection.
- Short/long output policies.
- Rollback after partial failure.
- Constants and synthetic locals remain comment-only.

### UI/lifecycle tests

- Standalone window ownership and taskbar behavior.
- No always-on-top leakage outside IDA.
- Reopening/closing without stale Qt objects.
- Theme, scaling, filtering, copy/export, and large-buffer responsiveness.

### Acceptance criteria

- Correct target bytes and provenance are shown before analysis.
- Known algorithms never require AI.
- AI protocol output is never shown as normal chat/UI content.
- No unrestricted AI-generated code runs in the IDA process.
- A result is reproducible before comment/patch is enabled.
- Patches never exceed the confirmed range.
- Every write is confirmed, verified, auditable, and recoverable.
- Existing analyst comments are preserved.
- Failures are actionable and never presented as successful decryption.

---

## 17. Implementation sequence

### Phase 1 — Safe deterministic foundation

1. Define models, extraction contracts, limits, and provenance.
2. Implement disassembly/global/string/constant extraction.
3. Build standalone themed workbench and source/result previews.
4. Implement core transforms, parsers, golden-vector tests, and candidate scoring.
5. Implement comment-only application and audit.

### Phase 2 — Safe patch workflow

6. Add exact-length patch preview, confirmation, verification, rollback, and restore.
7. Add wide-string and typed-array policies.
8. Add lifecycle and IDA 8.3/9.3 integration tests.

### Phase 3 — AI identification

9. Build bounded context extraction and Context Preview.
10. Implement structured algorithm-identification response and evidence validation.
11. Route known AI identifications to trusted local algorithms.
12. Add provider/context error reporting and audit.

### Phase 4 — Custom script generation

13. Add AST validation and isolated helper runner.
14. Add editable script review, reproducibility checks, timeout/output limits, and hostile-script tests.
15. Add export script/result/session functions.

### Phase 5 — Advanced coverage

16. Add def-use reconstruction for statically initialized local buffers.
17. Add layered decoding search and key/table discovery.
18. Add optional vetted crypto providers.
19. Consider safe instruction-immediate patching as a separate feature only after encoding/fixup tests.

Do not begin Phase 4 by adding raw `exec()` to the IDA process. The deterministic engine, extraction accuracy, preview, and safe apply transaction are prerequisites.
