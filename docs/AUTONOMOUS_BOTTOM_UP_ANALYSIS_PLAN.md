# Autonomous Bottom-Up Analysis Plan

## Objective

Make Autonomous Analysis perform a complete, resumable, bottom-up investigation of the IDB. When **Enable IDA changes** is active, each analyzed function may receive:

- An evidence-based function name.
- A short function comment explaining its behavior.

Renaming callees before callers gives later analysis better semantic context and improves accuracy.

## User experience principles

Internal structured records, model envelopes, tool arguments, raw JSON, and checkpoint data must not be displayed in the normal UI.

Only show information that helps the analyst understand progress, review changes, or respond to a problem.

### Display during analysis

Show a compact status area containing:

- Current phase, such as `Building call graph`, `Analyzing leaves`, `Analyzing callers`, or `Final validation`.
- Overall coverage: `Analyzed 1,240 / 4,318 functions`.
- Changes: `Renamed 862` and `Commented 858` when IDA changes are enabled.
- Remaining, deferred, and failed counts.
- Current function address and current/final name.
- A short activity message, for example `Analyzing callers after 14 callees were resolved`.
- Pause, Resume, and Stop controls.

Do not continuously print raw pseudocode, tool payloads, JSON responses, or complete evidence records into the chat.

### Display for each successful function

Use one concise activity line only when useful:

```text
0x140012340  sub_140012340 → initialize_network_state
Initializes socket state and registers network callbacks.  Confidence: 88%
```

If the existing name is retained:

```text
0x140012340  initialize_network_state — existing name retained
Initializes socket state and registers network callbacks.
```

The UI may group or collapse these lines for large IDBs. It should not create thousands of chat bubbles.

### Display when attention is required

Show only actionable failures:

- Decompilation and disassembly both failed.
- A rename collided and could not be resolved safely.
- A user comment or manual rename conflicts with a pending change.
- A write partially failed.
- The provider rejected the request or exceeded its context window.
- The safety limit was reached with functions still pending.

Each message should include the affected address, a short reason, and what PseudoNote will do next.

### Display at completion

Show a concise completion summary:

- Total functions.
- Fully analyzed functions.
- Renamed functions.
- Commented functions.
- Existing names retained.
- Failed or unresolved functions.
- High-confidence behavioral findings.
- Important unknowns.
- Link/button to open or export the complete function ledger and audit.

Do not place the internal session snapshot or raw tool audit in the main result. Keep those available through an explicit diagnostic/export action.

## 1. Durable function memory

Extend `AgentSession` with a persistent per-function record keyed by canonical function address. The internal record should retain:

- Original and current function names.
- Suggested name and validation result.
- One-sentence behavioral summary.
- Confidence score.
- Evidence references.
- Internal callees and dependency state.
- Analysis, rename, and comment status.
- Code fingerprint and analysis version.
- Attempt count and last failure.

This data is internal and must not be rendered as raw JSON to the user.

The memory must persist in the IDB checkpoint and must not use the bounded recent-observation ledger. It needs to retain every function in large databases.

## 2. Bottom-up call-graph scheduler

Build the full internal call graph and schedule functions as follows:

1. Analyze leaf functions with no unresolved internal callees.
2. Apply validated names and short comments when changes are enabled.
3. Refresh caller code so new callee names appear in pseudocode.
4. Analyze callers using the completed callee summaries as context.
5. Continue upward toward entry points and root functions.
6. Detect strongly connected components for recursive cycles.
7. Analyze cyclic groups together or select an explicit cycle breaker.
8. Retry deferred callers after their dependencies are resolved.

Queue ownership must remain in the host. The model may not declare coverage complete or silently replace the queue.

## 3. Per-function analysis contract

The model response is parsed internally into:

- Suggested function name.
- Short behavioral comment.
- Confidence.
- Evidence.
- Whether deeper investigation is required.

The normal UI shows only the validated name, short summary, confidence when relevant, and final apply state.

The short comment must:

- Be one sentence.
- Describe observed behavior.
- Avoid unsupported intent or malware claims.
- Avoid generic text such as `This function...`.
- Avoid addresses unless an address is essential to the behavior.
- Be useful as caller context.

## 4. Shared Bulk Function Renamer infrastructure

Extract or reuse the Bulk Function Renamer logic for:

- Fresh decompilation after callee renames.
- Dependency blocking on unresolved `sub_*` callees.
- Context-window budgeting.
- Dynamic batch sizing.
- Oversized-function single analysis.
- Name cleaning and collision handling.
- Meaningless or address-derived name rejection.
- Low-confidence individual rescans.
- Cycle-breaker and final deferred passes.
- Original-name preservation.
- Main-thread IDA write operations.
- Hex-Rays cache invalidation.

Do not duplicate these behaviors in a second incompatible pipeline.

## 5. Atomic rename and comment application

Only perform writes when **Enable IDA changes** is active.

For each validated function:

1. Save the original function name and existing managed comment state.
2. Apply the validated function name.
3. Apply or replace the PseudoNote-managed short function comment.
4. Clear the affected Hex-Rays cache.
5. Verify both writes.
6. Update durable function memory.
7. Checkpoint immediately or after a very small completed batch.

Treat rename and comment as one logical transaction. A partial failure must be recorded and retried or surfaced to the user.

Preserve analyst comments. Use a recognizable managed line such as:

```text
[PseudoNote] Initializes socket state and registers network callbacks.
```

Replace the existing PseudoNote-managed line on reanalysis instead of appending duplicates.

## 6. Callee context for caller analysis

Caller prompts should include bounded, validated callee knowledge:

```text
Known callees:
- initialize_network_state: Initializes socket state and registers network callbacks.
- cleanup_tls_state: Releases thread-local and fiber-local resources.
```

Prefer newly applied semantic names and concise behavior summaries over raw unresolved `sub_*` identifiers.

The context builder must prioritize direct callees, high-confidence summaries, important APIs, strings, data references, and recorded findings while respecting the provider context window.

## 7. Coverage and completion rules

A function is fully analyzed only when it has:

- Function-local evidence.
- Decompiled code or bounded disassembly fallback.
- A validated short behavioral summary.
- A validated naming decision, including an explicit decision to retain a good existing name.
- Verified rename/comment state when changes are enabled.

Do not accept a final report while any function is pending, stale, deferred, partially applied, or awaiting retry.

If a safety limit is reached, stop with an incomplete-coverage message. Do not generate a misleading complete summary.

## 8. Recovery, resume, and invalidation

Checkpoint the queue and per-function memory continuously.

On resume:

- Restore completed, pending, deferred, and failed states.
- Skip functions whose code fingerprint and dependencies are unchanged.
- Reanalyze callers when a callee name or summary changes.
- Detect manual analyst renames or comment edits.
- Never overwrite conflicting manual changes silently.
- Retry failed decompilation using bounded disassembly.
- Preserve all prior function summaries for later caller context.

## 9. Audit and review

Maintain a complete internal function ledger with:

- Address.
- Original and final name.
- Short behavioral summary.
- Confidence.
- Evidence references.
- Rename/comment results.
- Analysis state and failure reason.

Expose it through a dedicated review/export action. The standard chat and progress UI should show only concise, important information.

Every IDA write must remain in the existing tool audit with its evidence and outcome.

## 10. Testing and acceptance criteria

Add automated and manual coverage for:

- Simple leaf-to-root chains.
- Recursive and mutually recursive functions.
- Name collisions.
- Existing analyst comments.
- Existing good function names.
- Decompilation failure and disassembly fallback.
- Low-confidence rescan.
- Oversized functions.
- Stop and resume.
- Manual changes during analysis.
- Read-only mode.
- Changes-enabled mode.
- Partial rename/comment failure.
- Context-window errors.
- Large IDBs with thousands of functions.
- Final-report rejection while coverage is incomplete.

Acceptance requires:

- Every enumerated function has a durable terminal state.
- Callers are analyzed after their resolvable callees.
- Applied names and comments are verified.
- Existing analyst content is preserved.
- Resuming does not lose memory or redo unchanged work.
- The user-facing UI contains no unnecessary raw JSON or tool payloads.

## Implementation sequence

1. Define and migrate durable per-function memory.
2. Extract shared rename validation and apply helpers.
3. Add the call-graph and strongly-connected-component scheduler.
4. Add the structured name/summary analysis contract.
5. Add atomic managed rename/comment application.
6. Add callee-summary context propagation.
7. Add coverage gating and stale-state invalidation.
8. Add compact progress, actionable errors, and completion UI.
9. Add review/export for the complete ledger and diagnostics.
10. Complete regression and large-IDB validation.
