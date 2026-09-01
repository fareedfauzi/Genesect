# AI assistant tutorials

All features in this guide are available under **right-click > PseudoNote > AI Assistant**. Configure a provider first and wait for IDA auto-analysis before requesting function-level analysis.

## Chat About This Function

1. Place the cursor in a function and open **Chat About This Function**.
2. Ask a question or double-click a tool in the sidebar, such as **Show pseudocode**, **Show assembly**, **Explain function**, or **Suggest function name**.
3. The AI can call read-only IDA tools automatically. Turn on **Enable IDA changes** only when you want reviewed rename, type, or comment operations.
4. Use **Context Preview** to inspect supplied evidence and **Export Log** to save the conversation.

Be explicit about the desired representation: “show actual disassembly” invokes the disassembly tool, while “show pseudocode” invokes Hex-Rays decompilation.

## Chat About a Function Chain

1. Open the command on an entry function. Use the searchable Entry dropdown to switch to any IDB function by name or address, or click **Current Func** to follow IDA's cursor.
2. Set graph depth and maximum functions, then click **Build Function Graph**.
3. Select the functions shown in the left sidebar.
4. Ask a question spanning the selected callers and callees.

Use a small graph first. Large selections consume more context and can obscure the relationships that matter.

## Function Chain Summarizer

1. Select the entry function from the searchable dropdown, then set maximum depth and maximum function count. **Load Current Function** returns to the function under IDA's cursor.
2. Click **Load Current Function** to build the bounded graph and inspect loaded functions in the sidebar.
3. Click **Start Summarizer**. The Activity panel reports mapping and reduction progress.
4. Review **Summarizer Report** and **Execution Log**, then export Markdown if needed.

This workflow is optimized for a structured overview; use Function Chain Chat for follow-up conversation.

## Autonomous Investigation

1. Open **Autonomous Investigation** on a relevant entry function.
2. Enter a mission such as “find C2 configuration and trace how it is used,” or click **Start Investigation** for the default malware-analysis mission.
3. Follow tool observations in Activity. Use the steering box to redirect the agent or focus on an address.
4. Use **Stop** if the investigation is no longer productive.
5. Keep **Enable IDA changes** disabled for read-only analysis; enable it only when you want the agent to propose reviewed changes.
6. Open **Audit Log** or export the session to inspect every tool call and result.

The agent should cite addresses and distinguish evidence from inference. A final report claiming tool limitations despite already collected evidence should be treated as incomplete and rerun with a narrower mission.

## Bulk Function Renamer

1. Load candidate functions by naming pattern, entry points, exports, high cross-reference count, wrappers, or the current function tree.
2. Filter and select rows, then click **Analyze Selected Function**.
3. Review the suggested name, confidence score, reason, and status.
4. Select acceptable proposals and click **Apply Renames**.
5. Use **Undo Renames** or Change History if a result needs rollback.

No rename prefix is added unless you explicitly configure one. Prefer high-confidence behavioral names over assumptions about malware intent.

## Bulk Variable Renamer

1. Load functions and select the rows to process.
2. Click **Start Variable Rename**.
3. Inspect per-function suggestions and blocked/error states.
4. Click **Apply Suggestions**, review the variable proposal dialog, and apply only valid rows.
5. Export CSV when you need an external review record.

Local-variable renaming requires successful Hex-Rays decompilation. Failed functions may need prototype or stack repair first.

## Bulk Function Analysis

1. Load and select candidate functions.
2. Start analysis and monitor queue, worker, and request status.
3. Review classifications, tags, summaries, and evidence rather than relying only on the label.
4. Retry failed rows after correcting provider, timeout, or decompilation issues.

Use filters and bounded batches for large IDBs. A zero cooldown removes the configured delay, but it cannot override provider quotas.

## Deep Analyzer with Report

1. Choose any IDB entry function from the searchable dropdown, or use **Load Current Function**, then configure graph limits in Settings.
2. Decide whether reviewed local/global variable renaming is allowed.
3. Click **Start Analysis** and monitor discovered nodes, stages, confidence, and logs.
4. Inspect Call Graph and Mermaid Flow views while analysis progresses.
5. Open the generated HTML report and verify important claims at the cited addresses.

Deep Analyzer is intended for recursive evidence collection and reporting. Use Bulk Function Analysis when you only need scalable per-function classification.

## Suggest Function Name — Code Context

1. Place the cursor inside the target function.
2. Run **Suggest Function Name (Code Context)**.
3. Review the proposed name and reasoning.
4. Accept or edit it before applying.

This mode emphasizes observed behavior and is appropriate for ordinary libraries and application logic.

## Suggest Function Name — Malware Context

Follow the same steps as Code Context, but use **Malware Context** when capability-oriented naming is useful. Verify intent words such as `inject`, `steal`, or `persist` against direct evidence before applying them.

## Suggest Variable Name

1. Open the target function in pseudocode.
2. Run **Suggest Variable Name**.
3. Review the current-to-proposed mapping.
4. Uncheck weak proposals and click **Apply Selected**.

The progress overlay closes when the review dialog is ready; the review itself is not an active AI request.

## Suggest Function Prototype

1. Open pseudocode for the function.
2. Run **Suggest Function Prototype**.
3. Compare the proposed return type, calling convention, and arguments against callers and stack use.
4. Apply only after review; incorrect prototypes can damage decompilation quality.

## Infer / Edit Structure

1. Open a function that accesses repeated offsets through a pointer.
2. Run **Infer / Edit Structure**.
3. Review inferred fields, sizes, offsets, and types.
4. Correct overlaps or uncertain fields, then apply the reviewed structure.

For broader cross-function layout recovery, use **Structure Recovery Explorer**.

## Generate Pseudocode Comments

1. Open the target Hex-Rays view.
2. Run **Generate Pseudocode Comments**.
3. Review generated explanations at their target locations.
4. Save the IDB after verifying comments do not overstate behavior.

Use **Remove Pseudocode Comments...** to preview and remove generated comments from the current scope.

## Generate Disassembly Comments

1. Place the cursor in the function's assembly view.
2. Run **Generate Disassembly Comments**.
3. Review the proposed section/instruction comments and apply them.

Use **Remove Disassembly Comments...** to delete comments with explicit confirmation.

## Analyze Selected Bytes / Shellcode

1. Select a bounded byte range in disassembly.
2. Run **Analyze Selected Bytes / Shellcode**.
3. Confirm or select the architecture.
4. Review execution structure, transformations, capability evidence, and assumptions.

The feature analyzes bytes statically; it does not guarantee safe execution or complete emulation.
