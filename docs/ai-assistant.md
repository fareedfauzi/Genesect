# AI Assistant Workflows

The procedures detailed in this document are accessible via **Right-Click > PseudoNote > AI Assistant**. Proper AI provider configuration and completion of IDA Pro's auto-analysis are prerequisites for executing function-level analysis.

## Core Interface: PseudoNote Pane (`Ctrl+Alt+G`)

The primary dockable panel provides multiple analytical contexts.

*   **Function Details:** Aggregates static metadata directly from the IDB (callers, callees, strings) without invoking external AI requests.
*   **Function Explain:** Generates a comprehensive, plain-English summary of the current function's behavioral intent and algorithmic logic.
*   **Tree Graph:** Synthesizes a text-based, hierarchical control flow graph detailing decision branches, loops, and conditional logic.
*   **Custom Prompt:** Facilitates targeted, ad-hoc querying of the AI model. Contextual inclusions (Pseudocode or Assembly) are configurable via interface toggles.

## Interactive Contextual Analysis

### Function Chat (`Ctrl+Alt+A`)

1. Navigate to the target function and invoke **Chat About This Function**.
2. Formulate a query or utilize the predefined tools (e.g., **Show pseudocode**, **Explain function**, **Suggest function name**).
3. The interface operates in a read-only capacity by default. Enable the **Enable IDA changes** toggle only when explicit IDB modifications (renames, comments) are required.
4. Utilize the **Context Preview** to audit data transmitted to the AI provider, and use **Export Log** to archive the session.

### Function Chain Chat

1. Invoke the command on a designated entry function.
2. Define the analytical scope by setting the maximum graph depth and node count, then execute **Build Function Graph**.
3. Select the relevant caller and callee nodes from the generated hierarchy.
4. Issue queries spanning the selected scope. Restrict the graph size to maintain context limits and analytical focus.

### Autonomous Investigation

1. Invoke **Autonomous Investigation** on the entry function.
2. Define specific analytical objectives (e.g., "Identify cryptographic constants and execution flow") or execute the default malware analysis profile.
3. Monitor the agent's iterative tool calls and hypotheses via the Activity pane.
4. The agent operates in a read-only state. Maintain this configuration unless direct IDB mutation is authorized.

## Bulk Processing Operations

### Bulk Function Renamer (`Ctrl+Shift+R`)

A high-throughput batch processor for autonomous function renaming, constrained strictly by behavioral evidence derived from decompiled pseudocode.

1. Populate the processing queue by filtering functions via naming patterns, cross-reference counts, or export status.
2. Select the target rows and execute **Analyze Selected Function**.
3. Evaluate the generated proposals, noting the confidence score and algorithmic rationale.
4. Authorize valid proposals via **Apply Renames**.

### Bulk Variable Renamer (`Ctrl+Shift+V`)

Applies batch renaming logic to local variables across multiple functions.

1. Populate the processing queue and select target rows.
2. Execute **Start Variable Rename**.
3. Review the per-function mappings and identify any decompilation errors.
4. Authorize valid mappings via **Apply Suggestions**.

## Symbol Resolution

### Function Renaming (`Ctrl+Alt+N` / `Ctrl+Alt+M`)

*   **Code Context (`Ctrl+Alt+N`):** Prioritizes algorithmic logic and standard application behavior. Optimal for standard library functions and benign routines.
*   **Malware Context (`Ctrl+Alt+M`):** Enforces a threat intelligence context, prompting the AI to identify evasion techniques, C2 structures, and malicious intent.

### Variable Renaming (`Ctrl+Alt+R`)

1. Open the target function in the pseudocode view.
2. Execute **Suggest Variable Name**.
3. Review the proposed `current_name -> new_name` mapping table.
4. Reject invalid proposals and execute **Apply Selected**.

## Structural Inference

### Prototype Inference (`Ctrl+Alt+S`)

1. Navigate to the pseudocode view and execute **Suggest Function Prototype**.
2. Evaluate the proposed calling convention, parameter definitions, and return type against the underlying stack operations.
3. Apply the prototype only after verifying its accuracy, as incorrect definitions will degrade decompilation quality.

### Structure Inference (`Ctrl+Alt+E`)

1. Right-click a pointer or variable exhibiting repeated offset access patterns in pseudocode, and select **Struct editor**.
2. Execute **AI Suggestion** to initiate memory access pattern analysis.
3. Review the inferred field layouts, sizes, and data types.
4. Apply the structure to import it into the IDB's Local Types repository.

## Automated Documentation

### Pseudocode Comments (`Ctrl+Alt+C`)

Executes an analysis of the decompiled logic and injects explanatory inline comments at critical execution junctures. These are registered as Hex-Rays user comments.

### Disassembly Section Comments

Available exclusively in the IDA-View. Organizes assembly instructions into logical blocks and applies descriptive summary comments. Supports targeted analysis of specific instruction ranges via selection prior to invocation.
