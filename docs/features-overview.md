# Features & Action Registry

## Interface Access

PseudoNote Extended actions are accessible primarily via the context menu within IDA Pro.

1. Allow IDA Pro's auto-analysis to reach completion.
2. Navigate to a function within the Pseudocode or Disassembly view.
3. Right-click to access the **PseudoNote** context menu and select the desired action.
4. Alternatively, utilize the predefined keyboard shortcuts detailed below.

---

## Action Registry & Keyboard Shortcuts

| Action Identifier | Default Shortcut | Context Availability |
|---|---|---|
| Show PseudoNote Panes | `Ctrl+Alt+G` | Global |
| View Saved Notes | `Ctrl+Alt+L` | Global |
| Configure Settings | Menu Only | Global |
| Rename Function (Code Context) | `Ctrl+Alt+N` | Global |
| Rename Function (Malware Context) | `Ctrl+Alt+M` | Global |
| Rename Variables | `Ctrl+Alt+R` | Global |
| Infer Function Prototype | `Ctrl+Alt+S` | Pseudocode |
| Generate Comments (Pseudocode) | `Ctrl+Alt+C` | Pseudocode |
| Generate Section Comments (IDA-View) | Menu Only | Disassembly |
| Delete Comments (Pseudocode) | `Ctrl+Alt+D` | Pseudocode |
| Delete Comments (IDA-View) | Menu Only | Disassembly |
| Invoke Contextual Chat | `Ctrl+Alt+A` | Global |
| Execute Bulk Function Renamer | `Ctrl+Shift+R` | Global |
| Execute Bulk Variable Renamer | `Ctrl+Shift+V` | Global |
| Execute Bulk Function Analyzer | `Ctrl+Shift+A` | Global |
| Execute Deep Analyzer Pipeline | `Ctrl+Shift+S` | Global |
| Execute Function Chain Summarizer | Menu Only | Global |
| Execute FLOSS Strings Discovery | `Ctrl+Shift+F` | Global |
| Rust Binary Triage | Menu Only | Global |
| Display Rust Strings | Menu Only | Pseudocode |
| Demangle Rust Symbols | Menu Only | Global |
| RIFT Library Recognition | Menu Only | Global |
| Analyze Static Shellcode/Bytes | Menu Only | Disassembly |
| Toggle Call Highlight (Pseudocode) | `Ctrl+Alt+H` | Pseudocode |
| Toggle Call Highlight (Graph/Linear) | Menu Only | Disassembly |
| Toggle Indent Marks | `Ctrl+Alt+I` | Pseudocode |
| Open Interactive Call Hierarchy | `Ctrl+Alt+X` | Global |
| Open Hex Viewer | `Ctrl+Alt+B` | Global |
| Open Struct Editor | `Ctrl+Alt+E` | Pseudocode |
| Global Variable Explorer | Menu Only | Global |
| VTable Explorer | Menu Only | Global |
| Virtual-Class Explorer | Menu Only | Global |
| Callback Explorer | Menu Only | Global |
| Thread Explorer | Menu Only | Global |
| Entry-Point Explorer | Menu Only | Global |
| Find Crypt Explorer | Finds crypto/hash/compression/encoding constants and API usage; optional reviewed annotation | Utilities |
| Anti-Analysis Explorer | Menu Only | Global |
| Process Injection Explorer | Menu Only | Global |
| C2, Protocol and Packet Explorer | Menu Only | Global |
| API Sequence Explorer | Menu Only | Global |
| API Classification Explorer | Menu Only | Global |
| Configuration and IOC Extractor | Menu Only | Global |
| Regex Search Across IDB | Menu Only | Global |
| Dump Selected Bytes | Menu Only | Disassembly (Selection Required) |
| Copy Function Tree / Global Xref Tree | Menu Only | Global |
| Comment Explorer | Menu Only | Global |
| Pivot: Search Bytes in VirusTotal | Context Menu | Disassembly (Selection Required) |
| Pivot: Export Bytes to CyberChef | Context Menu | Disassembly (Selection Required) |
| Pivot: Search String in VirusTotal | Context Menu | Global (Text Selection) |
| Pivot: Search String in Google | Context Menu | Global (Text Selection) |
| Pivot: Search String in GitHub | Context Menu | Global (Text Selection) |
| Pivot: Search String in MSDN | Context Menu | Global (Text Selection) |
| Pivot: Export String to CyberChef | Context Menu | Global (Text Selection) |

---

## Feature Categorization

### Core Panels (`Ctrl+Alt+G`)
*   **Readable Code:** Synthesizes human-readable, high-level code representations of the active function.
*   **Function Details:** Aggregates and displays static metadata (callers, callees, API imports, string references).
*   **Analyst Notes:** Provides a persistent, Markdown-based documentation interface per function.
*   **Custom Prompt:** Facilitates ad-hoc, structured queries to the AI provider with optional pseudocode/assembly context inclusion.
*   **Execution Flow:** Generates a textual, high-level control flow graph describing logical branches and intent.

### Symbol Resolution & Documentation
*   **Function Renaming:** Suggests semantic function names based on algorithmic logic (Code mode) or threat intelligence heuristics (Malware mode).
*   **Variable Renaming:** Contextually renames local variables to reflect their data types and usage.
*   **Automated Commenting:** Injects explanatory inline comments into Hex-Rays pseudocode or logical block comments into disassembly.
*   **Prototype Inference:** Analyzes stack usage and calling conventions to apply accurate C prototypes.
*   **Struct Inference:** deduces structure layouts and field offsets based on memory access patterns.

### Advanced Analytical Pipelines
*   **Contextual Chat:** A persistent, function-aware conversational interface.
*   **Bulk Renaming Engines:** High-throughput batch processors for renaming functions and variables autonomously.
*   **Bulk Function Analyzer:** Rapid triage engine that classifies functions against known malicious behavior taxonomies.
*   **Deep Analyzer:** A comprehensive, multi-stage pipeline that traverses call graphs, renames symbols bottom-up, and generates a standalone HTML report.
*   **Function Chain Summarizer:** Applies Map-Reduce methodologies to synthesize execution flow summaries across complex call graphs.
*   **FLOSS Integration:** Automates the extraction of stack-constructed, tightly-looped, and obfuscated strings via FireEye Labs Obfuscated String Solver.
*   **Rust Binary Analysis:** Scores Rust-specific indicators, surfaces `lang_start_internal` and panic-location leads, improves Rust string display in pseudocode, demangles Rust function symbols, and can submit library-recognition jobs to a configured RIFT server.
*   **Shellcode Analysis:** Performs static capability analysis on raw byte sequences.

### Navigational Utilities & Extraction
*   **Call Highlighter:** Visually differentiates known and unknown function calls within the disassembly and pseudocode views.
*   **Call Tree:** A dynamic, lazily-loaded hierarchical viewer for navigating function cross-references and dependency chains.
*   **Search Pivots:** Integrates external threat intelligence and documentation lookups directly into the selection context.
*   **Hex Viewer:** A customized, dockable hexadecimal editor optimized for binary analysis.
*   **Advance Copy:** Extracts and formats byte sequences into highly optimized templates (e.g., YARA rules, Python literals, C arrays).
