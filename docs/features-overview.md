# Features & Action Registry

## Interface Access

Genesect actions are accessible primarily via the context menu within IDA Pro.

1. Allow IDA Pro's auto-analysis to reach completion.
2. Navigate to a function within the Pseudocode or Disassembly view.
3. Right-click to access the **Genesect** context menu and select the desired action.
4. Alternatively, utilize the predefined keyboard shortcuts detailed below.

---

## Action Registry & Keyboard Shortcuts

| Action Identifier | Default Shortcut | Context Availability |
|---|---|---|
| Open Readable Code | `Ctrl+Alt+G` | Global |
| Open Analyst Notes | `Ctrl+Alt+Shift+G` | Global |
| Browse Saved Artifacts | `Ctrl+Alt+L` | Global |
| Settings | `Ctrl+Alt+P` | Global |
| Migrate Legacy Data | Menu Only | Global |
| UI Component Preview | Menu Only | Global |
| Suggest Function Name (Code Context) | `Ctrl+Alt+N` | Global |
| Suggest Function Name (Malware Context) | `Ctrl+Alt+M` | Global |
| Suggest Variable Name | `Ctrl+Alt+R` | Global |
| Suggest Function Prototype | `Ctrl+Alt+S` | Pseudocode |
| Infer / Edit Structure | `Ctrl+Alt+E` | Pseudocode |
| Generate Pseudocode Comments | `Ctrl+Alt+C` | Pseudocode |
| Remove Pseudocode Comments | `Ctrl+Alt+D` | Pseudocode |
| Generate Disassembly Comments | `Ctrl+Shift+C` | Disassembly |
| Remove Disassembly Comments | `Ctrl+Shift+D` | Disassembly |
| Chat About This Function | `Ctrl+Alt+A` | Global |
| Chat About a Function Chain | `Ctrl+Alt+Shift+A` | Global |
| Autonomous Investigation | `Ctrl+Alt+Shift+M` | Global |
| Bulk Function Renamer | `Ctrl+Shift+R` | Global |
| Bulk Variable Renamer | `Ctrl+Shift+V` | Global |
| Bulk Function Analysis | `Ctrl+Shift+A` | Global |
| Deep Analyzer with Report | `Ctrl+Shift+S` | Global |
| Function Chain Summarizer | `Ctrl+Alt+Z` | Global |
| Discover Strings with FLOSS | `Ctrl+Shift+F` | Global |
| GoReSym | Menu Only | Global |
| Organize Go Packages | Menu Only | Global |
| Go/Rust User Code Map | Menu Only | Global |
| Mark Go/Rust User Code in IDB | Menu Only | Global |
| Rust Binary Triage | Menu Only | Global |
| Display Rust Strings | Menu Only | Pseudocode |
| Demangle Rust Symbols | Menu Only | Global |
| RIFT Library Recognition | Menu Only | Global |
| Analyze Selected Bytes / Shellcode | `Ctrl+Shift+E` | Disassembly Selection |
| Toggle Call Highlight (Pseudocode) | `Ctrl+Alt+H` | Pseudocode |
| Toggle Call Highlight (Assembly) | `Ctrl+Shift+H` | Disassembly |
| Toggle Indent Marks | `Ctrl+Alt+I` | Pseudocode |
| Interactive Code Blocks | Menu Only | Pseudocode |
| Display function argument names | Menu Only | Pseudocode |
| Zoom Views (Ctrl+Wheel) | `Ctrl+Wheel` | Scrollable Views |
| Call Tree | `Ctrl+Alt+X` | Global |
| Hex Viewer | `Ctrl+Alt+B` | Global |
| Global Variable Explorer | Menu Only | Global |
| VTable Explorer | Menu Only | Global |
| Virtual-Class Explorer | Menu Only | Global |
| COM Explorer | Menu Only | Global |
| Indirect Call Explorer | Menu Only | Global |
| Callback Shellcode APIs | Menu Only | Global |
| Call Centrality Explorer | Menu Only | Global |
| Thread Explorer | Menu Only | Global |
| Entry-Point Explorer | Menu Only | Global |
| Find Crypt Explorer | Menu Only | Global |
| Anti-Analysis Explorer | Menu Only | Global |
| Process Injection Explorer | Menu Only | Global |
| C2, Protocol and Packet Explorer | Menu Only | Global |
| API Sequence Explorer | Menu Only | Global |
| API Classification Explorer | Menu Only | Global |
| Configuration and IOC Extractor | Menu Only | Global |
| Regex Search Across IDB | Menu Only | Global |
| Dump Selected Bytes | Menu Only | Disassembly Selection |
| Export AI Workspace | Menu Only | Global |
| Copy Function Tree | `Ctrl+Alt+T` | Global |
| Copy Global Xref Tree | Menu Only | Global |
| Comment Explorer | Menu Only | Global |
| Search Selected Bytes on VirusTotal | Context Menu | Disassembly Selection |
| Open Selected Bytes in CyberChef | Context Menu | Disassembly Selection |
| Search Text on VirusTotal | Context Menu | Text Selection |
| Search Text on Google | Context Menu | Text Selection |
| Search Text on GitHub | Context Menu | Text Selection |
| Search WinAPI Documentation | Context Menu | Text Selection |
| Open Text in CyberChef | Context Menu | Text Selection |
| Copy Hex Bytes | Context Menu | Disassembly Selection |
| Generate YARA Rule | Context Menu | Disassembly Selection |
| Copy Hex (Mask Targets/Relocs) | Context Menu | Disassembly Selection |
| Copy Hex (Mask Immediates) | Context Menu | Disassembly Selection |
| Copy Hex (Opcodes Only) | Context Menu | Disassembly Selection |
| Copy Python Byte Literal | Context Menu | Disassembly Selection |
| Copy C/C++ Byte Array | Context Menu | Disassembly Selection |
| Copy Disassembly Text | Context Menu | Disassembly Selection |

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
*   **Autonomous Investigation:** A read-only agent workflow that traverses the call graph through IDA tools, records evidence, and supports compact skill routes for malware RE, IOC extraction, unpacking, Go/Rust user-code recovery, and C++ virtual dispatch.
*   **Bulk Renaming Engines:** High-throughput batch processors for renaming functions and variables autonomously.
*   **Bulk Function Analyzer:** Rapid triage engine that classifies functions against known malicious behavior taxonomies.
*   **Deep Analyzer:** A comprehensive, multi-stage pipeline that traverses call graphs, renames symbols bottom-up, and generates a standalone HTML report.
*   **Function Chain Summarizer:** Applies Map-Reduce methodologies to synthesize execution flow summaries across complex call graphs.
*   **FLOSS Integration:** Automates the extraction of stack-constructed, tightly-looped, and obfuscated strings via FireEye Labs Obfuscated String Solver.
*   **GoReSym Integration:** Runs Mandiant GoReSym, imports recovered Go function/type names, and can download a platform release when no local binary is configured.
*   **Go Package Organizer:** Groups recovered Go functions into IDA function folders by user, third-party, standard library, runtime, and uncategorized packages.
*   **Go/Rust User Code Map:** Classifies runtime, standard library, third-party, and likely user code, then marks or clears actionable function comments and colors in the IDB.
*   **Rust Binary Analysis:** Scores Rust-specific indicators, surfaces `lang_start_internal` and panic-location leads, improves Rust string display in pseudocode, demangles Rust function symbols, and can submit library-recognition jobs to a configured RIFT server.
*   **Shellcode Analysis:** Performs static capability analysis on raw byte sequences.

### Navigational Utilities & Extraction
*   **Call Highlighter:** Visually differentiates known and unknown function calls within the disassembly and pseudocode views.
*   **Interactive Code Blocks:** Adds collapsible block controls to Hex-Rays pseudocode for large nested functions.
*   **Display function argument names:** Shows known API argument names inline for selected calls.
*   **Call Tree:** A dynamic, lazily-loaded hierarchical viewer for navigating function cross-references and dependency chains.
*   **Program Structure Explorers:** Global variables, vtables, virtual classes, COM usage, indirect calls, callback shellcode APIs, centrality, threads, and entry points.
*   **Search Pivots:** Integrates external threat intelligence and documentation lookups directly into the selection context.
*   **Hex Viewer:** A customized, dockable hexadecimal editor optimized for binary analysis.
*   **Export AI Workspace:** Exports an AI-readable project folder containing function indexes, per-function decompilation and disassembly, callgraph edges, strings, imports, exports, segments, names, Go/Rust classifications, virtual-class evidence, a triage router, a malware reverse-engineering skill pack, and IOC/reporting guidance for Codex, Claude, Cursor, and similar agents.
*   **Advanced Copy:** Extracts and formats byte sequences into YARA rules, masked hex, Python literals, C arrays, opcode-only sequences, and clean disassembly text.
