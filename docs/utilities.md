# Utility Procedures & Explorers

The utilities detailed in this document are accessible via **Right-Click > PseudoNote > Utilities**. Analysts are encouraged to register frequently utilized commands to the **Bookmarks** menu for rapid access.

## Navigational Aids and Visualizations

### Hex Viewer (`Ctrl+Alt+B`)

A specialized, dockable hexadecimal editor optimized for binary analysis within the IDA environment.

*   **Cursor Synchronization:** Automatically tracks and highlights the active memory address synchronized with the IDA-View or Pseudocode pane.
*   **Data Annotation:** Supports persistent, color-coded highlighting of specific byte ranges for structural annotation.
*   **Format Adaptation:** Dynamically adapts to the active IDA color palette (light or dark mode).

### Toggle Call Highlight (`Ctrl+Alt+H`)

Visual differentiation of function calls within the analysis environment.

*   **Pseudocode Highlighting:** Applies background coloring to lines containing function invocations, increasing the right margin to prevent truncation of deep call chains.
*   **Disassembly Highlighting:** Visually isolates `call` and `jmp` instructions.
*   **State Tracking:** Distinguishes between resolved (renamed) functions and unresolved (`sub_`) stubs.

### Toggle Indent Marks (`Ctrl+Alt+I`)

Visually renders vertical indent guidelines within the pseudocode view to easily track nested loops and conditional branches. Configurable via Settings.

### Zoom Views (`Ctrl+Wheel`)

Allows dynamic font scaling of the Hex-Rays pseudocode, disassembly, and native PseudoNote interfaces by holding `Ctrl` and scrolling the mouse wheel.

## Program Structure Analysis

### Call Tree (`Ctrl+Alt+X`)

An interactive, lazily-loaded hierarchical visualization interface for navigating code cross-references.

*   **Dependency Tracking:** Expands `Used By` (callers) and `Uses` (callees) recursively without degrading UI performance.
*   **API Resolution:** Dynamically resolves import directory thunks to their corresponding API string identifiers.
*   **Filtering & Navigation:** Supports dynamic text filtering and double-click navigation to the source instruction.

### Variable and Structure Explorers

*   **Global Variable Explorer:** Aggregates read/write access patterns, initialization logic, and alias definitions for global objects.
*   **Virtual-Class Explorer:** Identifies RTTI structures, virtual method tables (vtables), and inheritance models to assist in C++ class reconstruction.
*   **Callback and Dispatch Resolver:** Locates function pointer assignments, dispatch tables, and indirect execution transfers.
*   **Thread and Synchronization Explorer:** Scans for thread creation APIs, synchronization primitives (mutexes, events), and shared global state access patterns.
*   **Exception and Unwind Explorer:** Identifies SEH handlers, C++ landing pads, and stack unwind metadata.
*   **Entry-Point Explorer:** Enumerates PE entry points, exported functions, TLS callbacks, and constructor arrays for rapid initial triage.
*   **Structure Recovery Explorer:** Correlates pointer-offset access patterns across multiple functions to infer complex structure definitions.

### Decompiler Quality Inspector

An automated diagnostic utility that identifies Hex-Rays decompilation failures, including suspicious type casting, prototype mismatches, unresolved indirect calls, and stack frame inconsistencies.

## Threat Intelligence & Malware Explorers

PseudoNote Extended includes specialized heuristic engines designed to accelerate malware triage.

*   **Anti-Analysis Explorer:** Detects environmental fingerprinting, virtual machine evasion, timing checks, and debugger detection mechanisms.
*   **Process Injection Explorer:** Correlates memory allocation, cross-process write operations, and thread creation APIs to identify injection sequences.
*   **C2 & Protocol Explorer:** Analyzes network initialization, socket configuration, and serialization routines to map command-and-control structures.
*   **Syscall & Kernel Interface Mapper:** Identifies direct system calls, `DeviceIoControl` usage, and kernel-mode transition points.
*   **Dynamic API Resolution Explorer:** Traces custom API hashing algorithms, PE Export Directory parsing, and manual payload loading mechanisms.
*   **API Hash Explorer:** Resolves suspected API hashes against the bundled `apilist.txt` dataset.
*   **Crypto and Encoding Explorer:** Identifies cryptographic constants, Base64 tables, XOR loops, and compression algorithms.
*   **Configuration and IOC Extractor:** Extracts hardcoded IP addresses, domains, registry keys, and embedded configuration blobs based on string access patterns.
*   **String Decryption Workbench:** Heuristically detects runtime string decoding loops and provides a safe, static preview of the decoded payloads without execution.

## Data Extraction and Pivoting

### FLOSS Integration (`Ctrl+Shift+F`)

Provides native execution and parsing of the FireEye Labs Obfuscated String Solver (FLOSS).

1. Ensure the `floss` executable is defined in Settings or available in the system `$PATH`.
2. Execute the string discovery protocol.
3. The resulting stack-strings, tight-strings, and decoded strings are rendered in a persistent, sortable IDA Chooser.

### Static Shellcode Analysis

Executes a heuristic analysis on a selected range of raw bytes to determine potential shellcode architecture, execution logic, and malicious capabilities without relying on dynamic emulation.

### Advance Copy Operations

Optimized extraction formats for signature generation and reporting. Accessible via the right-click context menu over a selected byte range in the Disassembly view.

*   **YARA Generation:** Extract raw hex, mask immediate values, mask relocation targets, extract opcodes only, or generate a complete rule template.
*   **Source Code Literals:** Extract bytes formatted as Python literals or C/C++ arrays.
*   **Disassembly Text:** Extract clean assembly instructions stripped of address prefixes.

### External Pivot Searching

Enables immediate querying of selected strings or bytes against external threat intelligence platforms (VirusTotal, Google, GitHub, MSDN, CyberChef). 

*Note: Execution of these pivots transmits the selected artifact to the respective third-party service.*

### Dump Selected Bytes
Allows extraction of a continuous memory block directly to a raw binary file on disk. Requires an active selection in the Disassembly view.

### Regex Search Across IDB
Executes high-performance regular expression queries across decompiled code, disassembly, strings, symbol names, and IDB comments globally.

### Copy Function Tree / Global Xref Tree
Exports a formatted, indented text representation of either a function's caller/callee tree or a global variable's cross-reference hierarchy directly to the clipboard.

## IDB Maintenance Operations

### Automatic Enum Recovery

Scans imported API definitions against known OS SDK structures, automatically mapping standard integer parameters to symbolic enumerations (e.g., process creation flags, memory protection constants) within the decompiled output.

### Comment Explorer

Provides a centralized interface to filter, inspect, edit, or remove all user-defined and AI-generated comments across the entire IDB.

### Change History and Undo Explorer

Maintains a comprehensive transaction log of all IDB modifications executed by PseudoNote Extended. Facilitates selective rollback operations to revert erroneous structural changes.
