# Utility Procedures & Explorers

The utilities detailed in this document are accessible via **Right-Click > PseudoNote > Utilities**. Analysts are encouraged to register frequently utilized commands to the **Bookmarks** menu for rapid access.

## Navigational Aids and Visualizations

### Hex Viewer (`Ctrl+Alt+B`)

A specialized, dockable hexadecimal editor optimized for binary analysis within the IDA environment.

*   **Cursor Synchronization:** Automatically tracks and highlights the active memory address synchronized with the IDA-View or Pseudocode pane.
*   **Data Annotation:** Supports persistent, color-coded highlighting of specific byte ranges for structural annotation.
*   **Format Adaptation:** Dynamically adapts to the active IDA color palette (light or dark mode).

### Call Highlighter (`Ctrl+Alt+H`)

Visual differentiation of function calls within the analysis environment.

*   **Pseudocode Highlighting:** Applies background coloring to lines containing function invocations, increasing the right margin to prevent truncation of deep call chains.
*   **Disassembly Highlighting:** Visually isolates `call` and `jmp` instructions.
*   **State Tracking:** Distinguishes between resolved (renamed) functions and unresolved (`sub_`) stubs.

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

## IDB Maintenance Operations

### Automatic Enum Recovery

Scans imported API definitions against known OS SDK structures, automatically mapping standard integer parameters to symbolic enumerations (e.g., process creation flags, memory protection constants) within the decompiled output.

### Change History and Undo Explorer

Maintains a comprehensive transaction log of all IDB modifications executed by PseudoNote Extended. Facilitates selective rollback operations to revert erroneous structural changes.
