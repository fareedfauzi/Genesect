# Utility Procedures & Explorers

The utilities detailed in this document are accessible via **Right-Click > PseudoNote > Utilities**. Analysts are encouraged to register frequently utilized commands to the **Bookmarks** menu for rapid access.

## Navigational Aids and Visualizations

### Hex Viewer

<img width="903" height="871" alt="image" src="https://github.com/user-attachments/assets/61fd5e42-c283-4c25-af74-a4b832b3dec0" />

A specialized, dockable hexadecimal editor optimized for binary analysis within the IDA environment.

*   **Cursor Synchronization:** Automatically tracks and highlights the active memory address synchronized with the IDA-View or Pseudocode pane.
*   **Data Annotation:** Supports persistent, color-coded highlighting of specific byte ranges for structural annotation.
*   **Format Adaptation:** Dynamically adapts to the active IDA color palette (light or dark mode).

### Toggle Call Highlight

<img width="1360" height="649" alt="image" src="https://github.com/user-attachments/assets/7f88e086-dcf3-439b-ad28-6a29f5bcf8a9" />

Visual differentiation of function calls within the analysis environment.

*   **Pseudocode Highlighting:** Applies background coloring to lines containing function invocations, increasing the right margin to prevent truncation of deep call chains.
*   **Disassembly Highlighting:** Visually isolates `call` and `jmp` instructions.
*   **State Tracking:** Distinguishes between resolved (renamed) functions and unresolved (`sub_`) stubs.

### Toggle Indent Marks

<img width="837" height="572" alt="image" src="https://github.com/user-attachments/assets/c107770a-b49a-4a21-a452-79fb05f1f5a5" />

Visually renders vertical indent guidelines within the pseudocode view to easily track nested loops and conditional branches. Configurable via Settings.

### Zoom Views

<img width="1296" height="829" alt="image" src="https://github.com/user-attachments/assets/1d6cf48e-2fe8-4a69-af3a-a6a2c081a070" />

<img width="611" height="645" alt="image" src="https://github.com/user-attachments/assets/572ba097-2186-45bb-b7d7-66c4de0c51fc" />

Allows dynamic font scaling of the Hex-Rays pseudocode, disassembly, and native PseudoNote interfaces by holding `Ctrl` and scrolling the mouse wheel.

### Folded Pseudocode

<img width="756" height="290" alt="image" src="https://github.com/user-attachments/assets/f2e57929-17f4-40b5-ae47-15c9ced45720" />

### Display function argument (WinAPI)

<img width="958" height="478" alt="image" src="https://github.com/user-attachments/assets/0cb14b3b-d4c8-418e-a5b4-7ec2b6c557b4" />


## Program Structure Analysis

### Call Tree

<img width="597" height="632" alt="image" src="https://github.com/user-attachments/assets/a713fe28-2251-4f5c-8f33-6b4733ae8ce0" />

An interactive, lazily-loaded hierarchical visualization interface for navigating code cross-references.

*   **Dependency Tracking:** Expands `Used By` (callers) and `Uses` (callees) recursively without degrading UI performance.
*   **API Resolution:** Dynamically resolves import directory thunks to their corresponding API string identifiers.
*   **Filtering & Navigation:** Supports dynamic text filtering and double-click navigation to the source instruction.

### Variable and Structure Explorers

*   **Global Variable Explorer:** Aggregates read/write access patterns, initialization logic, and alias definitions for global objects.
*   **Virtual-Class Explorer:** Identifies RTTI structures, virtual method tables (vtables), and inheritance models to assist in C++ class reconstruction.
*   **Callback Explorer:** Locates function pointer assignments, dispatch tables, and indirect execution transfers.
*   **Thread Explorer:** Maps thread-creation APIs, recovered entry points, APC scheduling, completion queues, and explicit message activity.
*   **Entry-Point Explorer:** Enumerates PE entry points, exported functions, TLS callbacks, and constructor arrays for rapid initial triage.

<img width="1533" height="709" alt="image" src="https://github.com/user-attachments/assets/19ca8327-e0a5-4021-97d5-a8773a10ff45" />

<img width="1524" height="686" alt="image" src="https://github.com/user-attachments/assets/b35ff0a6-035b-4743-b6d8-dbb6d87b07da" />

<img width="1524" height="675" alt="image" src="https://github.com/user-attachments/assets/f87d2fec-2c72-4ace-a585-50cc87f40a18" />


## Malware Analysis Explorers

PseudoNote Extended includes specialized heuristic engines designed to accelerate malware triage.

*   **Find Crypt Explorer:** Detects exact crypto/hash constants and tables plus Windows CryptoAPI, CNG, DPAPI, SChannel, compression, and encoding APIs. It also covers common cross-platform crypto, hashing, compression, encoding, modern elliptic-curve, and post-quantum library symbols. Scanning is read-only; annotation requires explicit confirmation and preserves analyst-defined names.
*   **Anti-Analysis Explorer:** Detects environmental fingerprinting, virtual machine evasion, timing checks, and debugger detection mechanisms.
*   **Process Injection Explorer:** Correlates memory allocation, cross-process write operations, and thread creation APIs to identify injection sequences.
*   **C2, Protocol and Packet Explorer:** Correlates socket, WinINet/WinHTTP, TLS, WebSocket, MQTT, AMQP, gRPC, SSH, named-pipe, and mailslot activity. It recovers network-correlated endpoints, HTTP/protocol artifacts, bidirectional sessions, beacon timing candidates, dispatch IDs, framing constants, repeated non-stack packet fields, serialization helpers, and evidence-backed handlers. Generic comparisons, stack displacements, unstructured callees, loopback addresses, and unrelated endpoint strings are downgraded or suppressed.
*   **API Sequence Explorer:** Correlates ordered multi-API behaviors such as remote-thread injection, process hollowing, runtime API resolution, and registry persistence. Isolated dual-use API calls are omitted.
*   **API Classification Explorer:** Classifies and correlates API calls to identify malware behaviors and explore evidence.
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

### Dump Selected Bytes
Allows extraction of a continuous memory block directly to a raw binary file on disk. Requires an active selection in the Disassembly view.

### Regex Search Across IDB
Executes high-performance regular expression queries across decompiled code, disassembly, strings, symbol names, and IDB comments globally.

### Copy Function Tree / Global Xref Tree
Exports a formatted, indented text representation of either a function's caller/callee tree or a global variable's cross-reference hierarchy directly to the clipboard.

## IDB Maintenance Operations

### Comment Explorer

Provides a centralized interface to filter, inspect, edit, or remove all user-defined and AI-generated comments across the entire IDB.


### Find Crypt Explorer

Inspired by GhidraFindcrypt, this explorer uses exact byte signatures to locate known constants and tables, then correlates direct Windows and cross-platform cryptography, hashing, compression, and encoding API calls. Scanning never modifies the IDB. Use **Annotate Selected...** to explicitly name and comment a constant after reviewing the evidence.
