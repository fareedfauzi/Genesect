# Utility tutorials

Utilities are under **right-click > PseudoNote > Utilities**. Add frequently used commands to **PseudoNote > Bookmarks** from the Bookmarks tab in Settings.

## Navigation and views

### Hex Viewer

Open **Hex Viewer** to inspect IDB bytes in a dockable hex/ASCII canvas. Navigate to an address, search for hex or text, and use labels to retain context. The viewer reads the currently loaded IDB; an empty view usually means no binary database is active.

### Toggle Call Highlight — Pseudocode and Assembly

Use the separate toggles to highlight call sites in Hex-Rays or graph/linear disassembly. Enabling pseudocode call highlighting sets the Hex-Rays right margin to 120 and regenerates the current pseudocode so long calls remain readable. Assembly highlighting is enabled by default and uses `#ffaaff` unless changed in Settings. Toggling off restores only colors owned by PseudoNote.

### Toggle Indent Marks

Indent Marks are enabled by default in pseudocode. Toggle them from the menu or press `Ctrl+Alt+I`. Select style, width, and empty-line behavior in Settings. Reopen or refresh pseudocode if Hex-Rays regenerated its text.

### Zoom Views

Enable **Zoom Views (Ctrl+Wheel)**, hold Ctrl, and use the mouse wheel over compatible IDA or PseudoNote views. Toggle it off to return Ctrl+wheel handling to the host widgets.

## Program structure

### Global Variable Explorer

Open the explorer, filter global objects, and select one to inspect reads, writes, inferred type, initialization, aliases, and affected functions. Double-click references to navigate. Treat inferred types as proposals until cross-checked with access width and use.

### Call Tree

Open **Call Tree** on the current function. Expand **Used By** for callers and **Uses** for callees, or filter by name to search the immediate relationships automatically. Direct calls and cross-function tail calls are kept separate from address-taken callback evidence, which appears only when **Indirect calls** is enabled. Double-click an entry to visit its reference site, or right-click to navigate to the target function, visit the reference site, or copy the entry. Toggle API visibility to control library noise.

### Browse Virtual Tables

Run the vtable scan, select a candidate table, and inspect its virtual methods and references. Use this lightweight list when you need tables and methods; use Virtual-Class Explorer for class recovery.

### Virtual-Class Explorer

Scan for vtables, RTTI, constructors, destructors, methods, and inheritance evidence. Select a class candidate to inspect relationships and navigate to supporting addresses. Review compiler-specific and stripped-binary uncertainty before applying names or types.

### Callback and Dispatch Resolver

Scan the IDB for function-pointer assignments, callback registrations, dispatch tables, jump tables, and indirect calls. Select a candidate to compare registration and invocation evidence, then navigate to possible targets.

### Thread and Synchronization Explorer

Scan for thread creation, entry points, locks, events, queues, and shared globals. Follow edges between threads and shared state. Reported race or deadlock risks are static indicators and require path validation.

### Exception and Unwind Explorer

Open the explorer to review SEH handlers, landing pads, cleanup paths, and unwind metadata. Select entries to navigate between protected regions and handlers. Compiler-generated cleanup code may not represent application-level exceptions.

### Entry-Point Explorer

Scan and review the executable entry point, exports, TLS callbacks, constructors, initialization arrays, and detected thread entries. Start malware triage here when behavior may execute before `main`.

### Structure Recovery Explorer

Scan pointer-offset access patterns, group compatible layouts, and inspect inferred fields across functions. Compare candidates, correct conflicts, and apply only reviewed types.

### Decompiler Quality Inspector

Run the inspector to find failed decompilations, suspicious casts, bad prototypes, stack inconsistencies, unresolved calls, and poorly typed variables. Work from high-impact root causes—function boundaries, stack pointer, and prototypes—then refresh Hex-Rays.

## Malware-analysis explorers

### Anti-Analysis Explorer

Scan for debugger checks, VM/sandbox probes, correlated timing logic, environment fingerprints, opaque predicates, and control-flow tricks. The default view shows corroborated evidence only: explicit debugger APIs, confirmed debug information classes, referenced VM artifacts, multi-signal fingerprinting, and complete timing chains. Enable **Weak signals** when you intentionally want to review standalone Sleep/CPUID/timestamp calls, exception APIs, unreferenced strings, possible opaque predicates, and dense indirect dispatch. Select a finding to inspect its evidence score and references.

### Process Injection Explorer

Scan for allocation, cross-process writes, section mapping, remote threads, APCs, hollowing, and execution transitions. Follow the staged evidence from target acquisition through execution; isolated APIs should not be labeled injection without the sequence.

### C2, Protocol and Packet Explorer

Scan network and serialization code, then inspect endpoints, command IDs, message layouts, request/response handlers, and packet fields. Correlate constants with branches and data flow before naming a protocol command.

### Syscall and Kernel Interface Mapper

Review direct syscalls, IOCTLs, device paths, kernel callbacks, and user/kernel boundaries. Decode IOCTL fields where possible and inspect buffers at both sides of the interface.

### Dynamic API Resolution Explorer

Scan runtime resolver calls, export walking, API hashes, syscall tables, and custom loaders. Follow each resolver from input identifier to stored function pointer and later indirect calls.

### API Hash Explorer

Enter or select hash values, choose known algorithms, and resolve against bundled `apilist.txt`. Review collisions and module context. For an unknown algorithm, invoke AI assistance to analyze the custom hash routine, then validate it with known input/output pairs.

### Crypto and Encoding Explorer

Scan for constants and code patterns associated with cryptography, hashing, XOR loops, Base64, compression, and custom transforms. Select a candidate and inspect the cited instructions and callers before assigning an algorithm name.

### Configuration and IOC Extractor

Scan strings, data, and access patterns for configuration structures, domains, IPs, paths, mutexes, keys, campaign IDs, and encoded blobs. Export findings only after distinguishing embedded defaults, decoys, and runtime values.

### String Decryption Workbench

Detect likely decoder functions, select call sites or encoded blobs, and preview decoded output using the supported safe analysis path. Apply annotations only to verified results. Do not execute an untrusted sample merely to obtain strings.

## Search and data

### Regex Search Across IDB

Enter a regular expression, choose decompilation, disassembly, strings, names, and/or comments, then run the search. Double-click results to navigate. Begin with a constrained scope and expression to avoid expensive whole-IDB searches.

### Discover Strings with FLOSS

Configure the FLOSS executable in Settings or make it available on `PATH`. Open the feature, select the sample when required, and run analysis. PseudoNote parses JSON output and presents discovered strings. If JSON parsing fails, verify that the configured binary supports the requested JSON mode and that its stdout is not an error page or banner.

### Dump Selected Bytes

Select a valid address range in disassembly, run **Dump Selected Bytes...**, choose a file, and confirm the reported byte count. Gaps or unloaded addresses are rejected rather than silently filled.

## Copy and export

### Copy Function Tree and Copy Global Xref Tree

Run **Copy Function Tree** on a function or **Copy Global Xref Tree** on a global object. Configure depth where offered, copy the rendered hierarchy, and paste it into notes, reports, or an external analysis tool. Recursive cycles are bounded.

### Byte and disassembly formats

Select bytes in disassembly, then choose:

- **Copy Hex Bytes** for a plain hex pattern.
- **Copy Hex (Mask Targets/Relocs)** to wildcard relocation-sensitive references and branch targets.
- **Copy Hex (Mask Immediates)** to wildcard immediate/address fields.
- **Copy Hex (Opcodes Only)** for the most generalized instruction pattern.
- **Generate YARA Rule...** for a starter rule that must be reviewed and tested.
- **Copy Python Byte Literal** or **Copy C/C++ Byte Array** for source-code embedding.
- **Copy Disassembly Text** for a textual instruction listing.

Always test generated YARA rules against representative clean and malicious corpora; short or heavily wildcarded signatures can create false positives.

## External pivot search

Select text or bytes and choose the relevant VirusTotal, Google, GitHub, Microsoft documentation, or CyberChef action. Confirm the browser URL before submitting sensitive proprietary material. These commands open external services; PseudoNote does not control their retention policies.

## IDB maintenance

### Comment Explorer

Open the explorer, filter assembly and pseudocode comments, and double-click an entry to navigate. Edit, delete, or export selected comments after reviewing scope.

### Automatic Enum Recovery

Scan recognized Windows and Linux imports, validate each real imported prototype, and review parameter enum types before applying them. The table shows the import slot and its reference count; it does not claim that the import-slot address is a call site. Proposals start unchecked, and entries with missing or incompatible prototypes cannot be selected. Applying a proposal changes the imported API parameter type so Hex-Rays can render constants such as process flags, page protection, socket families, and mapping flags symbolically at call sites.

Scan calls for arguments matching known API enum values, review the proposed enum and target operand, and apply selected proposals. Re-run decompilation to observe improved symbolic constants.

### Change History and Undo Explorer

Open the journal to review recorded IDB modifications with before/after values. Select a compatible entry, inspect dependencies and current state, then perform a selective rollback. Save a backup before undoing broad or interdependent changes.
