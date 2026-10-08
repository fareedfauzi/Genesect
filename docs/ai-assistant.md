# AI Assistant Workflows

The procedures detailed in this document are accessible via **Right-Click > PseudoNote > AI Assistant**. Proper AI provider configuration and completion of IDA Pro's auto-analysis are prerequisites for executing function-level analysis.

## Core Interface: PseudoNote Pane

<img width="797" height="128" alt="image" src="https://github.com/user-attachments/assets/04a4a801-4014-4451-9ef7-d19d29b72b18" />

<img width="1529" height="668" alt="image" src="https://github.com/user-attachments/assets/c153a9f6-043f-469c-aea3-e72abb030fb4" />

<img width="1533" height="679" alt="image" src="https://github.com/user-attachments/assets/158ffd62-b994-4382-9a82-44b6ad02633e" />

The primary dockable panel provides multiple analytical contexts.

*   **Function Details:** Aggregates static metadata directly from the IDB (callers, callees, strings) without invoking external AI requests.
*   **Function Explain:** Generates a comprehensive, plain-English summary of the current function's behavioral intent and algorithmic logic.
*   **Tree Graph:** Synthesizes a text-based, hierarchical control flow graph detailing decision branches, loops, and conditional logic.
*   **Custom Prompt:** Facilitates targeted, ad-hoc querying of the AI model. Contextual inclusions (Pseudocode or Assembly) are configurable via interface toggles.

## Interactive Contextual Analysis

### Function Chat

<img width="1532" height="865" alt="image" src="https://github.com/user-attachments/assets/8725b31c-7db5-4ce1-a863-eb966b2404a9" />

1. Navigate to the target function and invoke **Chat About This Function**.
2. Formulate a query or utilize the predefined tools (e.g., **Show pseudocode**, **Explain function**, **Suggest function name**).
3. The interface operates in a read-only capacity by default. Enable the **Enable IDA changes** toggle only when explicit IDB modifications (renames, comments) are required.
4. Utilize the **Context Preview** to audit data transmitted to the AI provider, and use **Export Log** to archive the session.

### Function Chain Chat

<img width="1860" height="875" alt="image" src="https://github.com/user-attachments/assets/3568115b-c9b9-42e1-97a5-21f09e3946c0" />

1. Invoke the command on a designated entry function.
2. Define the analytical scope by setting the maximum graph depth and node count, then execute **Build Function Graph**.
3. Select the relevant caller and callee nodes from the generated hierarchy.
4. Issue queries spanning the selected scope. Restrict the graph size to maintain context limits and analytical focus.

### Autonomous Investigation

<img width="1532" height="869" alt="image" src="https://github.com/user-attachments/assets/8cd64480-9680-4185-80a7-ed2f274b2698" />

1. Invoke **Autonomous Investigation** on the entry function.
2. Define specific analytical objectives (e.g., "Identify cryptographic constants and execution flow") or execute the default malware analysis profile.
3. Monitor the agent's iterative tool calls and hypotheses via the Activity pane.
4. The agent operates in a read-only state. Maintain this configuration unless direct IDB mutation is authorized.

Example result:
```
Coverage complete: 83/83 analyzed • 80 renamed • 83 commented • 3 names retained • 0 unresolved.
Final Analysis:
Executive summary
This binary is a Windows program that attempts to download an executable from a remote URL and run it. If the download succeeds it spawns the downloaded file (via CreateProcessW); if the download fails it opens a fallback URL and invokes ShellExecuteW to run a local ping+payload command. Primary code implementing this behavior is at 0x401080 (decompiled pseudocode and function_evidence). Confidence in the observed control flow is high (≈85%).
Observed facts (evidence-backed, tool outputs cited)
Core network/file operations (main at 0x401080):
InternetOpenW called with user-agent "Mozilla/5.0" (decompile/main evidence at 0x401080; string at 0x403288). (evidence: decompile 0x401080; function_evidence 0x401080)
URLDownloadToFileW is invoked to download http://ssl-6582datamanager.helpdeskbros.local/favicon.ico and save it to C:\Users\Public\Documents\CR433101.dat.exe (URL string at 0x4031B8, path at 0x403230; seen in decompile of 0x401080). (evidence: decompile 0x401080; function_evidence 0x401080)
On successful download the code builds a command line using GetModuleFileNameW and the format string "cmd.exe /C ping 1.1.1.1 -n 1 -w 3000 > Nul & Del /f /q "%s"" and calls CreateProcessW to run it (decompile 0x401080; format string at 0x403140). (evidence: decompile 0x401080)
If URLDownloadToFileW fails the code calls InternetOpenUrlW to open a fallback URL (http://huskyhacks.dev, string at 0x4032A0) and then calls ShellExecuteW with verb "open" and the command string "ping 1.1.1.1 -n 1 -w 3000 > Nul & C:\Users\Public\Documents\CR433101.dat.exe" (string at 0x4032D0). (evidence: decompile 0x401080; function_evidence 0x401080)
APIs and imports used by main (function_evidence 0x401080): InternetOpenW, URLDownloadToFileW, InternetOpenUrlW, ShellExecuteW, CreateProcessW, GetModuleFileNameW, CloseHandle.
CRT/runtime helpers present and recorded (evidence ledger): security and GS helpers at 0x401399 (security_check_cookie) and 0x401623 (report_gsfailure); CRT startup wrappers at 0x40146F (scrt_common_main_seh) and 0x4015F1 (start); numeric helpers at 0x402560 (ltod3), 0x402040 (alldiv), 0x4020F0 (alldvrm), 0x4021D0 (allmul). These were observed in decompiles and function_evidence entries.
IOCs (strings and addresses observed in the binary)
URLs:
http://ssl-6582datamanager.helpdeskbros.local/favicon.ico (string/address observed in 0x401080; string located at 0x4031B8)
http://huskyhacks.dev (fallback host; string at 0x4032A0)
File path: C:\Users\Public\Documents\CR433101.dat.exe (string at 0x403230; used as the download target in 0x401080)
Command strings:
Format string used to build process command: "cmd.exe /C ping 1.1.1.1 -n 1 -w 3000 > Nul & Del /f /q "%s"" (string at 0x403140; used in 0x401080)
Fallback command: "ping 1.1.1.1 -n 1 -w 3000 > Nul & C:\Users\Public\Documents\CR433101.dat.exe" (string at 0x4032D0; used in 0x401080)
User-Agent: "Mozilla/5.0" (string at 0x403288; used in InternetOpenW call in 0x401080)
IP referenced (in command strings): 1.1.1.1
Behavior and capability mapping (based only on observed evidence)
Downloader/stager behavior: uses URLDownloadToFileW to retrieve an executable and save it under C:\Users\Public\Documents (T1105 — Ingress Tool Transfer). (evidence: decompile 0x401080; function_evidence 0x401080)
Execution of retrieved payload: after successful download CreateProcessW is called to execute the prepared command line; on failure the code uses InternetOpenUrlW and ShellExecuteW to run a fallback command that references the saved path (evidence: decompile 0x401080).
Use of cmd.exe and ping appears to be used to create a small delay and then delete a file (strings at 0x403140 and 0x4032D0); these are present as literal strings in the binary and invoked by the code (evidence: decompile 0x401080).
Confidence and provenance
The main control flow (download then execute/fallback) is directly visible in the decompiled main function at 0x401080 and corroborated by function_evidence entries for that function. Confidence for this core behavior is high (~85%).
All IOCs and API usages listed above are taken directly from the decompiled output and function_evidence collected during analysis; addresses for strings and functions are taken from the host-provided evidence ledger.
Unknowns and limitations
The content and behavior of the downloaded file (CR433101.dat.exe) are unknown from this static analysis; no dynamic retrieval of the remote resource was performed here.
The binary includes many CRT/runtime helpers (numeric, startup, GS checks). Those helpers appear to be standard CRT code; their presence does not change the observed network/file behavior, and their deeper roles (if any) beyond normal runtime support are not indicated by the evidence collected for main.
Analyst recommended next steps (evidence-driven)
In a controlled analysis environment (isolated VM with snapshots), execute the sample with network capture and process tracing to observe runtime network calls and confirm the download and subsequent execution of CR433101.dat.exe. Capture the downloaded file for separate analysis.
If the remote hosts resolve and serve content, retrieve the downloaded file in a controlled manner and perform static/dynamic analysis on that payload to determine capabilities and persistence mechanisms.
Add the observed strings/hosts/file path to detection/blocked-lists and create YARA or IDS signatures based on the static IOCs for hunting.
If desired, enumerate historical DNS/WHOIS and passive DNS for the two domains to look for additional associated infrastructure.
Relevant evidence citations (addresses)
Main function and behavior: 0x401080 (decompile output and function_evidence entries). See decompiled pseudocode and function_evidence records for 0x401080 in the evidence ledger.
Strings (locations from function_evidence for 0x401080):
Primary URL string: 0x4031B8 -> "http://ssl-6582datamanager.helpdeskbros.local/favicon.ico"
Fallback URL string: 0x4032A0 -> "http://huskyhacks.dev"
Target path: 0x403230 -> "C:\Users\Public\Documents\CR433101.dat.exe"
Command format: 0x403140 -> "cmd.exe /C ping 1.1.1.1 -n 1 -w 3000 > Nul & Del /f /q "%s""
Fallback command: 0x4032D0 -> "ping 1.1.1.1 -n 1 -w 3000 > Nul & C:\Users\Public\Documents\CR433101.dat.exe"
User-Agent: 0x403288 -> "Mozilla/5.0"
CRT and helper functions (addresses recorded during analysis): 0x401399 (__security_check_cookie), 0x401623 (__report_gsfailure), 0x40146F (scrt_common_main_seh), 0x4015F1 (start), 0x402560 (ltod3), 0x402040 (alldiv), 0x4020F0 (alldvrm), 0x4021D0 (allmul).
Final assessment (one sentence)
This binary is a downloader/stager that attempts to fetch an executable from a primary URL and execute it (or uses a fallback URL and ShellExecute invocation if the download fails), placing the file in C:\Users\Public\Documents\CR433101.dat.exe and invoking it via command/shell strings embedded in the binary (evidence: decompile and function_evidence for 0x401080).
```

## Bulk Processing Operations

### Bulk Function Renamer

<img width="1200" height="850" alt="image" src="https://github.com/user-attachments/assets/f6e0262f-4fb8-407a-8989-dbb210e95bf6" />


A high-throughput batch processor for autonomous function renaming, constrained strictly by behavioral evidence derived from decompiled pseudocode.

1. Populate the processing queue by filtering functions via naming patterns, cross-reference counts, or export status.
2. Select the target rows and execute **Analyze Selected Function**.
3. Evaluate the generated proposals, noting the confidence score and algorithmic rationale.
4. Authorize valid proposals via **Apply Renames**.

### Bulk Variable Renamer

<img width="1302" height="932" alt="image" src="https://github.com/user-attachments/assets/dd571f95-b89d-4952-8042-85c365d52d0d" />

Applies batch renaming logic to local variables across multiple functions.

1. Populate the processing queue and select target rows.
2. Execute **Start Variable Rename**.
3. Review the per-function mappings and identify any decompilation errors.
4. Authorize valid mappings via **Apply Suggestions**.

## Symbol Resolution

<img width="388" height="168" alt="image" src="https://github.com/user-attachments/assets/a0327f18-19fa-4c86-872f-8932371c6cc3" />

### Function Renaming (`Ctrl+Alt+N` / `Ctrl+Alt+M`)

*   **Code Context (`Ctrl+Alt+N`):** Prioritizes algorithmic logic and standard application behavior. Optimal for standard library functions and benign routines.
*   **Malware Context (`Ctrl+Alt+M`):** Enforces a threat intelligence context, prompting the AI to identify evasion techniques, C2 structures, and malicious intent.

### Variable Renaming (`Ctrl+Alt+R`)

1. Open the target function in the pseudocode view.
2. Execute **Suggest Variable Name**.
3. Review the proposed `current_name -> new_name` mapping table.
4. Reject invalid proposals and execute **Apply Selected**.

## Automated Documentation

### Pseudocode Comments (`Ctrl+Alt+C`)

Executes an analysis of the decompiled logic and injects explanatory inline comments at critical execution junctures. These are registered as Hex-Rays user comments.

### Disassembly Section Comments

Available exclusively in the IDA-View. Organizes assembly instructions into logical blocks and applies descriptive summary comments. Supports targeted analysis of specific instruction ranges via selection prior to invocation.
