# PseudoNote Extended tutorials

These guides explain the features available from the **right-click > PseudoNote** menu in IDA. Its root contains **Settings**, **AI Assistant**, **Utilities**, and a configurable **Bookmarks** submenu. Some commands are view-specific: pseudocode actions require a Hex-Rays pseudocode window, while byte-selection actions require a selection in the disassembly view.

## Start here

1. [Installation, settings, and workspace](getting-started.md) — install the plugin, configure an AI provider, migrate classic data, and use notes and saved artifacts.
2. [AI assistant tutorials](ai-assistant.md) — chat, autonomous investigation, summarization, bulk workflows, renaming, types, and comments.
3. [Utility tutorials](utilities.md) — navigation, program-structure explorers, malware-analysis explorers, search, export, and IDB maintenance.

## Recommended first workflow

1. Open a binary and wait for IDA auto-analysis to finish.
2. Right-click in pseudocode and select **PseudoNote > AI Assistant > Settings...**.
3. Configure and test an AI provider, then save. Saved provider changes take effect immediately.
4. Open **Chat About This Function** for interactive analysis, or **Autonomous Investigation** for a bounded multi-step investigation.
5. Keep **Enable IDA changes** off until you are ready to review proposed names, types, or comments.
6. Use **Change History and Undo Explorer** to inspect and selectively roll back recorded changes.

## Safety model

- Treat AI output as a hypothesis until verified against pseudocode, disassembly, cross-references, and data.
- Autonomous Investigation starts read-only. IDA-changing tools require explicit enablement and review.
- Bulk tools show proposals or results before database changes whenever the underlying IDA API permits it.
- External pivot searches open third-party services and may disclose the selected text or bytes to those services.
- String decoding and shellcode features are static-analysis helpers; do not execute untrusted samples on a production system.

## Terminology

- **Current function**: the function containing the cursor when a command starts.
- **Function chain**: a bounded caller/callee graph rooted at an entry function.
- **IDB**: IDA's analysis database containing names, types, comments, and PseudoNote artifacts.
- **Reviewed change**: an IDA mutation explicitly accepted by the analyst.
