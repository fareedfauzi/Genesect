# Installation, settings, and workspace

## Install on Windows

From the project directory, run:

```bat
install.bat
```

The portable installer uses `%IDAUSR%\plugins` when `IDAUSR` is defined; otherwise it uses `%APPDATA%\Hex-Rays\IDA Pro\plugins`. To install into a particular copy of IDA, pass its plugin directory:

```bat
install.bat "D:\Tools\IDA\plugins"
```

The fixed-path `install_pseudonote_extended_ida83.bat` and `install_pseudonote_extended_ida93.bat` scripts are retained for local testing.

## Install on Linux or macOS

```sh
sh install.sh
```

The script honors `$IDAUSR`. Without it, the default is `~/.idapro/plugins` on Linux and `~/Library/Application Support/Hex-Rays/IDA Pro/plugins` on macOS. A custom plugin directory can be passed as the first argument.

Restart IDA after installing or updating the plugin.

## Settings

Settings appears directly under **right-click > PseudoNote > Settings**. Use its **Bookmarks** tab to search all features and choose the shortcuts shown under **PseudoNote > Bookmarks**. The AI Assistant and Utilities trees remain the complete organized feature catalog.

Open **right-click > PseudoNote > AI Assistant > Settings...**.

1. Select the provider.
2. Enter its base URL, model, and API key when the provider requires one.
3. Adjust timeout, output-token limit, retry behavior, and proxy if necessary.
4. Click **Test Connection**.
5. Click **Save**. The runtime AI client is rebuilt immediately; restarting IDA is not required.

Local OpenAI-compatible servers such as LM Studio and Ollama may not require a real API key. Settings can be saved without a key, although hosted services normally require one to make requests.

The remaining Settings tabs control fonts, workspace appearance, bulk worker counts, batch sizes, cooldowns, naming behavior, and Deep Analyzer options. A cooldown of `0` disables PseudoNote's deliberate inter-request delay; provider-side HTTP 429 responses may still require retry backoff.

## Open Readable Code

Use **AI Assistant > Analyst Notes > Open Readable Code** on the current function.

1. Choose the source view or generated-code tab.
2. Generate a readable C rewrite when desired.
3. Review the result and save it to the IDB.
4. Use the language selector and editor for manual refinement.

Generated code is an analyst aid, not a replacement for the original Hex-Rays output.

## Open Analyst Notes

Use **Open Analyst Notes** to maintain per-function Markdown notes.

1. Navigate to a function.
2. Enter observations, hypotheses, IOCs, or follow-up items.
3. Save the note; it is stored in the IDB for that function.
4. Switch between edit and preview modes as needed.

The Explanation, Execution Flow, Function Intelligence, and Custom Prompt tabs provide additional function-focused AI workflows. Custom Prompt can include pseudocode, assembly, or both.

## Browse Saved Artifacts

Use **Browse Saved Artifacts** to find functions with saved readable code or analyst notes.

1. Open the artifact list.
2. Search or select a saved item.
3. Navigate to its function and reopen the corresponding workspace.

## Migrate Classic PseudoNote Data

If the migration command is exposed by your build, run **Migrate Classic PseudoNote Data...** once on a backed-up IDB.

1. Review the detected legacy data.
2. Start migration.
3. Verify readable code and notes in the Extended workspaces.
4. Retain the original IDB until verification is complete.

## UI Component Preview

**UI Component Preview...** is primarily a theme/development aid. It displays shared buttons, fields, states, and typography without changing the IDB.
