# Installation and Workspace Initialization

## 1. Dependency Resolution

Genesect requires a standardized Python environment. All dependencies must be installed within the Python interpreter utilized by your IDA Pro installation.

Execute the following command in your terminal:

```bash
pip install openai httpx PySide6
```

*(Optional: Install `anthropic` and `google-generativeai` to enable support for Claude and Google Gemini API endpoints).*

### Linux Environment Considerations

IDA Pro natively utilizes the system-wide Python environment. Modern Linux distributions (e.g., Debian 12+, Ubuntu 23.04+) enforce PEP 668, blocking system-wide `pip` installations to prevent package manager conflicts.

**Method A: Direct Installation via Pip (Recommended for Analysis VMs)**  
Append the override flag to force installation into the system environment:

```bash
pip install openai httpx PySide6 --break-system-packages
```

**Method B: Installation via System Package Manager (Debian/Ubuntu)**  
Install the dependencies using `apt` if they are available in your distribution's repository:

```bash
sudo apt update
sudo apt install python3-httpx python3-openai python3-pyside6.qtcore python3-pyside6.qtgui python3-pyside6.qtwidgets
```

## 2. Plugin Installation

### Windows Environments

**Quick Install (PowerShell):**
```powershell
irm https://raw.githubusercontent.com/fareedfauzi/Genesect-Extended/main/install.ps1 | iex
```

Alternatively, to install from a local repository clone, navigate to the project directory and execute the batch installer:

```bat
install.bat
```

The local installer dynamically resolves the target directory, prioritizing `%IDAUSR%\plugins` if defined, falling back to `%APPDATA%\Hex-Rays\IDA Pro\plugins`. To force local installation into a specific directory, provide the absolute path as an argument:

```bat
install.bat "C:\Path\To\IDA\plugins"
```

### Manual Installation

Clone the repository:

```bash
git clone https://github.com/fareedfauzi/Genesect-Extended.git
cd Genesect-Extended
```

Copy the plugin entry file and package directory into your IDA user plugins folder:

```text
Genesect.py
genesect/
```

Default plugin folders:

```text
Windows: %APPDATA%\Hex-Rays\IDA Pro\plugins
Linux:   ~/.idapro/plugins
macOS:   ~/Library/Application Support/Hex-Rays/IDA Pro/plugins
```

If you configured `IDAUSR`, copy both items into `IDAUSR/plugins` instead.

Windows PowerShell example:

```powershell
$Plugins = "$env:APPDATA\Hex-Rays\IDA Pro\plugins"
New-Item -ItemType Directory -Force -Path $Plugins | Out-Null
Copy-Item -Force .\Genesect.py $Plugins
Copy-Item -Recurse -Force .\genesect $Plugins
```

### Linux and macOS Environments

**Quick Install (Shell):**
```sh
curl -fsSL https://raw.githubusercontent.com/fareedfauzi/Genesect-Extended/main/install.sh | bash
```

Alternatively, to install from a local repository clone, execute the shell installer script:

```sh
sh install.sh
```

The local script respects the `$IDAUSR` environment variable. Default fallbacks are `~/.idapro/plugins` (Linux) and `~/Library/Application Support/Hex-Rays/IDA Pro/plugins` (macOS).

Linux example:

```sh
mkdir -p ~/.idapro/plugins
cp -f Genesect.py ~/.idapro/plugins/
rm -rf ~/.idapro/plugins/genesect
cp -R genesect ~/.idapro/plugins/
```

macOS example:

```sh
mkdir -p "$HOME/Library/Application Support/Hex-Rays/IDA Pro/plugins"
cp -f Genesect.py "$HOME/Library/Application Support/Hex-Rays/IDA Pro/plugins/"
rm -rf "$HOME/Library/Application Support/Hex-Rays/IDA Pro/plugins/genesect"
cp -R genesect "$HOME/Library/Application Support/Hex-Rays/IDA Pro/plugins/"
```

**Ensure IDA Pro is restarted following a successful installation.**

## 3. Configuration Parameters

Settings are managed via the context menu: **Right-Click > Genesect > Settings**.

1. Navigate to the **AI Assistant** tab to select the target AI provider.
2. Supply the necessary connection parameters (Base URL, Model Name, API Key).
3. Tune operational parameters including request timeout limits, maximum output tokens, and proxy settings.
4. Execute **Test Connection** to validate the endpoint reachability and authentication.
5. Save the configuration. Changes are immediately applied to the runtime client.

**Note:** Local providers (e.g., LM Studio, Ollama) may operate without an API key, whereas remote enterprise endpoints will require valid authentication tokens. If the plugin lacks write access to the IDA installation directory, configuration state will safely fallback to `~/.genesect.ini`.

Additional configuration tabs dictate UI rendering (fonts, syntax highlighting), concurrent worker limits, batch processing sizes, API rate-limit cooldowns, and behavioral parameters for the Deep Analyzer.

## 4. Workspace Management

### Readable Code Reconstruction

Navigate to a target function and invoke **AI Assistant > Analyst Notes > Open Readable Code**.

This interface facilitates the generation of high-level, human-readable C (or other targeted languages) via AI-driven reconstruction of the Hex-Rays pseudocode. The generated code is persistently stored within the IDB and serves as an analytical aid.

### Analyst Documentation

Invoke **Open Analyst Notes** to instantiate a per-function Markdown editor.

This facility allows analysts to document hypotheses, record Indicators of Compromise (IOCs), and maintain contextual notes directly tied to the function's address within the IDB. The interface supports standard Markdown formatting and live preview rendering.

### Artifact Retrieval

The **Browse Saved Artifacts** utility enumerates all functions within the IDB that contain saved readable code or analyst notes, providing a centralized index for rapid navigation across documented components.

## 5. Legacy Data Migration

For users migrating from an older installation, execute the **Migrate Legacy Data...** utility.

1. Ensure the IDB is backed up prior to execution.
2. Review the enumerated legacy artifacts.
3. Initiate the migration sequence to transfer data into the Extended namespace.
4. Verify the integrity of the migrated readable code and notes within the new workspace interfaces.
