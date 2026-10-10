<img width="1672" height="941" alt="Genesect Banner" src="https://github.com/user-attachments/assets/bf3db3fe-e0e7-4244-adbe-11bab2783acf" />

# Genesect

**An AI-powered IDA Pro plugin built for reverse engineers and malware analysts.**

Genesect is an IDA Pro plugin for practical reverse engineering and malware analysis. It takes the grunt work out of reverse engineering by integrating Large Language Models (LLMs) directly into IDA Pro and the Hex-Rays decompiler. It assists analysts with tasks such as renaming functions and variables, explaining complex or obscure code, recovering structures, and generating comprehensive analysis reports.

Genesect is the upgraded successor to [fareedfauzi/PseudoNote](https://github.com/fareedfauzi/PseudoNote), which is now archived and kept for reference only.

Inspired by the Gepetto IDA plugin, Genesect extends that workflow with practical malware-analysis, batch-processing, and modern language triage features for large reverse-engineering projects.

Whether you're triaging a massive binary or performing a deep dive into a specific execution chain, Genesect provides an interactive, AI-assisted workflow directly inside your IDA Pro workspace.

## What's in the box?

* **Agentic Investigation:** Hand the AI a mission (like "Find the C2 config logic") and watch it autonomously traverse the call graph, analyze evidence, and synthesize findings into a structured report. Compact skill routing keeps the agent focused on malware RE, IOC extraction, unpacking, Go/Rust user-code recovery, or C++ virtual dispatch when the task calls for it.
* **Deep Analysis Pipeline:** Point it at an entry function and let it recursively build a call graph, rename everything bottom-up, and spit out a beautiful HTML report.
* **Bulk Processing Engine:** Feed it hundreds of unnamed functions or variables and let it batch-rename them based on behavioral heuristics.
* **Contextual AI Chat:** A dockable chat interface that actually understands the function you're currently looking at.
* **Go and Rust Triage:** GoReSym integration, Go package organization, Go/Rust user-code mapping, Rust binary triage, Rust symbol demangling, Rust string display fixups, and optional RIFT library signature workflows.
* **Malware Analysis Explorers:** Dedicated static analysis utilities for spotting anti-analysis tricks, process injection, dynamic API resolution, crypto routines, callback dispatch, COM usage, C2/protocol behavior, and more.
* **AI Workspace Export:** Build a local folder of decompilation, disassembly, callgraphs, strings, imports, Go/Rust evidence, recovered virtual-class data, triage routing, malware RE skills, and IOC/reporting guidance for project-level AI review outside IDA.

## Installation

Genesect runs independently from older installations, so you can safely install it without overwriting existing analysis data.

### 1. Install Dependencies

You'll need a few Python packages installed in whatever Python environment IDA is using:

```bash
pip install openai httpx PySide6
```

*(Optional: Install `anthropic` and `google-generativeai` if you want Claude or Gemini support. FLOSS, GoReSym, rustfilt, and RIFT are optional external tools used only by their matching utilities.)*

### 2. Install the Plugin

**Quick Install (Windows):**

```powershell
irm https://raw.githubusercontent.com/fareedfauzi/Genesect/main/install.ps1 | iex
```

**Quick Install (Linux / macOS):**

```bash
curl -fsSL https://raw.githubusercontent.com/fareedfauzi/Genesect/main/install.sh | bash
```

**Manual Install:**

Clone the repository:

```bash
git clone https://github.com/fareedfauzi/Genesect.git
cd Genesect
```

Copy these into your IDA user plugins folder:

```text
Genesect.py
genesect/
```

Common IDA user plugin folders:

```text
Windows: %APPDATA%\Hex-Rays\IDA Pro\plugins
Linux:   ~/.idapro/plugins
macOS:   ~/Library/Application Support/Hex-Rays/IDA Pro/plugins
```

If you use a custom `IDAUSR`, copy them into `IDAUSR/plugins` instead.

*(If you prefer a local installer from a clone, run `install.bat` on Windows or `sh install.sh` on Linux/macOS).*

Restart IDA Pro once it's done!

## Configuration

To hook up your API keys, just right-click anywhere in the Pseudocode or IDA-View windows and hit **Genesect > Settings**.

From there, you can select your provider (OpenAI, LM Studio, Ollama, DeepSeek, etc.), plug in your endpoint/key, and hit **Test Connection**. Your settings take effect immediately upon saving.

## Documentation

Want to dig deeper? Check out the [`docs/`](docs/) folder for all the details:

* [**Getting Started**](docs/getting-started.md) - Full installation steps, troubleshooting, and IDB migration.
* [**Features & Hotkeys**](docs/features-overview.md) - A cheat sheet of every action and shortcut.
* [**AI Assistant Workflows**](docs/ai-assistant.md) - How to use the chat, autonomous agent, and bulk renamers.
* [**Utilities & Explorers**](docs/utilities.md) - Guides on the Hex Viewer, Call Tree, Go/Rust workflows, malware explorers, and external pivots.
* [**Analysis Pipelines**](docs/pipelines.md) - Under the hood of the Deep & Bulk Analyzers.

## Credit
- Codex
- Rohitab Batra for the Windows API dictionary
