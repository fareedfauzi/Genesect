# Genesect

**An AI-powered IDA Pro plugin built for reverse engineers and malware analysts.**

Genesect is an IDA Pro plugin for practical reverse engineering and malware analysis. It takes the grunt work out of reverse engineering by integrating Large Language Models (LLMs) directly into IDA Pro and the Hex-Rays decompiler. It assists analysts with tasks such as renaming functions and variables, explaining complex or obscure code, recovering structures, and generating comprehensive analysis reports.

Inspired by the Gepetto IDA plugin, Genesect takes the concept further - essentially Gepetto on steroids - with additional capabilities designed for practical malware analysis and large-scale reverse engineering.

Whether you're triaging a massive binary or performing a deep dive into a specific execution chain, Genesect provides an interactive, AI-assisted workflow directly inside your IDA Pro workspace.

## What's in the box?

* **Agentic Investigation:** Hand the AI a mission (like "Find the C2 config logic") and watch it autonomously traverse the call graph, analyze evidence, and synthesize findings into a structured report.
* **Deep Analysis Pipeline:** Point it at an entry function and let it recursively build a call graph, rename everything bottom-up, and spit out a beautiful HTML report.
* **Bulk Processing Engine:** Feed it hundreds of unnamed functions or variables and let it batch-rename them based on behavioral heuristics.
* **Contextual AI Chat:** A dockable chat interface that actually understands the function you're currently looking at.
* **Tons of Explorers:** Dedicated static analysis utilities for spotting anti-analysis tricks, process injection, dynamic API resolution, crypto routines, and more.

## Installation

Genesect runs independently from older installations, so you can safely install it without overwriting existing analysis data.

### 1. Install Dependencies

You'll need a few Python packages installed in whatever Python environment IDA is using:

```bash
pip install openai httpx PySide6
```

*(Optional: Install `anthropic` and `google-generativeai` if you want Claude or Gemini support).*

### 2. Install the Plugin

**Quick Install (Windows):**

```powershell
irm https://raw.githubusercontent.com/fareedfauzi/Genesect-Extended/main/install.ps1 | iex
```

**Quick Install (Linux / macOS):**

```bash
curl -fsSL https://raw.githubusercontent.com/fareedfauzi/Genesect-Extended/main/install.sh | bash
```

**Manual Install:**

Clone the repository:

```bash
git clone https://github.com/fareedfauzi/Genesect-Extended.git
cd Genesect-Extended
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
* [**Utilities & Explorers**](docs/utilities.md) - Guides on the Hex Viewer, Call Tree, and malware explorers.
* [**Analysis Pipelines**](docs/pipelines.md) - Under the hood of the Deep & Bulk Analyzers.

## Credit
- Codex
- Rohitab Batra for the Windows API dictionary
