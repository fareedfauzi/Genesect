# PseudoNote Extended

**An AI-powered IDA Pro plugin built for reverse engineers and malware analysts.**

PseudoNote Extended is an extended version of previous PseudoNote I created. It takes the grunt work out of reverse engineering by integrating Large Language Models (LLMs) directly into IDA Pro and the Hex-Rays decompiler. It assists analysts with tasks such as renaming functions and variables, explaining complex or obscure code, recovering structures, and generating comprehensive analysis reports.

Inspired by the Gepetto IDA plugin, PseudoNote takes the concept further - essentially Gepetto on steroids - with additional capabilities designed for practical malware analysis and large-scale reverse engineering.

Whether you're triaging a massive binary or performing a deep dive into a specific execution chain, PseudoNote provides an interactive, AI-assisted workflow directly inside your IDA Pro workspace.

## What's in the box?

* **Agentic Investigation:** Hand the AI a mission (like "Find the C2 config logic") and watch it autonomously traverse the call graph, analyze evidence, and synthesize findings into a structured report.
* **Deep Analysis Pipeline:** Point it at an entry function and let it recursively build a call graph, rename everything bottom-up, and spit out a beautiful HTML report.
* **Bulk Processing Engine:** Feed it hundreds of unnamed functions or variables and let it batch-rename them based on behavioral heuristics.
* **Contextual AI Chat:** A dockable chat interface that actually understands the function you're currently looking at.
* **Tons of Explorers:** Dedicated static analysis utilities for spotting anti-analysis tricks, process injection, dynamic API resolution, crypto routines, and more.

## Installation

PseudoNote Extended runs completely independent of the classic PseudoNote plugin, so you can safely install them side-by-side.

### 1. Install Dependencies

You'll need a few Python packages installed in whatever Python environment IDA is using:

```bash
pip install openai httpx PySide6
```

*(Optional: Install `anthropic` and `google-generativeai` if you want Claude or Gemini support).*

### 2. Install the Plugin

**Quick Install (Windows):**

```powershell
irm https://raw.githubusercontent.com/fareedfauzi/PseudoNote-Extended/main/install.ps1 | iex
```

**Quick Install (Linux / macOS):**

```bash
curl -fsSL https://raw.githubusercontent.com/fareedfauzi/PseudoNote-Extended/main/install.sh | bash
```

*(If you prefer to install manually from a local clone, just run `install.bat` or `sh install.sh` directly from the repo).*

Restart IDA Pro once it's done!

## Configuration

To hook up your API keys, just right-click anywhere in the Pseudocode or IDA-View windows and hit **PseudoNote > Settings**.

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
