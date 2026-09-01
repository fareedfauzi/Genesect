# PseudoNote Extended

**An AI-powered IDA Pro plugin built for reverse engineers and malware analysts.**

PseudoNote Extended takes the grunt work out of reverse engineering. It hooks up Large Language Models directly to IDA Pro's Hex-Rays decompiler to help you rename functions, explain obscure code, recover structures, and generate comprehensive analysis reports. 

Whether you're triaging a massive binary or doing a deep dive into a specific execution chain, this plugin gives you an interactive, AI-driven assistant right in your workspace. Best of all? Everything it generates—notes, symbol renames, AI chats—is saved straight into the IDB using IDA's native NetNodes, so you never lose your progress.

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

## A Note on Safety

By default, the AI starts in read-only mode. We made sure that any IDB-altering actions (like renaming symbols or adding comments) require your explicit approval first. 

*Always remember: AI outputs are educated guesses. Trust, but verify against the actual assembly.*
