# PseudoNote Extended

PseudoNote Extended is an advanced, AI-powered reverse engineering plugin for IDA Pro. Engineered specifically for malware analysts and reverse engineers, it accelerates the analysis process by automating symbol renaming, behavior explanation, code reconstruction, and forensic reporting.

By combining the analytical depth of large language models with the precision of IDA Pro's Hex-Rays decompiler, PseudoNote Extended provides an interactive and autonomous environment for binary analysis. All generated artifacts—including AI analysis, renamed symbols, investigator notes, and chat histories—are persistently stored within the IDA database (IDB) using native NetNodes.

## Architecture & Core Capabilities

PseudoNote Extended is built on a modular architecture that separates static analysis heuristics from AI-driven contextual analysis.

* **Agentic Investigation:** An autonomous analysis engine that systematically investigates functions, gathers evidence across callers and callees, evaluates memory evidence, and synthesizes findings into a structured report.
* **Deep Analysis Pipeline:** A recursive, bottom-up analysis pipeline that constructs a complete call graph, renames leaf functions before callers, and generates a comprehensive HTML forensic report.
* **Bulk Processing Engine:** Multi-threaded batch processing for renaming functions and variables at scale, as well as triaging functions based on established malware behavior classifications.
* **Contextual Chat & Summarization:** A dockable, context-aware interface that enables conversational queries regarding specific functions or bounded execution chains.
* **Specialized Explorers:** Dedicated static analysis utilities for identifying anti-analysis techniques, process injection, command-and-control structures, dynamic API resolution, and cryptographic routines.

## Installation

PseudoNote Extended is designed to run alongside classic PseudoNote without namespace collisions.

### Prerequisites

Ensure you have the required Python dependencies installed in the Python environment utilized by your IDA Pro installation:

```bash
pip install openai httpx PySide6
```

*(Optional: Install `anthropic` and `google-generativeai` to enable Claude and Gemini provider support).*

### Setup Instructions

**Windows environments:**
Execute the provided batch script from the project root:

```bat
install.bat
```

To specify a custom IDA plugin directory:

```bat
install.bat "C:\Path\To\IDA\plugins"
```

**Linux and macOS environments:**
Execute the shell script from the project root:

```sh
sh install.sh
```

Restart IDA Pro after the installation completes.

## Configuration

Settings are accessible via the context menu in the Pseudocode or IDA-View windows: **Right-Click > PseudoNote > Settings**.

1. Navigate to the **AI Assistant** tab.
2. Select your preferred provider (OpenAI, LM Studio, Ollama, DeepSeek, etc.).
3. Input the required endpoint URL, model identifier, and API key.
4. Execute **Test Connection** to validate the configuration.
5. Click **Save** to apply changes immediately.

## Documentation Reference

Comprehensive documentation and detailed workflows are located in the `docs/` directory:

* [**Getting Started**](docs/getting-started.md) - System requirements, detailed installation procedures, and workspace initialization.
* [**Features Overview**](docs/features-overview.md) - Action registry, context availability, and default keyboard shortcuts.
* [**AI Assistant Workflows**](docs/ai-assistant.md) - Methodologies for interactive chat, autonomous investigation, and automated renaming.
* [**Utilities & Explorers**](docs/utilities.md) - Documentation on the Hex Viewer, Call Tree, and specialized static analysis explorers.
* [**Analysis Pipelines**](docs/pipelines.md) - Architectural overview of the Deep Analyzer and Bulk Analyzer pipelines.
