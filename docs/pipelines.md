# Analysis Pipelines

PseudoNote Extended implements two primary automated analysis engines: the Deep Analyzer and the Bulk Analyzer. 

*   **Bulk Analyzer:** Optimized for rapid, breadth-first triage of the entire binary.
*   **Deep Analyzer:** Optimized for thorough, depth-first analysis of a specific execution chain.

## Bulk Function Analyzer Pipeline

The Bulk Function Analyzer is designed to quickly classify every function within a binary against established malware behavior profiles.

### Execution Flow

1.  **Function Enumeration:** The engine scans the IDB and retrieves all defined functions.
2.  **Filtration:** System libraries, API thunks, and null-code functions are optionally excluded based on configuration parameters.
3.  **Static Pre-Classification:** Functions are evaluated against a localized static taxonomy (`malware_api_tags.json`). This heuristic phase identifies known-malicious Windows API combinations without requiring an external AI request.
4.  **Batch AI Processing:** Functions are grouped into configurable batches. The decompiled pseudocode, string references, and API call lists are transmitted to the AI provider.
5.  **State Application:** The analytical verdict (Tag, Confidence Score, and Rationale) is populated in the user interface and committed to the IDB via NetNodes.
6.  **Fault Tolerance:** Requests resulting in timeouts or API rate-limit errors are automatically requeued for execution.

## Deep Analyzer Pipeline

The Deep Analyzer executes a comprehensive, multi-stage recursive analysis originating from a user-defined entry point. It constructs a call graph, performs bottom-up symbolic renaming, conducts behavioral analysis, and synthesizes a standalone HTML report.

### Phase 1: Discovery & Preparation

*   **Stage 1: Workspace Initialization**
    Creates isolated workspace directories adjacent to the IDB. Validates AI provider configuration, checks dependencies, and establishes the operational environment.
*   **Stage 2: Graph Construction**
    Recursively traverses the cross-reference engine originating from the entry point. Constructs a deterministic `FuncNode` graph detailing caller/callee relationships, execution depth, and library boundaries.
*   **Stage 3: Symbolic Normalization (Bottom-Up)**
    Executes the Bulk Variable and Bulk Function renaming engines sequentially, starting from leaf functions. This ensures that when a caller is analyzed, its callees have already been semantically named.

### Phase 2: Contextual Analysis & Reporting

*   **Stage 4: Code Reconstruction & Baseline Assessment**
    Translates the Hex-Rays pseudocode into high-level, readable C. Executes a preliminary behavioral assessment to assign risk tags (`malicious`, `suspicious`, `benign`) and extract initial indicators.
*   **Stage 5: Contextual Refinement**
    Re-evaluates each function utilizing the behavioral context derived from its callers. This stage upgrades benign-looking utility functions called maliciously, downgrades false positives, and propagates behavioral intent across the execution chain.
*   **Stage 6: Data Synthesis**
    Aggregates the analytical output, extracts functional Indicators of Compromise (IOCs), maps behaviors to the MITRE ATT&CK framework, and generates the data structures required for visualization.
*   **Stage 7: Analysis Report Generation**
    Compiles a self-contained HTML report detailing the executive summary, MITRE ATT&CK coverage, function-level risk assessments, extracted IOCs, and interactive control flow diagrams. The report is deposited in the initialized workspace directory.

## Pipeline Comparison

| Specification | Bulk Function Analyzer | Deep Analyzer |
|---|---|---|
| **Objective** | Breadth-first triage and classification | Depth-first deep investigation |
| **Operational Scope** | Flat enumeration of all IDB functions | Bounded recursive graph from entry point |
| **Analytical Depth** | Single-pass evaluation | Multi-stage contextual refinement |
| **Variable Renaming** | No | Yes (Bottom-up) |
| **Code Reconstruction** | No | Yes (Readable C generation) |
| **Persistence Output** | IDB Tags and UI population | IDB modifications, disk artifacts, HTML Report |
| **Execution Velocity** | High (Parallel batch processing) | Low (Sequential, thorough analysis) |
