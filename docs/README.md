# PseudoNote Extended Documentation

This documentation details the functionality and operational procedures for the PseudoNote Extended plugin within IDA Pro. The primary interface is accessible via the context menu (Right-Click > PseudoNote) in both the Pseudocode and Disassembly views.

The toolset is categorized into four primary domains: Settings, AI Assistant, Utilities, and a customizable Bookmarks submenu for rapid access to frequently used commands.

## Documentation Index

1. [**Getting Started**](getting-started.md)
   - Dependency installation for Windows, Linux, and macOS
   - AI provider configuration
   - Workspace initialization
   - Legacy data migration procedures

2. [**Features Overview**](features-overview.md)
   - Comprehensive action registry
   - Keyboard shortcuts and view context requirements

3. [**AI Assistant Workflows**](ai-assistant.md)
   - Interactive analysis via the Chat interface
   - Autonomous Function Investigation
   - Bulk symbol and variable renaming procedures
   - Automated code commenting and prototype inference

4. [**Utilities & Explorers**](utilities.md)
   - Navigational aids including the Hex Viewer and Call Tree
   - Structural and malware-specific static analysis explorers
   - Signature generation and external pivoting utilities

5. [**Analysis Pipelines**](pipelines.md)
   - Architecture and execution flow of the Deep Analyzer
   - Architecture and execution flow of the Bulk Analyzer

## Operational Paradigm

1. Allow IDA Pro's initial auto-analysis to conclude before invoking complex plugin operations.
2. Ensure the AI provider is properly configured and tested via the Settings menu prior to analysis.
3. Utilize the Chat interface or Autonomous Investigation for preliminary triage of complex functions.
4. Maintain a read-only stance for all AI-driven tools until the generated proposals (names, types, comments) have been manually reviewed.
5. Utilize the built-in Change History and Undo Explorer to manage and revert modifications to the IDB.

## Security Model & Data Integrity

- **Validation Requirement:** All AI-generated outputs are heuristic proposals. They must be validated against the underlying assembly, cross-references, and runtime data before acceptance.
- **Explicit Modification:** Autonomous agents and batch processors operate in a read-only capacity by default. State mutations within the IDB require explicit configuration and analyst review.
- **External Communications:** Search pivots and external querying tools transmit selected data to third-party services. Analysts must verify that selected data does not violate operational security policies prior to transmission.
- **Static Analysis Constraints:** Features such as shellcode analysis and string/byte inspection operate purely via static analysis and do not execute code on the host system.

## Terminology Reference

- **Current Function:** The subroutine currently containing the cursor focus when an action is invoked.
- **Function Chain:** A deterministic graph of callers and callees, bounded by depth and node limits, originating from an entry function.
- **IDB:** The primary IDA Pro database file, serving as the persistent storage mechanism for both native analysis data and PseudoNote Extended artifacts (via NetNodes).
- **Reviewed Change:** A modification to the IDB that has been explicitly authorized by the analyst following AI suggestion.
