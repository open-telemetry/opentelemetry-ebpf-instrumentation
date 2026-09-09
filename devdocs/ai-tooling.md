# AI Tooling

This document provides recommendations for contributors who use coding agents when working in this repository.

## DeepWiki

DeepWiki is useful for fast architecture lookup, codebase orientation, and identifying likely areas to inspect before reading the repository in detail.

Repository page:

- [OpenTelemetry eBPF Instrumentation on DeepWiki](https://deepwiki.com/open-telemetry/opentelemetry-ebpf-instrumentation)

MCP endpoint:

- `https://mcp.deepwiki.com/mcp`

## Codex

Codex supports MCP servers through the shared Codex CLI and IDE configuration.

Add DeepWiki with the CLI:

```sh
codex mcp add deepwiki --url https://mcp.deepwiki.com/mcp
```

## Claude

Claude Code supports remote HTTP MCP servers directly.

Add DeepWiki as a user-scoped MCP server:

```sh
claude mcp add --transport http --scope user deepwiki https://mcp.deepwiki.com/mcp
```

## Verify repository instructions

Agent tools may load or cache instruction files when a session starts. After
changing one, start a new session or restart the current session when the tool
does not automatically reload instructions.

- **Codex:** In a new task rooted in this repository, ask Codex to list and
  summarize the instruction files it loaded. `AGENTS.md` applies to Codex agent
  workflows, not unrelated editor autocomplete.
- **Claude Code:** Run `/context` and inspect the memory files. `CLAUDE.md` and
  the files it imports should be listed. These instructions apply to Claude
  Code sessions.
- **GitHub Copilot:** In Copilot CLI, run `/instructions`. In other supported
  Copilot chat or coding-agent surfaces, inspect the cited instruction files in
  the response. Support varies by surface; inline completion does not
  necessarily use these instructions.
- **Cursor:** In an Agent or Chat session, inspect the active rules in the Agent
  sidebar and confirm that `AGENTS.md` is included. These instructions do not
  necessarily apply to tab completion.
