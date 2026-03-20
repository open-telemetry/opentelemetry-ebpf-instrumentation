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
