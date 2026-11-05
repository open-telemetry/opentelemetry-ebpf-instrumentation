# AI Tooling

This document provides recommendations for contributors who use coding agents when working in this repository.

## Versioning and compatibility

Follow the [compatibility check in AGENTS.md](../AGENTS.md#compatibility-check)
for contribution requirements and [AI-POLICY.md](../AI-POLICY.md) for contributor
responsibilities. This document covers tool setup and instruction verification.

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

### Check compatibility decisions

After changing compatibility instructions, use a fresh session to ask the agent
to assess representative PRs without editing files. Compare its reasoning with
[VERSIONING.md](../VERSIONING.md) and the relevant surface contract, including
cases that should be accepted as well as rejected. For example:

| Proposed change | Expected assessment |
| --- | --- |
| Rename a metric classified as stable in a prior v1 release in the next v1 minor release, with a schema transformation provided. | Block the rename under the stable telemetry contract; the transformation does not waive the release rules. |
| Rename a metric classified as development in a v1 minor release, with no effect on stable telemetry or other protected contracts. | The telemetry contract permits the rename; check the required schema transformation, release documentation, and relevant validation. |
| Correct a spelling error in documentation without changing a documented contract. | Patch-compatible; a one-sentence compatibility assessment and Markdown validation suffice. |

Instruction-loading checks and Markdown lint do not establish that an agent will
make these decisions reliably. Record actual responses and limitations when
reporting a behavioral check.
