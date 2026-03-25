# PR Review Instructions

When reviewing pull requests in this repository, prioritize signs of contributor ownership and repository-specific understanding.

Use AGENTS.md and CONTRIBUTING.md as the source of truth for expected code quality, structure, and contribution behavior.

Flag pull requests when you see one or more of these patterns:

- The PR description is generic, plan-like, or tool-generated in tone, and does not explain why this approach fits this repository.
- The change duplicates existing utilities, helpers, abstractions, or patterns instead of reusing them.
- The PR scope is broader than necessary for the stated problem.
- The change introduces unrelated cleanup, comments, abstractions, or refactors.
- The code does not follow existing repository structure or subsystem boundaries.
- Validation appears incomplete for the files being changed.
- Follow-up revisions appear to apply reviewer feedback mechanically without integrating it coherently into the surrounding code.

When you flag these issues:

- Be direct and explicit.
- Ask for repository-specific rationale.
- Ask why existing code was not reused when applicable.
- Ask for a smaller and more focused change when scope is too large.
- Ask for confirmation of local validation steps.

Prefer asking concrete questions over making vague suggestions.

Do not object merely because AI may have been used. Object when the PR shows weak ownership, weak understanding, duplication, unnecessary abstraction, or poor integration with the existing codebase.
