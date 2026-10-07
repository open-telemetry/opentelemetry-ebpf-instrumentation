---
name: code-review
description: Review OBI pull requests for correctness, compatibility, and adherence to repository conventions. Use when performing a pull request review in this repository.
---

# OBI code review

All paths below are relative to the repository root.

Read `AGENTS.md`, `CONTRIBUTING.md`, and `.github/copilot-instructions.md`.
Apply files under `.github/instructions/` whose `applyTo` patterns match
changed files. Consult `devdocs/pipeline-map.md` when tracing behavior
across pipeline stages.

Establish the intended behavior from the PR and related issues, then verify
those claims against the code. Compare the base and head revisions, trace
relevant callers and consumers, and search for existing helpers and nearby
implementations before recommending a new approach.

Use the repository instructions for detailed checks. Pay particular
attention to these relationships when relevant to the diff:

- eBPF: follow C event and map changes through Go loaders and consumers;
  check ABI consistency, verifier constraints, supported kernels, and
  required generated artifacts.
- Protocol parsers: compare buffer handling with nearby implementations;
  check partial and malformed input, bounds, allocations, and error paths.
- Telemetry: follow emitted changes through exporters and the registry;
  consult `devdocs/telemetry-schema.md` for transformation, release-note,
  and generated-documentation requirements.

Inspect relevant tests and available CI results. Distinguish validation
you performed, results you inspected, and contributor claims. Connect any
validation concern to a specific uncovered behavior or repository requirement.

Report actionable issues introduced by the PR, including concrete
violations of repository requirements around reuse, abstraction, and scope.
For each finding, identify the affected location, consequence, supporting
code or requirement, and a focused correction or rationale question.
Keep comments concise, avoid duplicate findings, and omit unsupported
speculation and personal style preferences. State material review limitations;
if no actionable issue is found, say so without claiming correctness is proven.
