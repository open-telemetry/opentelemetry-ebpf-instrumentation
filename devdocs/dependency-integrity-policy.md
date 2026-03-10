# Dependency Integrity Policy

This document defines dependency integrity requirements for Dockerfiles and build scripts in this repository.

## Why this policy exists

Without integrity controls, two builds from the same commit can pull different dependency contents and produce different results.

In practice, that causes three recurring problems:

- **Build drift:** a previously green pipeline fails later because a floating dependency changed upstream.
- **Incident response friction:** when behavior changes unexpectedly, it is hard to prove what exact dependencies were used.
- **Supply-chain risk:** unverified downloads or mutable install commands can execute tampered content.

This policy exists to make builds predictable, auditable, and safer. The rules below are intentionally concrete so reviewers can quickly determine whether a Dockerfile is reproducible and integrity-protected.

## Goals

- Make dependency resolution deterministic.
- Prevent supply-chain tampering via unverified downloads.
- Keep build behavior reproducible across CI and local environments.

## Required Rules

### Pin Docker images by digest

- Use `FROM image:tag@sha256:<digest>`.
- Do not use floating `latest` tags.

### Go tool installation must be immutable

- Do not use `go install ...@latest`.
- Pin exact module versions.
- Prefer copying tools from a pinned builder image over downloading ad-hoc archives in Dockerfiles.
- Prefer a committed `go.mod` and `go.sum` over defining one-off versions in Dockerfiles.

### Python installs must be hash-locked

- Do not run ad-hoc `pip install <packages...>` in Dockerfiles.
- Use a committed requirements file with hashes and install with hash enforcement.
- Require hashes when installing (e.g. `pip install --require-hashes -r requirements.txt`).

### Node installs must be lockfile-enforced

- Commit lockfiles.
- Use `npm ci` in Dockerfiles.
- Do not run `npm init` or mutable `npm install` during image builds unless generating lockfiles in a dedicated, reviewed update workflow.

### Rust builds must honor lockfiles

- Use `cargo build --locked` (and equivalent locked flags for other cargo operations).

### uvx / uv tool invocations must be version and hash pinned

- Do not use bare `uvx <tool>` without a pinned version: this always fetches the latest available release.
- Do not use `uvx <tool>==<version>` alone: this pins the version but does not verify integrity.
- Commit a `<tool>-requirements.in` with the pinned version (e.g., `zizmor==1.23.1`) and a generated `<tool>-requirements.txt` produced by `pip-compile --generate-hashes --strip-extras`, following the same pattern as other `requirements.in`/`requirements.txt` pairs in this repo.
- Install with `uv venv .venv && uv pip install --require-hashes -r <tool>-requirements.txt` and invoke via `.venv/bin/<tool>`. Do not use `--system`; GitHub-hosted runners use externally-managed Python that rejects it.
- When upgrading, update the pinned version and replace all hashes in the requirements file, verifying the new hashes from PyPI.

### Remote downloads must be verified

- Do not use `curl ... | bash` patterns.
- Any downloaded artifact must be verified with checksum/signature before execution/extraction.
- Prefer pinned upstream images containing required toolchains instead of shell bootstrap installers.
