# Compatibility checks

[Issue #4269](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/issues/4269)
tracks the staged implementation of CI for [VERSIONING.md](../VERSIONING.md).
The first stage checks the root module's public Go API on Linux amd64 and arm64.
It runs in **advisory mode**. Configuration, CLI, telemetry, artifacts, support
policy, and activation of required checks remain separate stages. The Collector
module has its own version line.

## Run locally

Install Go, Git, Docker, and Cosign. Prepare the candidate and a clean target
checkout, generating each checkout's own BPF files:

```sh
git worktree add --detach /tmp/obi-compat-base upstream/main
make -C /tmp/obi-compat-base docker-generate
make docker-generate
make check-compat COMPAT_BASE_REF=upstream/main COMPAT_BASE_DIR=/tmp/obi-compat-base
```

`COMPAT_BASE_DIR` must be clean and at `COMPAT_BASE_REF`. The checked-out
candidate may include local edits. A clean candidate compared with its own HEAD
can omit the base directory. The target's committed `versions.yaml` selects the
release line; editing the candidate's version does not change that selection.

The checker compares both checkouts against every official immutable stable
core release from v1.0.0 through the target minor line. It verifies release
source-generated archives and checksum files with Cosign against the tagged
release workflow, then verifies archive checksums. Cached assets are reverified.
Set `GH_TOKEN` if GitHub API rate limits require authentication.

```sh
make check-compat COMPAT_BASE_REF=upstream/main COMPAT_BASE_DIR=/tmp/obi-compat-base COMPAT_ARCH=arm64
make check-compat COMPAT_BASE_REF=upstream/main COMPAT_BASE_DIR=/tmp/obi-compat-base COMPAT_RELEASE_VERSION=v1.1.0
make test-compat
```

JSON is written to `testoutput/compatibility.json`, and verified release assets
are cached under `testoutput/compatibility-cache`. Override these paths with
`COMPAT_REPORT` and `COMPAT_CACHE_DIR`.

## Interpret the report

The summary separates findings introduced by the PR from findings already on
its target branch. JSON `findings` contains the former; `existing_findings`
contains the latter. A tooling-only PR should not be blamed for an existing
release incompatibility.

`required_release` classifies the PR's changes: **patch** for no observed API
change, **minor** for compatible additions, and **major** for incompatibilities.
`release_required` classifies the entire candidate. Additions require a minor
release only when absent from the newest applicable release (`release_base`).
Incompatibilities against any protected release require a major release.

**INCOMPLETE** means acquisition, extraction, or comparison failed. The JSON
`error` records the failure. Findings with `unsupported: true` are unclassified:
for example, naming an anonymous struct with private fields may preserve source
compatibility, but the diff tool cannot prove it. Such changes make the affected
PR comparison or full-candidate release assessment incomplete. They are never
silently waived or counted as proven incompatibilities.

The checker uses pinned `golang.org/x/exp/apidiff` and Go type information. A
module-wide comparison follows aliases and types exposed by public declarations,
including internal types. Commands, tests, nested modules, and unrelated internal
declarations are excluded. Checks cover exported declarations, signatures,
fields, methods, constants, comparability, and generic constraints. Runtime
behavior, ABI layout, and dependency import/version conflicts are not validated.
This report is evidence for review, not proof of every policy requirement.

The executable returns 0 for a compatible PR comparison, 1 for incompatibilities,
and 2 for incomplete execution or invalid inputs. With `COMPAT_RELEASE_VERSION`,
all candidate findings are checked, including inherited problems; a patch
release also fails if new API requires a minor release. A version edit does not
authorize breaking the existing module line. Make uses its own failure status;
automation should inspect the JSON report.

## Rollout

The workflow publishes a summary and attempts to upload JSON even on failure.
Comparison failures are advisory; tests and prerequisite failures remain CI
failures. Fork PRs use a read-only token. Shared release assets are saved only
from main-branch pushes with completed baseline acquisition and extraction.

Enforcement and release integration require a separate activation PR. Record
baseline self-comparisons, consumer compilation fixtures, representative PR
replays, and resolution of unclassified findings in the tracking issue first.
