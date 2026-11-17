# Compatibility checks

[Issue #4269](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/issues/4269)
tracks the incremental implementation and activation of the
[versioning policy](../VERSIONING.md) checks.

The first slice checks the public Go API of the root module on Linux amd64 and
arm64. CI runs it in **advisory mode**. Configuration, CLI/environment inputs,
telemetry, packaging, and declared support are not yet checked by this workflow.
The Collector module retains its independent version line.

## Run locally

Install Go, Git, Docker, and Cosign. Generate candidate BPF artifacts before
loading the Go packages:

```sh
make docker-generate
make check-compat COMPAT_BASE_REF=upstream/main
```

The checker compares the checked-out candidate, including local edits, with
official immutable stable core releases from v1.0.0 through the target
revision's minor line. `COMPAT_BASE_REF` identifies the trusted target revision;
its committed `versions.yaml` selects the release line. Candidate edits to that
file do not select a different baseline. Published contracts determine
protection; unreleased API additions are not protected merely by merging.
Reports cover the entire candidate against published contracts and can include
incompatibilities already present on the target branch.

The newest applicable release determines whether an API addition is new. The
JSON `release_base` field identifies that release. Additions already present in
that release do not force another minor release; incompatible changes against
any protected release still require a major release.

Release source-generated archives contain the historical generated BPF files
and embedded Java agent. The checker verifies the archive and checksum-file
Cosign signatures against the tagged release workflow, then verifies the
archive checksum. Cached assets are reverified on every run. Both lightweight
and annotated release tags are resolved to commit identities for the report.
Set `GH_TOKEN` when GitHub API rate limits require authentication.

Useful options:

```sh
make check-compat COMPAT_BASE_REF=upstream/main COMPAT_ARCH=arm64
make check-compat COMPAT_BASE_REF=upstream/main COMPAT_RELEASE_VERSION=v1.1.0
make test-compat
```

The default JSON report is `testoutput/compatibility.json`; downloaded assets
are cached under `testoutput/compatibility-cache`. Override these with
`COMPAT_REPORT` and `COMPAT_CACHE_DIR`.

The checker uses pinned `golang.org/x/exp/apidiff` tooling and Go package/type
information. It excludes internal packages, commands, tests, and nested modules.
It detects package/symbol removal, incompatible signatures and types,
interface-method additions, and changed constants. Implementation behavior and
subjective meaning changes are outside this check.

## Interpret the result

- **patch:** no public Go API change was observed.
- **minor:** compatible API additions were observed.
- **major:** an incompatible public Go API change was observed.
- **INCOMPLETE:** acquisition or extraction failed; this is not a compatibility
  pass. The JSON `error` field records the failure.

A proposed patch release fails when additions require a minor release. A version
change alone does not authorize an incompatible API change in the existing
module. Without `COMPAT_RELEASE_VERSION`, ordinary PRs need no version bump.

The executable `.tools/compatcheck` returns 0 for a compatible comparison, 1 for
an incompatibility or insufficient proposed release version, and 2 for invalid
inputs or incomplete execution. Make reports failed recipes with its own exit
status; use the JSON report to distinguish failures in automation.

## Rollout

The advisory workflow always publishes a summary and attempts to upload the
JSON report. Incompatibilities and incomplete comparisons remain visible even
though enforcement is not enabled. Tests and prerequisite failures remain CI
failures. Fork PRs use a read-only token; shared release-asset caches are saved
only by main-branch pushes whose baseline acquisition and API extraction
completed successfully, including comparisons that found incompatibilities.

Enabling a required status or adding release gates is a separate activation PR.
Record baseline self-comparisons, deliberate-break fixtures, representative PR
replays, and resolved false positives in the tracking issue before activation.
