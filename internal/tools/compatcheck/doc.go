// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Command compatcheck compares the root module's public Go source API on Linux.
// It implements a subset of VERSIONING.md's Go API rules in code; policy changes
// require corresponding code and test updates. VERSIONING.md is not read at runtime.
//
// It follows aliases and exposed internal and dependency types. Commands, test
// files, and independently versioned modules are excluded as roots. bpf2go
// declarations and generated layouts are excluded, including
// through handwritten aliases and wrappers.
//
// Run from the repository root with Go, Git, and Cosign installed:
//
//	make check-compat COMPAT_BASE_REF=upstream/main COMPAT_BASE_DIR=/path/to/target
//
// The target checkout must be clean and match COMPAT_BASE_REF. Both checkouts
// need their own generated BPF artifacts (make docker-generate). The candidate
// may contain local edits. Run the checker tests with:
//
//	go -C internal/tools test -race ./...
//
// Candidate and target are each compared with signed, immutable release source
// archives from v1.0.0 through the target's minor line. The target's committed
// versions.yaml selects that line. Changes shared with the target are inherited
// and do not count as PR findings.
//
// CI fetches GitHub API metadata in a separate job using a script pinned to a
// fixed commit; update the pin when changing that script. COMPAT_RELEASE_METADATA
// supplies its output to the comparison, disabling live metadata requests.
// CI passes no GitHub token to the comparison; archive downloads remain anonymous
// and signature-verified.
//
// testoutput/compatibility.json separates incompatibilities (findings) from
// unresolved comparisons (unclassified_changes); existing_ fields hold inherited
// results. Compatible additions, including concrete methods, produce no findings.
// required_release classifies the PR; release_required includes inherited changes.
// Unresolved comparisons make the corresponding assessment incomplete.
//
// COMPAT_RELEASE_VERSION=vX.Y.Z additionally checks the candidate's Go API
// release classification against that version, including inherited changes.
// The executable exits 0 when the PR (or requested release) assessment passes,
// 1 for incompatibilities or additions
// in a proposed patch, and 2 for invalid inputs or an incomplete assessment.
// Make wraps exit statuses.
//
// Static type comparisons do not validate runtime behavior, ABI layout, dependency
// import/version conflicts, or non-Go policy surfaces.
package main
