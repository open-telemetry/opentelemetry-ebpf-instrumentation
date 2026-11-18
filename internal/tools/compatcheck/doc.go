// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Command compatcheck compares the root module's public Go source API on Linux
// and classifies changes using a subset of the Go API rules in VERSIONING.md.
//
// It follows aliases and exposed internal and dependency types. Commands, test
// files, and independently versioned modules are excluded as roots. bpf2go
// declarations and generated layouts are excluded, including through handwritten
// aliases and wrappers.
//
// Usage:
//
//	compatcheck -target upstream/main -report compatibility.json
//
// The candidate is the current working tree, including local edits. Use -repo to
// select another working tree. The target is a Git revision (default: HEAD).
//
// Requires Go, Git, and Cosign. The candidate needs generated BPF artifacts.
// The tool prepares the target in a temporary Git worktree and cleans it up
// afterward. Target BPF generation requires Make and Docker; -target-bpf accepts
// a directory of pre-generated target bindings and bytecode instead.
//
// Candidate and target are each compared with signed, immutable release source
// archives within the target's major version, from vN.0.0 through its minor line.
// The target's committed versions.yaml selects that line; v2+ modules must use
// the corresponding /vN import path suffix. Changes shared with the target are
// inherited and do not count as PR findings.
//
// The optional -report JSON output separates incompatibilities (findings) from
// unresolved comparisons (unclassified_changes); existing_ fields hold inherited
// results. Compatible additions, including concrete methods, produce no findings.
// required_release classifies changes relative to the target; release_required
// includes inherited changes.
// Unresolved comparisons make the corresponding assessment incomplete.
//
// Use -release-version vX.Y.Z to check the candidate's Go API release classification
// against a proposed version, including inherited changes. Use -release-metadata
// to supply prefetched GitHub API responses instead of making live metadata requests.
//
// The executable exits 0 when the PR or requested release assessment passes,
// 1 for incompatibilities or additions in a proposed patch, and 2 for invalid
// inputs or an incomplete assessment.
//
// Static type comparisons do not validate runtime behavior, ABI layout, dependency
// import/version conflicts, or non-Go policy surfaces.
package main
