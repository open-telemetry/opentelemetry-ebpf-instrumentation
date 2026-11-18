// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Command compatcheck checks the root module's public Go source API on Linux
// against VERSIONING.md. It follows aliases and exposed internal and dependency
// types; commands, test files, and independently versioned modules are excluded
// as roots.
//
// Run from the repository root with Go, Git, and Cosign installed:
//
//	make check-compat COMPAT_BASE_REF=upstream/main COMPAT_BASE_DIR=/path/to/target
//
// The target checkout must be clean and match COMPAT_BASE_REF. Both checkouts
// need their own generated BPF artifacts (make docker-generate). The candidate
// may contain local edits. make test-compat runs the checker tests.
//
// Candidate and target are each compared with signed, immutable release source
// archives from v1.0.0 through the target's minor line. The target's committed
// versions.yaml selects that line. Changes shared with the target are inherited
// and do not count as PR findings.
//
// testoutput/compatibility.json separates incompatibilities (findings) from
// unresolved comparisons (unclassified_changes); existing_ fields hold inherited
// results. Compatible additions, including concrete methods, produce no findings.
// required_release classifies the PR; release_required includes inherited changes.
// Unresolved comparisons make the corresponding assessment incomplete.
//
// COMPAT_RELEASE_VERSION=vX.Y.Z additionally validates the entire candidate for
// that release, including inherited changes. The executable exits 0 when the PR
// (or requested release) assessment passes, 1 for incompatibilities or additions
// in a proposed patch, and 2 for invalid inputs or an incomplete assessment.
// Make wraps exit statuses.
//
// Static type comparisons do not validate runtime behavior, ABI layout, dependency
// import/version conflicts, or non-Go policy surfaces.
package main
