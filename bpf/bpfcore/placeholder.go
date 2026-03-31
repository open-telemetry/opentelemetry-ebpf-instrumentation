// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build obi_bpf

package bpfcore // import "go.opentelemetry.io/obi/bpf/bpfcore"

// Below is the version of the cilium/ebpf library that we are using, which is
// the main dependency of this module.
//
// If you are updating the version of cilium/ebpf, update the version here as
// well. This will trigger a check in the CI to ensure that the version of
// cilium/ebpf used in this module is consistent with the version used in the
// main module (go.opentelemetry.io/obi) and that functinality is not broken
// due to the update.
//
// If you are updating the version of cilium/ebpf, also update the version in
// the go.mod file of this module and the main module (go.opentelemetry.io/obi)
// to ensure consistency.
//
// github.com/cilium/ebpf v0.21.0
