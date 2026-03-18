// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package bpf_verifier_test

import (
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/stretchr/testify/require"

	commonbpf "go.opentelemetry.io/obi/pkg/ebpf/common"
	gotracerbpf "go.opentelemetry.io/obi/pkg/internal/ebpf/gotracer"
	gpueventbpf "go.opentelemetry.io/obi/pkg/internal/ebpf/gpuevent"
	loggerbpf "go.opentelemetry.io/obi/pkg/internal/ebpf/logger"
	tpinjectorbpf "go.opentelemetry.io/obi/pkg/internal/ebpf/tpinjector"
	watcherbpf "go.opentelemetry.io/obi/pkg/internal/ebpf/watcher"
	netollybpf "go.opentelemetry.io/obi/pkg/internal/netolly/ebpf"
	rdnsxdpbpf "go.opentelemetry.io/obi/pkg/internal/rdns/ebpf/xdp"
)

const privilegedEnv = "PRIVILEGED_TESTS"

// loadAndVerify loads a BPF collection spec into the kernel, triggering the BPF
// verifier, then immediately closes it. Any verifier rejection surfaces as a test failure.
// Pin types are stripped so the test works without a mounted BPF filesystem.
func loadAndVerify(t *testing.T, name string, loadFn func() (*ebpf.CollectionSpec, error)) {
	t.Helper()
	t.Run(name, func(t *testing.T) {
		spec, err := loadFn()
		require.NoError(t, err, "failed to load collection spec")

		for _, m := range spec.Maps {
			m.Pinning = ebpf.PinNone
			// Some maps have MaxEntries=0 because the Go code sets them
			// dynamically at runtime. Use a minimal value for verification.
			if m.MaxEntries == 0 {
				switch m.Type {
				case ebpf.RingBuf:
					// Ring buffers require a page-aligned non-zero size.
					m.MaxEntries = uint32(os.Getpagesize())
				case ebpf.SkStorage, ebpf.InodeStorage, ebpf.TaskStorage, ebpf.CgroupStorage:
					// Per-object local storage maps must have MaxEntries=0.
				default:
					m.MaxEntries = 1
				}
			}
		}

		coll, err := ebpf.NewCollection(spec)
		require.NoError(t, err, "BPF verifier rejected program(s)")
		coll.Close()
	})
}

// TestBPFVerifier loads every generated BPF collection into the kernel and checks that
// the BPF verifier accepts all programs. Requires CAP_SYS_ADMIN / root.
//
// Run with: sudo env PRIVILEGED_TESTS=true go test ./pkg/internal/ebpf/verifier/...
func TestBPFVerifier(t *testing.T) {
	if os.Getenv(privilegedEnv) == "" {
		t.Skipf("Skipping this test because %v is not set", privilegedEnv)
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("cannot remove memlock limit (insufficient privileges?): %v", err)
	}

	// netolly: TC-based flow monitor
	loadAndVerify(t, "netolly/Net", netollybpf.LoadNet)
	// netolly: socket-filter-based flow monitor
	loadAndVerify(t, "netolly/NetSk", netollybpf.LoadNetSk)

	// generic tracer (uprobe-based HTTP/gRPC/...)
	loadAndVerify(t, "gotracer/Bpf", gotracerbpf.LoadBpf)
	loadAndVerify(t, "gotracer/BpfDebug", gotracerbpf.LoadBpfDebug)
	loadAndVerify(t, "gotracer/BpfTP", gotracerbpf.LoadBpfTP)
	loadAndVerify(t, "gotracer/BpfTPDebug", gotracerbpf.LoadBpfTPDebug)

	// tracepoint injector
	loadAndVerify(t, "tpinjector/Bpf", tpinjectorbpf.LoadBpf)
	loadAndVerify(t, "tpinjector/BpfDebug", tpinjectorbpf.LoadBpfDebug)

	// process watcher
	loadAndVerify(t, "watcher/Bpf", watcherbpf.LoadBpf)
	loadAndVerify(t, "watcher/BpfDebug", watcherbpf.LoadBpfDebug)

	// GPU event tracer
	loadAndVerify(t, "gpuevent/Bpf", gpueventbpf.LoadBpf)
	loadAndVerify(t, "gpuevent/BpfDebug", gpueventbpf.LoadBpfDebug)

	// BPF ring-buffer logger
	loadAndVerify(t, "logger/BpfDebug", loggerbpf.LoadBpfDebug)

	// reverse DNS XDP program
	loadAndVerify(t, "rdns/xdp/Bpf", rdnsxdpbpf.LoadBpf)

	// shared common BPF helpers / maps
	loadAndVerify(t, "common/Bpf", commonbpf.LoadBpf)
}
