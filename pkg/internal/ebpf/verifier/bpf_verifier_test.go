// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package bpf_verifier_test

import (
	"errors"
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/stretchr/testify/require"

	generictracerbpf "go.opentelemetry.io/obi/pkg/internal/ebpf/generictracer"
	gotracerbpf "go.opentelemetry.io/obi/pkg/internal/ebpf/gotracer"
	gpueventbpf "go.opentelemetry.io/obi/pkg/internal/ebpf/gpuevent"
	logenricherbpf "go.opentelemetry.io/obi/pkg/internal/ebpf/logenricher"
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

		coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
			Programs: ebpf.ProgramOptions{
				// Increase log buffer so verifier rejections are not truncated.
				LogSizeStart: 10 * 1024 * 1024,
			},
		})
		if err != nil {
			var ve *ebpf.VerifierError
			if errors.As(err, &ve) {
				t.Fatalf("BPF verifier rejected program(s):\n%+v", ve)
			}
			require.NoError(t, err, "failed to load BPF collection")
		}
		coll.Close()
	})
}

// TestBPFVerifier loads every generated BPF collection into the kernel and checks that
// the BPF verifier accepts all programs. Requires CAP_SYS_ADMIN / root.
//
// Run with: sudo env PATH=$PATH PRIVILEGED_TESTS=true go test ./pkg/internal/ebpf/verifier/...
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

	// generictracer (iter programs like ObiIterTcp are included in the main Bpf spec)
	loadAndVerify(t, "generictracer/Bpf", generictracerbpf.LoadBpf)

	// gotracer
	loadAndVerify(t, "gotracer/Bpf", gotracerbpf.LoadBpf)

	// tracepoint injector
	loadAndVerify(t, "tpinjector/Bpf", tpinjectorbpf.LoadBpf)
	loadAndVerify(t, "tpinjector/BpfIter", tpinjectorbpf.LoadBpfIter)

	// process watcher
	loadAndVerify(t, "watcher/Bpf", watcherbpf.LoadBpf)

	// GPU event tracer
	loadAndVerify(t, "gpuevent/Bpf", gpueventbpf.LoadBpf)

	// logger
	loadAndVerify(t, "logger/Bpf", loggerbpf.LoadBpf)

	// log enricher
	loadAndVerify(t, "logenricher/Bpf", logenricherbpf.LoadBpf)

	// reverse DNS XDP program
	loadAndVerify(t, "rdns/xdp/Bpf", rdnsxdpbpf.LoadBpf)
}
