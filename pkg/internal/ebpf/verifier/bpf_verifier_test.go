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

	ebpfconvenience "go.opentelemetry.io/obi/pkg/internal/ebpf/convenience"
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
// An optional constants map can be provided to rewrite BPF constants before loading.
func loadAndVerify(t *testing.T, name string, loadFn func() (*ebpf.CollectionSpec, error), consts ...map[string]any) {
	t.Helper()
	t.Run(name, func(t *testing.T) {
		spec, err := loadFn()
		require.NoError(t, err, "failed to load collection spec")

		if len(consts) > 0 && consts[0] != nil {
			err = ebpfconvenience.RewriteConstants(spec, consts[0])
			require.NoError(t, err, "failed to rewrite constants")
		}

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

// TestBPFVerifierWithConstants verifies that BPF programs pass the kernel verifier
// with non-default constant values. Different constant values cause the verifier to
// evaluate different code paths (e.g. debug logging, traceparent parsing, header
// propagation), which may trigger verifier rejections not caught by default-value tests.
func TestBPFVerifierWithConstants(t *testing.T) {
	if os.Getenv(privilegedEnv) == "" {
		t.Skipf("Skipping this test because %v is not set", privilegedEnv)
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("cannot remove memlock limit (insufficient privileges?): %v", err)
	}

	// netolly
	loadAndVerify(t, "netolly/Net/debug", netollybpf.LoadNet, map[string]any{
		"g_bpf_debug":    true,
		"sampling":       uint32(100),
		"trace_messages": uint8(1),
		"port_guessing":  uint8(1),
	})

	loadAndVerify(t, "netolly/NetSk/debug", netollybpf.LoadNetSk, map[string]any{
		"g_bpf_debug":    true,
		"sampling":       uint32(100),
		"trace_messages": uint8(1),
		"port_guessing":  uint8(1),
	})

	// generictracer
	loadAndVerify(t, "generictracer/Bpf/debug", generictracerbpf.LoadBpf, map[string]any{
		"g_bpf_debug": true,
	})

	loadAndVerify(t, "generictracer/Bpf/traceparent", generictracerbpf.LoadBpf, map[string]any{
		"g_bpf_traceparent_enabled": true,
		"capture_header_buffer":     int32(1),
	})

	loadAndVerify(t, "generictracer/Bpf/all_features", generictracerbpf.LoadBpf, map[string]any{
		"g_bpf_debug":               true,
		"g_bpf_traceparent_enabled": true,
		"filter_pids":               int32(1),
		"capture_header_buffer":     int32(1),
		"high_request_volume":       uint32(1),
		"disable_black_box_cp":      uint32(1),
	})

	// gotracer
	loadAndVerify(t, "gotracer/Bpf/debug", gotracerbpf.LoadBpf, map[string]any{
		"g_bpf_debug": true,
	})

	loadAndVerify(t, "gotracer/Bpf/all_features", gotracerbpf.LoadBpf, map[string]any{
		"g_bpf_debug":               true,
		"g_bpf_traceparent_enabled": true,
		"g_bpf_header_propagation":  true,
		"g_bpf_loop_enabled":        true,
		"disable_black_box_cp":      uint32(1),
	})

	// tpinjector
	loadAndVerify(t, "tpinjector/Bpf/debug", tpinjectorbpf.LoadBpf, map[string]any{
		"g_bpf_debug": true,
	})

	loadAndVerify(t, "tpinjector/Bpf/all_features", tpinjectorbpf.LoadBpf, map[string]any{
		"g_bpf_debug":          true,
		"filter_pids":          int32(1),
		"inject_flags":         uint32(3),
		"max_transaction_time": uint64(5000000000),
	})

	loadAndVerify(t, "tpinjector/BpfIter/debug", tpinjectorbpf.LoadBpfIter, map[string]any{
		"g_bpf_debug": true,
	})

	// watcher
	loadAndVerify(t, "watcher/Bpf/debug", watcherbpf.LoadBpf, map[string]any{
		"g_bpf_debug": true,
	})

	// gpuevent
	loadAndVerify(t, "gpuevent/Bpf/debug", gpueventbpf.LoadBpf, map[string]any{
		"g_bpf_debug": true,
	})

	loadAndVerify(t, "gpuevent/Bpf/filter_pids", gpueventbpf.LoadBpf, map[string]any{
		"g_bpf_debug": true,
		"filter_pids": int32(1),
	})

	// logger
	loadAndVerify(t, "logger/Bpf/debug", loggerbpf.LoadBpf, map[string]any{
		"g_bpf_debug": true,
	})

	// logenricher
	loadAndVerify(t, "logenricher/Bpf/debug", logenricherbpf.LoadBpf, map[string]any{
		"g_bpf_debug": true,
	})

	// rdns xdp
	// Note: rdns/xdp already sets g_bpf_debug=true, so test with false
	loadAndVerify(t, "rdns/xdp/Bpf/no_debug", rdnsxdpbpf.LoadBpf, map[string]any{
		"g_bpf_debug": false,
	})
}
