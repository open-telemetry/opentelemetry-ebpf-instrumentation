// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package bpf_verifier_test

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/stretchr/testify/require"

	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
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
	statsolly "go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
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

		// On kernels < 5.17, replace obi_protocol_http (which uses bpf_loop)
		// with obi_protocol_http_legacy, matching what the production loader does.
		if spec.Programs["obi_protocol_http"] != nil {
			ebpfcommon.FixupSpec(spec, false)
		}

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

// constOption represents one constant and its possible values to test.
type constOption struct {
	name   string
	values []any
}

// forEachCombination generates generate every possible combination of options from all constant
// options and calls fn for each combination. The test name encodes all constant values.
// To get the next combination, it starts at the last index and increments it
// Example: we have 2 values, we start with [0, 0], then [0, 1], [1, 0], [1, 1],
// then [0, 0] stop.
func forEachCombination(t *testing.T, prefix string, loadFn func() (*ebpf.CollectionSpec, error), opts []constOption) {
	t.Helper()
	indices := make([]int, len(opts))
	for {
		consts := make(map[string]any, len(opts))
		var nameParts strings.Builder
		nameParts.WriteString(prefix)
		for i, opt := range opts {
			consts[opt.name] = opt.values[indices[i]]
			fmt.Fprintf(&nameParts, "/%s=%v", opt.name, opt.values[indices[i]])
		}
		loadAndVerify(t, nameParts.String(), loadFn, consts)

		// next combination
		carry := true
		for i := len(indices) - 1; i >= 0 && carry; i-- {
			indices[i]++
			if indices[i] < len(opts[i].values) {
				carry = false // found a valid item
			} else {
				indices[i] = 0 // finished all values for this option so reset
				// and move to the previous option
			}
		}
		if carry {
			break
		}
	}
}

// TestBPFVerifierWithConstants verifies that BPF programs pass the kernel verifier
// across all combinations of constant values (also default ones).
// Different constant values cause the verifier to evaluate different code paths
// (e.g. debug logging, traceparent parsing, header propagation), which may trigger
// verifier rejections not caught by default tests.
// Requires CAP_SYS_ADMIN / root.
// Run with: sudo env PATH=$PATH PRIVILEGED_TESTS=true go test ./pkg/internal/ebpf/verifier/...
func TestBPFVerifierWithConstants(t *testing.T) {
	if os.Getenv(privilegedEnv) == "" {
		t.Skipf("Skipping this test because %v is not set", privilegedEnv)
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("cannot remove memlock limit (insufficient privileges?): %v", err)
	}

	// netolly
	netollyOpts := []constOption{
		{"g_bpf_debug", []any{true, false}},
		{"sampling", []any{uint32(0), uint32(1), uint32(1000)}},
		{"trace_messages", []any{uint8(0), uint8(1)}},
		{"port_guessing", []any{uint8(0), uint8(1)}},
	}
	forEachCombination(t, "netolly/Net", netollybpf.LoadNet, netollyOpts)
	forEachCombination(t, "netolly/NetSk", netollybpf.LoadNetSk, netollyOpts)

	// generictracer
	forEachCombination(t, "generictracer/Bpf", generictracerbpf.LoadBpf, []constOption{
		{"g_bpf_debug", []any{true, false}},
		{"g_bpf_traceparent_enabled", []any{true, false}},
		{"filter_pids", []any{int32(0), int32(1)}},
		{"capture_header_buffer", []any{int32(0), int32(1)}},
		{"high_request_volume", []any{uint32(0), uint32(1)}},
		{"disable_black_box_cp", []any{uint32(0), uint32(1)}},
	})

	// gotracer
	forEachCombination(t, "gotracer/Bpf", gotracerbpf.LoadBpf, []constOption{
		{"g_bpf_debug", []any{true, false}},
		{"g_bpf_traceparent_enabled", []any{true, false}},
		{"g_bpf_header_propagation", []any{true, false}},
		{"g_bpf_loop_enabled", []any{ebpfcommon.SupportsEBPFLoops(slog.Default(), false)}},
		{"disable_black_box_cp", []any{uint32(0), uint32(1)}},
	})

	// tpinjector
	// inject_flags is a bitmask: bit 0 = HTTP headers, bit 1 = TCP options.
	forEachCombination(t, "tpinjector/Bpf", tpinjectorbpf.LoadBpf, []constOption{
		{"g_bpf_debug", []any{true, false}},
		{"filter_pids", []any{int32(0), int32(1)}},
		{"inject_flags", []any{uint32(0), uint32(1), uint32(2), uint32(3)}},
	})
	forEachCombination(t, "tpinjector/BpfIter", tpinjectorbpf.LoadBpfIter, []constOption{
		{"g_bpf_debug", []any{true, false}},
	})

	// watcher
	forEachCombination(t, "watcher/Bpf", watcherbpf.LoadBpf, []constOption{
		{"g_bpf_debug", []any{true, false}},
	})

	// gpuevent
	forEachCombination(t, "gpuevent/Bpf", gpueventbpf.LoadBpf, []constOption{
		{"g_bpf_debug", []any{true, false}},
		{"filter_pids", []any{int32(0), int32(1)}},
	})

	// logger
	forEachCombination(t, "logger/Bpf", loggerbpf.LoadBpf, []constOption{
		{"g_bpf_debug", []any{true, false}},
	})

	// logenricher
	forEachCombination(t, "logenricher/Bpf", logenricherbpf.LoadBpf, []constOption{
		{"g_bpf_debug", []any{true, false}},
	})

	// rdns xdp
	forEachCombination(t, "rdns/xdp/Bpf", rdnsxdpbpf.LoadBpf, []constOption{
		{"g_bpf_debug", []any{true, false}},
	})

	// statsolly
	forEachCombination(t, "statsolly/Stats", statsolly.LoadStats, []constOption{
		{"g_bpf_debug", []any{true, false}},
	})
}
