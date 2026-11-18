// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package generictracer // import "go.opentelemetry.io/obi/pkg/internal/ebpf/generictracer"

import (
	"errors"
	"io"
	"testing"

	"github.com/stretchr/testify/require"
)

type rustTestLink struct{ closed bool }

func (l *rustTestLink) Close() error { l.closed = true; return nil }

func TestRustAttachmentAlternatives(t *testing.T) {
	stable, failed, fallback := &rustTestLink{}, &rustTestLink{}, &rustTestLink{}
	groups := []rustProbeGroup{
		{name: "tasks", feature: "task", alternatives: []rustProbeAlternative{{rustTaskPoll: {1}}}},
		{name: "channel", feature: "channel", alternatives: []rustProbeAlternative{{rustHyperEnqueue: {2}}, {rustHyperSend: {3}}, {rustHyperFindBlock: {4}}}},
		{name: "missing TLS", feature: "tls", alternatives: []rustProbeAlternative{{rustTLSWrite: {5}}}},
	}
	links, enabled, err := attachRustGroups(groups, func(alternative rustProbeAlternative) ([]io.Closer, error) {
		switch {
		case len(alternative[rustTaskPoll]) > 0:
			return []io.Closer{stable}, nil
		case len(alternative[rustHyperEnqueue]) > 0:
			return []io.Closer{failed}, errors.New("inlined or unavailable")
		case len(alternative[rustHyperSend]) > 0:
			return nil, errors.New("attach rejected")
		case len(alternative[rustHyperFindBlock]) > 0:
			return []io.Closer{fallback}, nil
		default:
			return nil, errors.New("unavailable")
		}
	})
	require.ErrorContains(t, err, "missing TLS")
	require.True(t, enabled["task"])
	require.True(t, enabled["channel"])
	require.False(t, enabled["tls"])
	require.True(t, failed.closed)
	require.False(t, stable.closed)
	require.False(t, fallback.closed)
	require.Len(t, links, 2)
}

func TestRustPartialProbePlan(t *testing.T) {
	var symbols rustProbeSymbols
	for _, kind := range []rustProbeKind{rustTaskHarnessPoll, rustTaskBind, rustTLSClientProcess, rustTLSRead, rustTLSWrite, rustHTTP1Headers} {
		symbols.addresses[kind] = []uint64{uint64(kind) + 1}
	}
	groups := planRustProbes(symbols, BpfRustProtocolConfigT{Rustls: 1, Http1: 1, Http2: 1})
	names := map[string]bool{}
	for _, group := range groups {
		names[group.feature] = true
	}
	require.True(t, names["task-poll"], "Harness polling replaces an inlined raw poll")
	require.True(t, names["task-create"])
	require.True(t, names["tls-process"])
	require.True(t, names["tls-io"], "missing vectored writes must retain scalar read/write capture")
	require.True(t, names["http1"])
	require.False(t, names["h2-send"])
}
