// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package generictracer // import "go.opentelemetry.io/obi/pkg/internal/ebpf/generictracer"

import (
	"errors"
	"io"
	"testing"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/rustexec"
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

func TestRustChannelTriesEveryAlternative(t *testing.T) {
	const channel = "hyper::client::dispatch::Envelope<T>"
	addresses := map[rustProbeKind][]uint64{}
	for _, kind := range []rustProbeKind{
		rustHyperEnqueue, rustHyperDequeue, rustHyperChanSend, rustHyperSend, rustHyperReceive,
		rustHyperFindBlock, rustHyperPop, rustHyperRequestSend,
	} {
		addresses[kind] = []uint64{uint64(kind) + 1}
	}

	symbols := rustProbeSymbols{
		channels:      []string{channel},
		channelProbes: map[string]map[rustProbeKind][]uint64{channel: addresses},
	}
	config := BpfRustProtocolConfigT{
		Message: rustexec.MessageCallback | rustexec.MessageList | rustexec.MessageRequest,
	}
	groups := planRustProbes(symbols, config)
	require.Len(t, groups, 1)
	require.Len(t, groups[0].alternatives, 5)

	// Only the last alternative attaches, so every earlier one must have been tried.
	_, features, err := attachRustGroups(groups, func(alternative rustProbeAlternative) ([]io.Closer, error) {
		if len(alternative[rustHyperRequestSend]) == 0 {
			return nil, errors.New("inlined or unavailable")
		}
		return nil, nil
	})

	require.NoError(t, err)
	require.True(t, features["channel:"+channel])
}

func TestRustTLSFeaturesNameEachDirection(t *testing.T) {
	var symbols rustProbeSymbols
	for _, kind := range []rustProbeKind{rustTLSFlush, rustTLSWrite} {
		symbols.addresses[kind] = []uint64{uint64(kind) + 1}
	}

	groups := planRustProbes(symbols, BpfRustProtocolConfigT{Rustls: 1})
	_, features, err := attachRustGroups(groups, func(rustProbeAlternative) ([]io.Closer, error) {
		return nil, nil
	})

	require.NoError(t, err)
	require.True(t, features["tls-bind"], "flush alone binds a connection")
	require.True(t, features["tls-write"])
	require.False(t, features["tls-read"], "a write hook must not stand in for plaintext reads")
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
	require.True(t, names["tls-bind"])
	require.True(t, names["tls-read"])
	require.True(t, names["tls-write"], "missing vectored writes must retain scalar write capture")
	require.True(t, names["http1"])
	require.False(t, names["h2-send"])
}
