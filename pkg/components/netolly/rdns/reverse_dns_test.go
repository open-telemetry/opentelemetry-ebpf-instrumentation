// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package rdns

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/components/netolly/ebpf"
)

var (
	srcIP = [16]uint8{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 140, 82, 121, 4}
	dstIP = [16]uint8{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 127, 0, 0, 1}
)

func TestReverseDNS(t *testing.T) {
	netLookupAddr = func(addr string) (names []string, err error) {
		switch addr {
		case "140.82.121.4":
			return []string{"foo.github.com"}, nil
		case "127.0.0.1":
			return []string{"localhost.localdomain"}, nil
		default:
			return []string{"unknown"}, nil
		}
	}
	// Given a Reverse DNS node
	enrich, err := ReverseDNSEnricher(t.Context(), &ReverseDNS{Type: ReverseDNSLocalLookup, CacheLen: 255, CacheTTL: time.Minute})
	require.NoError(t, err)

	// When it receives flows without source nor destination name
	f1 := &ebpf.Record{NetFlowRecordT: ebpf.NetFlowRecordT{
		Id: ebpf.NetFlowId{IfIndex: 1},
	}}
	f1.Id.SrcIp.In6U.U6Addr8 = srcIP
	f1.Id.DstIp.In6U.U6Addr8 = dstIP

	enrich(f1)

	assert.Contains(t, f1.Attrs.SrcName, "github")
	assert.Contains(t, f1.Attrs.DstName, "local")
}

func TestReverseDNS_AlreadyProvidedNames(t *testing.T) {
	netLookupAddr = func(addr string) ([]string, error) {
		require.Fail(t, "network lookup shouldn't be invoked!", "Got:", addr)
		return nil, errors.New("boom")
	}
	// Given a Reverse DNS node
	enrich, err := ReverseDNSEnricher(t.Context(), &ReverseDNS{Type: ReverseDNSLocalLookup, CacheLen: 255, CacheTTL: time.Minute})
	require.NoError(t, err)

	// When it receives flows with source and destination names
	f1 := &ebpf.Record{
		NetFlowRecordT: ebpf.NetFlowRecordT{Id: ebpf.NetFlowId{IfIndex: 1}},
		Attrs:          ebpf.RecordAttrs{SrcName: "src", DstName: "dst"},
	}
	f1.Id.SrcIp.In6U.U6Addr8 = srcIP
	f1.Id.DstIp.In6U.U6Addr8 = dstIP

	enrich(f1)

	assert.Contains(t, f1.Attrs.SrcName, "src")
	assert.Contains(t, f1.Attrs.DstName, "dst")
}

func TestReverseDNS_Cache(t *testing.T) {
	lookups := 0
	netLookupAddr = func(_ string) (_ []string, _ error) {
		require.Zero(t, lookups, "address lookup should only happen once", lookups)
		lookups++
		return []string{"amazon"}, nil
	}
	// Given a Reverse DNS node
	enrich, err := ReverseDNSEnricher(t.Context(), &ReverseDNS{Type: ReverseDNSLocalLookup, CacheLen: 255, CacheTTL: time.Minute})
	require.NoError(t, err)

	// When it receives a flow with an unknown destination for the first time
	f1 := &ebpf.Record{
		NetFlowRecordT: ebpf.NetFlowRecordT{Id: ebpf.NetFlowId{IfIndex: 1}},
		Attrs:          ebpf.RecordAttrs{SrcName: "src"},
	}
	f1.Id.SrcIp.In6U.U6Addr8 = srcIP
	f1.Id.DstIp.In6U.U6Addr8 = dstIP

	// THEN it decorates it
	enrich(f1)

	assert.Contains(t, f1.Attrs.DstName, "amazon")

	// AND when it receives the same flow again
	f1.Attrs.DstName = ""
	enrich(f1)

	// THEN it decorates it from the cached copy (otherwise the fake netLookupAddr would crash)
	assert.Contains(t, f1.Attrs.DstName, "amazon")
}
