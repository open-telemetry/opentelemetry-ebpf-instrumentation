// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package cidr

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/components/netolly/ebpf"
)

const testTimeout = 5 * time.Second

func TestCIDRDecorator(t *testing.T) {
	grouper, err := CIDRDecorator([]string{
		"10.0.0.0/8",
		"10.1.2.0/24",
		"140.130.22.0/24",
		"2001:db8:3c4d:15::/64",
		"2001::/16",
	})

	require.NoError(t, err)

	records := []*ebpf.Record{
		flow("10.3.4.5", "10.1.2.3"),
		flow("2001:db8:3c4d:15:3210::", "2001:3333:3333::"),
		flow("140.130.22.11", "140.130.23.11"),
		flow("180.130.22.11", "10.1.2.4"),
	}

	for _, r := range records {
		grouper(r)
	}

	assert.Equal(t, "10.0.0.0/8", records[0].Attrs.Metadata["src.cidr"])
	assert.Equal(t, "10.1.2.0/24", records[0].Attrs.Metadata["dst.cidr"])
	assert.Equal(t, "2001:db8:3c4d:15::/64", records[1].Attrs.Metadata["src.cidr"])
	assert.Equal(t, "2001::/16", records[1].Attrs.Metadata["dst.cidr"])
	assert.Equal(t, "140.130.22.0/24", records[2].Attrs.Metadata["src.cidr"])
	assert.Empty(t, records[2].Attrs.Metadata["dst.cidr"])
	assert.Empty(t, records[3].Attrs.Metadata["src.cidr"])
	assert.Equal(t, "10.1.2.0/24", records[3].Attrs.Metadata["dst.cidr"])
}

func TestCIDRDecorator_GroupAllUnknownTraffic(t *testing.T) {
	grouper, err := CIDRDecorator([]string{
		"10.0.0.0/8",
		"10.1.2.0/24",
		"0.0.0.0/0", // this entry will capture all the unknown traffic
		"140.130.22.0/24",
		"2001:db8:3c4d:15::/64",
		"2001::/16",
	})

	require.NoError(t, err)

	records := []*ebpf.Record{
		flow("10.3.4.5", "10.1.2.3"),
		flow("2001:db8:3c4d:15:3210::", "2001:3333:3333::"),
		flow("140.130.22.11", "140.130.23.11"),
		flow("180.130.22.11", "10.1.2.4"),
	}

	for _, r := range records {
		grouper(r)
	}

	assert.Equal(t, "10.0.0.0/8", records[0].Attrs.Metadata["src.cidr"])
	assert.Equal(t, "10.1.2.0/24", records[0].Attrs.Metadata["dst.cidr"])
	assert.Equal(t, "2001:db8:3c4d:15::/64", records[1].Attrs.Metadata["src.cidr"])
	assert.Equal(t, "2001::/16", records[1].Attrs.Metadata["dst.cidr"])
	assert.Equal(t, "140.130.22.0/24", records[2].Attrs.Metadata["src.cidr"])
	assert.Equal(t, "0.0.0.0/0", records[2].Attrs.Metadata["dst.cidr"])
	assert.Equal(t, "0.0.0.0/0", records[3].Attrs.Metadata["src.cidr"])
	assert.Equal(t, "10.1.2.0/24", records[3].Attrs.Metadata["dst.cidr"])
}

func flow(srcIP, dstIP string) *ebpf.Record {
	er := ebpf.Record{}
	copy(er.Id.SrcIp.In6U.U6Addr8[:], net.ParseIP(srcIP).To16())
	copy(er.Id.DstIp.In6U.U6Addr8[:], net.ParseIP(dstIP).To16())
	return &er
}
