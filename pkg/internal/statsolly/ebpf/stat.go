// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpf // import "go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"

import (
	"net"

	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
)

// IPAddr encodes v4 and v6 IPs with a fixed length.
// IPv4 addresses are encoded as IPv6 addresses with prefix ::ffff/96
// as described in https://datatracker.ietf.org/doc/html/rfc4038#section-4.2
// (same behavior as Go's net.IP type)
type IPAddr [net.IPv6len]uint8

// IP returns the net.IP equivalent object.
func (ia IPAddr) IP() net.IP {
	return ia[:]
}

// String returns the human-readable IP address, or an empty string if the address is zero.
func (ia IPAddr) String() string {
	if ia.IsZero() {
		return ""
	}
	return net.IP(ia[:]).String()
}

// IsZero reports whether the address is the zero value (unset).
func (ia IPAddr) IsZero() bool {
	return ia == (IPAddr{})
}

type StatType uint8

const (
	StatTypeTCPRtt StatType = iota + 1
)

// Stat contains accumulated metrics from a stats, with extra metadata
// that is added from the user space
// REMINDER: any attribute here must be also added to the functions StatGetters
// in pkg/internal/statsolly/ebpf/stat_getters.go and getDefinitions in
// pkg/export/attributes/attr_defs.go
type Stat struct {
	Type   StatType `json:"type"`
	TCPRtt *TCPRtt  `json:"-"`

	// Attrs of the stat stat: source/destination, OBI IP, etc...
	Attrs StatAttrs
}

type StatAttrs struct {
	SrcAddr IPAddr
	DstAddr IPAddr

	SourcePort      int
	DestinationPort int

	// SrcName and DstName might be set from several sources along the processing/decoration pipeline:
	// - K8s entity
	// - Host name
	// - IP
	SrcName string
	DstName string

	// SrcZone and DstZone represent the Cloud availability zones of the source and destination
	SrcZone string
	DstZone string

	// OBIIP provides information about the source of the stat (the Agent that traced it)
	OBIIP    string
	Metadata map[attr.Name]string
}

type TCPRtt struct {
	SrttUs uint32 `json:"srtt_us"`
}
